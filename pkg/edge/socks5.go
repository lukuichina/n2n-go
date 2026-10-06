package edge

// SOCKS5 / HTTP-CONNECT ingress for an edge.
//
// The whole point of an edge is the TAP: bytes written into n2n_tap0 come back
// out as n2n packets, and bytes read from it were n2n packets. So a proxy in
// front of the overlay does not need to speak n2n at all. Handing an accepted
// TCP stream to the kernel is enough -- the kernel routes it into the TAP, the
// edge's existing handleTAP loop picks the segments up, and the peer on the
// other end hands them to its own kernel. Nothing here touches the data path,
// which is why this file has no n2n imports and no framing code.
//
// The alternative (redocks/tinyproxy plus iptables REDIRECT) reaches the same
// result but needs a packet filter, a transparent-proxy chain and a resolver
// hook on every deployment host. That is a lot of moving parts to reproduce on
// a router that only has busybox. This way the only new requirement is that the
// edge binary is the thing you already run.
//
// Policy matters here more than in most proxy code. An edge that listens for
// SOCKS5 and forwards to overlay peers is a private service; the same edge in
// "any" mode is an open relay, because it will happily connect to the internet
// on behalf of whoever can reach the port. So the default policy is "overlay"
// (only destinations inside the TAP's own subnet), the default bind address is
// loopback, and turning policy "any" without also setting credentials logs a
// warning rather than failing silently.

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"n2n-go/pkg/log"
)

// SOCKS5 wire constants (RFC 1928) and the username/password sub-negotiation
// (RFC 1929).
const (
	socks5Version      = 0x05
	socks5AuthNone     = 0x00
	socks5AuthUserPass = 0x02
	socks5AuthNoneOK   = 0xff // "no acceptable methods"

	socks5UserPassVersion = 0x01
	socks5UserPassStatus  = 0x00

	// Commands. Only CONNECT is served: BIND would ask the proxy to listen on
	// behalf of the client and UDP ASSOCIATE to relay datagrams, and neither has
	// any meaning for a TAP that only carries IP.
	socks5CmdConnect      = 0x01
	socks5CmdBind         = 0x02
	socks5CmdUDPAssociate = 0x03

	// Address types.
	socks5AtypIPv4   = 0x01
	socks5AtypDomain = 0x03
	socks5AtypIPv6   = 0x04

	// Reply codes.
	socks5RepSuccess            = 0x00
	socks5RepGeneralFailure     = 0x01
	socks5RepNotAllowed         = 0x02
	socks5RepNetworkUnreachable = 0x03
	socks5RepHostUnreachable    = 0x04
	socks5RepConnectionRefused  = 0x05
	socks5RepTTLExpired         = 0x06
	socks5RepCmdNotSupported    = 0x07
	socks5RepAtypNotSupported   = 0x08
)

// Policies.
const (
	// Socks5PolicyOverlay only serves destinations that resolve into the
	// subnet configured on the TAP. This is the default because it cannot turn
	// the host into a relay for the internet.
	Socks5PolicyOverlay = "overlay"
	// Socks5PolicyAny serves any destination, which makes the edge an egress
	// proxy (and, on a reachable interface, an open relay).
	Socks5PolicyAny = "any"
)

const (
	defaultSocks5Port             = "1080"
	defaultSocks5HandshakeTimeout = 10 * time.Second
	defaultSocks5DialTimeout      = 10 * time.Second
	// 30 minutes, not something shorter. OpenSSH leaves ServerAliveInterval
	// at 0, so a session that sits idle for five minutes with nothing typed
	// has sent no single byte -- and a proxy that treats that as a dead
	// tunnel kills a perfectly healthy SSH session with no error on either
	// side. Anything under a coffee break will surprise somebody.
	defaultSocks5IdleTimeout = 30 * time.Minute
)

// Socks5Options configures the ingress listener.
type Socks5Options struct {
	// ListenAddr is addr:port. Both parts may be omitted; a bare number is
	// read as a port, and an omitted address means loopback.
	ListenAddr string
	// Policy is Socks5PolicyOverlay or Socks5PolicyAny. Empty means overlay.
	Policy string
	// Auth is "user:pass". Empty disables the username/password method.
	Auth string

	HandshakeTimeout time.Duration
	DialTimeout      time.Duration
	IdleTimeout      time.Duration
}

// Socks5Server accepts SOCKS5 and HTTP CONNECT connections and turns each into
// an ordinary kernel-routed TCP stream.
type Socks5Server struct {
	edge *EdgeClient
	opts Socks5Options
	ln   net.Listener

	user string
	pass string

	overlayOnce sync.Once
	overlay     []*net.IPNet

	wg        sync.WaitGroup
	closeOnce sync.Once

	// Counters, exposed through the management API.
	Accepted atomic.Uint64
	Rejected atomic.Uint64
	Tunneled atomic.Uint64
	Active   atomic.Int64
}

// NewSocks5Server validates the options and binds the listener. Binding here
// rather than in Serve is deliberate: a port clash should fail edge startup
// loudly instead of vanishing into a goroutine.
func NewSocks5Server(edge *EdgeClient, opts Socks5Options) (*Socks5Server, error) {
	if opts.Policy == "" {
		opts.Policy = Socks5PolicyOverlay
	}
	switch opts.Policy {
	case Socks5PolicyOverlay, Socks5PolicyAny:
	default:
		return nil, fmt.Errorf("unknown socks5 policy %q (want %q or %q)",
			opts.Policy, Socks5PolicyOverlay, Socks5PolicyAny)
	}

	if opts.HandshakeTimeout <= 0 {
		opts.HandshakeTimeout = defaultSocks5HandshakeTimeout
	}
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = defaultSocks5DialTimeout
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = defaultSocks5IdleTimeout
	}

	s := &Socks5Server{edge: edge, opts: opts}

	if opts.Auth != "" {
		user, pass, ok := strings.Cut(opts.Auth, ":")
		if !ok || user == "" {
			return nil, fmt.Errorf("invalid socks5 auth %q (want user:pass)", opts.Auth)
		}
		s.user, s.pass = user, pass
	}

	if opts.ListenAddr == "" {
		opts.ListenAddr = "127.0.0.1:" + defaultSocks5Port
	}
	normalized, err := ParseListenAddr(opts.ListenAddr, "127.0.0.1", defaultSocks5Port)
	if err != nil {
		return nil, fmt.Errorf("invalid socks5 listen address: %w", err)
	}
	opts.ListenAddr = normalized

	// Re-stamp the normalized options now that the listen address is settled,
	// so the copy held by the server matches what was actually bound.
	s.opts = opts

	ln, err := net.Listen("tcp", opts.ListenAddr)
	if err != nil {
		return nil, err
	}
	s.ln = ln

	// Resolve the overlay now so the first connection does not pay for it, and
	// so a misconfigured TAP shows up at startup rather than as every request
	// being refused.
	nets := s.overlayNets()
	if opts.Policy == Socks5PolicyOverlay && len(nets) == 0 {
		log.Printf("socks5: warning: could not determine the overlay subnet from the TAP; " +
			"every request will be refused until the interface is up")
	} else if len(nets) > 0 {
		cidrs := make([]string, 0, len(nets))
		for _, n := range nets {
			cidrs = append(cidrs, n.String())
		}
		log.Printf("socks5: overlay subnet(s): %s", strings.Join(cidrs, ", "))
	}

	if opts.Policy == Socks5PolicyAny && s.user == "" && !isLoopbackHost(ln.Addr()) {
		log.Printf("socks5: warning: policy=any with no credentials on a non-loopback address "+
			"(%s) makes this host an open relay for anyone who can reach it", ln.Addr())
	}

	return s, nil
}

// Addr is the address the listener actually bound, useful when the caller asked
// for port 0.
func (s *Socks5Server) Addr() net.Addr { return s.ln.Addr() }

// Serve accepts connections until the listener is closed.
func (s *Socks5Server) Serve() {
	log.Printf("socks5: listening on %s (policy=%s, auth=%t)",
		s.ln.Addr(), s.opts.Policy, s.user != "")

	for {
		c, err := s.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("socks5: accept error: %v", err)
			// A transient accept failure (fd exhaustion) should not spin the
			// CPU; a persistent one will just log again after the pause.
			time.Sleep(50 * time.Millisecond)
			continue
		}

		s.Accepted.Add(1)
		s.Active.Add(1)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.Active.Add(-1)
			defer c.Close()
			s.serveConn(c)
		}()
	}
}

// Close stops the listener and waits for in-flight connections to finish.
func (s *Socks5Server) Close() {
	s.closeOnce.Do(func() {
		if s.ln != nil {
			s.ln.Close()
		}
	})
}

// Wait blocks until every handler goroutine has returned. Callers that want a
// bounded shutdown should bound their own wait; this exists for tests.
func (s *Socks5Server) Wait() { s.wg.Wait() }

func (s *Socks5Server) serveConn(c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(s.opts.HandshakeTimeout))

	br := bufio.NewReader(c)
	first, err := br.Peek(1)
	if err != nil {
		return
	}

	switch {
	case first[0] == socks5Version:
		s.serveSOCKS5(c, br)
	case isHTTPMethodStart(first[0]):
		s.serveHTTP(c, br)
	default:
		log.Printf("socks5: %s: unrecognised protocol byte 0x%02x", c.RemoteAddr(), first[0])
	}
}

// ---------------------------------------------------------------- SOCKS5 ---

func (s *Socks5Server) serveSOCKS5(c net.Conn, br *bufio.Reader) {
	if !s.socks5NegotiateAuth(c, br) {
		return
	}

	cmd, host, port, err := readSocks5Request(br)
	if err != nil {
		log.Printf("socks5: %s: bad request: %v", c.RemoteAddr(), err)
		return
	}

	if cmd != socks5CmdConnect {
		log.Printf("socks5: %s: command 0x%02x is not supported (only CONNECT)", c.RemoteAddr(), cmd)
		_ = writeSocks5Reply(c, socks5RepCmdNotSupported, nil, 0)
		return
	}

	target := net.JoinHostPort(host, strconv.Itoa(int(port)))

	up, rep, err := s.dialTarget(target)
	if err != nil {
		if rep == 0 {
			rep = socks5RepGeneralFailure
		}
		log.Printf("socks5: %s: %s: %v", c.RemoteAddr(), target, err)
		_ = writeSocks5Reply(c, rep, nil, 0)
		return
	}
	defer up.Close()

	if err := writeSocks5Reply(c, socks5RepSuccess, up.LocalAddr(), 0); err != nil {
		return
	}

	// The handshake is done; from here the deadlines belong to the idle timer.
	_ = c.SetDeadline(time.Time{})
	_ = up.SetDeadline(time.Time{})

	s.Tunneled.Add(1)
	s.logTunnelStart(c.RemoteAddr(), target, up)
	s.relay(c, br, up)
}

// socks5NegotiateAuth performs the method selection and, if configured, the
// username/password sub-negotiation. It returns false when the connection
// should be dropped (the reply, if any, has already been written).
func (s *Socks5Server) socks5NegotiateAuth(c net.Conn, br *bufio.Reader) bool {
	ver, err := br.ReadByte()
	if err != nil || ver != socks5Version {
		log.Printf("socks5: %s: unsupported SOCKS version %d", c.RemoteAddr(), ver)
		return false
	}
	nMethods, err := br.ReadByte()
	if err != nil {
		return false
	}
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(br, methods); err != nil {
		return false
	}

	want := byte(socks5AuthNone)
	if s.user != "" {
		want = socks5AuthUserPass
	}
	offered := false
	for _, m := range methods {
		if m == want {
			offered = true
			break
		}
	}
	if !offered {
		_, _ = c.Write([]byte{socks5Version, socks5AuthNoneOK})
		log.Printf("socks5: %s: client does not accept method 0x%02x", c.RemoteAddr(), want)
		return false
	}
	if _, err := c.Write([]byte{socks5Version, want}); err != nil {
		return false
	}
	if want != socks5AuthUserPass {
		return true
	}

	// RFC 1929 sub-negotiation.
	upVer, err := br.ReadByte()
	if err != nil || upVer != socks5UserPassVersion {
		return false
	}
	userLen, err := br.ReadByte()
	if err != nil {
		return false
	}
	user := make([]byte, userLen)
	if _, err := io.ReadFull(br, user); err != nil {
		return false
	}
	passLen, err := br.ReadByte()
	if err != nil {
		return false
	}
	pass := make([]byte, passLen)
	if _, err := io.ReadFull(br, pass); err != nil {
		return false
	}

	// Constant-time-ish comparison; these are short strings over a network.
	ok := subtleEqualStr(string(user), s.user) && subtleEqualStr(string(pass), s.pass)
	status := byte(socks5UserPassStatus)
	if !ok {
		status = 0x01
	}
	if _, err := c.Write([]byte{0x01, status}); err != nil {
		return false
	}
	if !ok {
		log.Printf("socks5: %s: authentication failed", c.RemoteAddr())
		return false
	}
	return true
}

func readSocks5Request(br *bufio.Reader) (cmd byte, host string, port uint16, err error) {
	hdr := make([]byte, 3)
	if _, err = io.ReadFull(br, hdr); err != nil {
		return
	}
	if hdr[0] != socks5Version {
		err = fmt.Errorf("bad version %d in request", hdr[0])
		return
	}
	cmd = hdr[1]

	atyp, err := br.ReadByte()
	if err != nil {
		return
	}
	switch atyp {
	case socks5AtypIPv4:
		buf := make([]byte, 4)
		if _, err = io.ReadFull(br, buf); err != nil {
			return
		}
		host = net.IP(buf).String()
	case socks5AtypIPv6:
		buf := make([]byte, 16)
		if _, err = io.ReadFull(br, buf); err != nil {
			return
		}
		host = net.IP(buf).String()
	case socks5AtypDomain:
		l, err := br.ReadByte()
		if err != nil {
			return 0, "", 0, err
		}
		if l == 0 {
			err = errors.New("empty domain name")
			return 0, "", 0, err
		}
		buf := make([]byte, l)
		if _, err = io.ReadFull(br, buf); err != nil {
			return 0, "", 0, err
		}
		host = string(buf)
	default:
		err = fmt.Errorf("unsupported address type 0x%02x", atyp)
		return
	}

	var p [2]byte
	if _, err = io.ReadFull(br, p[:]); err != nil {
		return
	}
	port = binary.BigEndian.Uint16(p[:])
	return
}

func writeSocks5Reply(w io.Writer, code byte, bound net.Addr, _ uint16) error {
	// BND.ADDR/BND.PORT describe the proxy-side endpoint. Clients ignore it in
	// practice, but the field is mandatory, so send the local side of the
	// connection when we have one and 0.0.0.0:0 otherwise.
	var bnd []byte
	if bound != nil {
		if ta, ok := bound.(*net.TCPAddr); ok {
			if v4 := ta.IP.To4(); v4 != nil {
				bnd = append(bnd, socks5AtypIPv4)
				bnd = append(bnd, v4...)
			} else if v6 := ta.IP.To16(); v6 != nil {
				bnd = append(bnd, socks5AtypIPv6)
				bnd = append(bnd, v6...)
			}
		}
	}
	if len(bnd) == 0 {
		bnd = []byte{socks5AtypIPv4, 0, 0, 0, 0}
	}
	out := make([]byte, 0, 3+len(bnd))
	out = append(out, socks5Version, code, 0)
	out = append(out, bnd...)
	out = append(out, 0, 0)
	_, err := w.Write(out)
	return err
}

// ------------------------------------------------------------------- HTTP ---

// isHTTPMethodStart reports whether b could begin an HTTP/1.x request line.
// Anything else is a protocol error worth refusing before we allocate.
func isHTTPMethodStart(b byte) bool {
	switch b {
	case 'C', 'G', 'P', 'H', 'O', 'D', 'T', 'E':
		return true
	}
	return false
}

// serveHTTP implements enough of RFC 7230/7231 to be useful as a plain HTTP
// proxy: CONNECT tunnels, and absolute-form requests are rewritten to
// origin-form and relayed. There is no header rewriting, no keep-alive reuse
// and no chunked decoding on the request side -- this is a tunnel with a
// convenience wrapper, not a caching proxy.
func (s *Socks5Server) serveHTTP(c net.Conn, br *bufio.Reader) {
	_ = c.SetReadDeadline(time.Now().Add(s.opts.HandshakeTimeout))

	line, err := readCRLFLine(br)
	if err != nil {
		return
	}
	// "METHOD request-target HTTP/1.1" -- the version has to be cut off before
	// the target is used, otherwise "CONNECT host:443 HTTP/1.1" ends up as the
	// destination and every CONNECT fails.
	method, rest, _ := strings.Cut(line, " ")
	rest, _, _ = strings.Cut(rest, " ")

	// Headers are consumed but not forwarded: for CONNECT the tunnel is raw
	// bytes afterwards, and for the rewritten form we synthesise our own.
	if err := discardHeaders(br); err != nil {
		return
	}

	var hostport string
	if strings.EqualFold(method, "CONNECT") {
		hostport = rest
	} else {
		// Absolute-form: "GET http://host:port/path HTTP/1.1".
		u := rest
		if !strings.HasPrefix(strings.ToLower(u), "http://") {
			log.Printf("socks5: %s: only http:// absolute-form requests are supported, got %q", c.RemoteAddr(), rest)
			httpError(c, http.StatusBadGateway, "only CONNECT and http:// are supported")
			return
		}
		after := u[len("http://"):]
		hostpart, path, _ := strings.Cut(after, "/")
		if !strings.Contains(hostpart, ":") {
			hostpart += ":80"
		}
		hostport = hostpart
		// strings.Cut consumed the separator, so put it back: the origin form
		// needs "/hello", not "hello".
		rest = "/" + path
	}
	target, err := normalizeHostPort(hostport, 80)
	if err != nil {
		httpError(c, http.StatusBadRequest, err.Error())
		return
	}

	up, rep, err := s.dialTarget(target)
	if err != nil {
		log.Printf("socks5: %s: %s: %v", c.RemoteAddr(), target, err)
		if rep == socks5RepNotAllowed {
			httpError(c, http.StatusForbidden, "destination not permitted by proxy policy")
		} else {
			httpError(c, http.StatusBadGateway, err.Error())
		}
		return
	}
	defer up.Close()

	_ = c.SetDeadline(time.Time{})
	_ = up.SetDeadline(time.Time{})

	s.Tunneled.Add(1)

	if strings.EqualFold(method, "CONNECT") {
		if _, err := c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
			return
		}
		s.logTunnelStart(c.RemoteAddr(), target, up)
		s.relay(c, br, up)
		return
	}

	// Rewrite the request line to origin-form and send it upstream. The
	// Host header was already consumed above, so re-emit it.
	req := method + " " + rest + " HTTP/1.1\r\nHost: " + hostpart(target) + "\r\n\r\n"
	if _, err := up.Write([]byte(req)); err != nil {
		return
	}
	s.logTunnelStart(c.RemoteAddr(), target, up)
	s.relay(c, br, up)
}

func hostpart(hostport string) string {
	h, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return h
}

func httpError(w io.Writer, code int, msg string) {
	if msg == "" {
		msg = http.StatusText(code)
	}
	body := msg + "\n"
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(body), body)
}

// readCRLFLine reads one CRLF-terminated line, without the terminator.
func readCRLFLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// discardHeaders consumes the blank line that ends the header block.
func discardHeaders(br *bufio.Reader) error {
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return err
		}
		if line == "\r\n" || line == "\n" {
			return nil
		}
	}
}

// ------------------------------------------------------------------ policy --

// dialTarget applies the policy and then dials. The returned byte is a SOCKS5
// reply code so the caller can report something more useful than "failure".
func (s *Socks5Server) dialTarget(target string) (net.Conn, byte, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, socks5RepAtypNotSupported, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, socks5RepAtypNotSupported, err
	}

	if s.opts.Policy == Socks5PolicyOverlay {
		ok, err := s.overlayAllows(host)
		if err != nil {
			return nil, socks5RepHostUnreachable, err
		}
		if !ok {
			return nil, socks5RepNotAllowed, fmt.Errorf(
				"destination %s is outside the overlay and policy=%s", host, s.opts.Policy)
		}
	}

	// Go's dialer resolves the name itself, which in "any" mode is what we
	// want: the edge's own resolver, the edge's own routes.
	d := net.Dialer{Timeout: s.opts.DialTimeout}
	c, err := d.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, socks5RepConnectionRefused, err
	}
	return c, socks5RepSuccess, nil
}

// overlayAllows reports whether host, an IP literal or a name, lands inside
// the overlay. Names are resolved here because the policy is about where the
// bytes end up, not about how they were spelled.
func (s *Socks5Server) overlayAllows(host string) (bool, error) {
	return overlayAllows(host, s.overlayNets())
}

// overlayNets returns the subnets configured on the TAP. It prefers asking the
// interface, because that is what the kernel actually routes with, and falls
// back to the address the supernode handed us.
func (s *Socks5Server) overlayNets() []*net.IPNet {
	return overlayNets(s.edge, &s.overlay, &s.overlayOnce)
}

// Stats is the snapshot served by the management API.
type Socks5Stats struct {
	ListenAddr string   `json:"listen_addr"`
	Policy     string   `json:"policy"`
	Auth       bool     `json:"auth"`
	Overlay    []string `json:"overlay"`
	Accepted   uint64   `json:"accepted"`
	Tunneled   uint64   `json:"tunneled"`
	Active     int64    `json:"active"`
}

// Stats snapshots the counters. Reading the overlay subnets here also warms the
// cache, so the first API call does not pay for the interface lookup.
func (s *Socks5Server) Stats() Socks5Stats {
	cidrs := []string{}
	for _, n := range s.overlayNets() {
		cidrs = append(cidrs, n.String())
	}
	addr := ""
	if s.ln != nil {
		addr = s.ln.Addr().String()
	}
	return Socks5Stats{
		ListenAddr: addr,
		Policy:     s.opts.Policy,
		Auth:       s.user != "",
		Overlay:    cidrs,
		Accepted:   s.Accepted.Load(),
		Tunneled:   s.Tunneled.Load(),
		Active:     s.Active.Load(),
	}
}

// ------------------------------------------------------------------ relay --

// relay copies in both directions until both halves are done, then closes.
// Each direction half-closes rather than closing, so a request/response
// protocol sees the peer's EOF and can still answer.
//
// clientSrc is normally the bufio.Reader the handshake was parsed from, not the
// conn itself. A client that writes its first payload bytes together with the
// CONNECT request leaves them sitting in that reader's buffer; reading the bare
// conn would skip them and the tunnel would come up one message short of what
// the peer sent. A conforming client waits for the reply, but a proxy that
// loses bytes when one doesn't wait is a very hard bug to find from the other
// end.
func (s *Socks5Server) relay(client net.Conn, clientSrc io.Reader, upstream net.Conn) {
	idle := s.opts.IdleTimeout
	c := &idleConn{Conn: client, idle: idle}
	u := &idleConn{Conn: upstream, idle: idle}
	if clientSrc == nil {
		clientSrc = client
	}

	// Counting the two directions is the only way to tell "the tunnel never
	// carried a byte" apart from "it carried some and then stalled". A tunnel
	// that dies silently looks identical from the outside either way.
	var up, down byteCounter // client->upstream, upstream->client
	start := time.Now()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(u, io.TeeReader(clientSrc, &up))
		halfClose(u.Conn)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(c, io.TeeReader(u, &down))
		halfClose(c.Conn)
	}()
	wg.Wait()

	s.logTunnelEnd(up.n.Load(), down.n.Load(), time.Since(start))
}

// logTunnelStart records which local address the kernel picked for the outbound
// connection. Getting that wrong is invisible from the client -- the SOCKS5
// reply still says success -- but the peer may never see the packet, because it
// arrives from an address outside the overlay.
func (s *Socks5Server) logTunnelStart(remote net.Addr, target string, up net.Conn) {
	log.Printf("socks5: %s -> %s via local=%s remote=%s",
		remote, target, up.LocalAddr(), up.RemoteAddr())
}

func (s *Socks5Server) logTunnelEnd(up, down uint64, took time.Duration) {
	log.Printf("socks5: tunnel closed after %s, client->upstream=%d B, upstream->client=%d B",
		took.Round(time.Millisecond), up, down)
}

// byteCounter is an io.Writer that only tallies, so io.TeeReader can be used to
// measure a direction without keeping the bytes.
type byteCounter struct{ n atomic.Uint64 }

func (b *byteCounter) Write(p []byte) (int, error) {
	b.n.Add(uint64(len(p)))
	return len(p), nil
}

func halfClose(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	// No CloseWrite (some TLS or wrapper connections): force the other
	// direction to unblock by expiring its deadline.
	_ = c.SetReadDeadline(time.Now())
}

// idleConn refreshes the read deadline on every Read, turning the fixed
// deadline io.Copy would otherwise inherit into a true idle timeout.
type idleConn struct {
	net.Conn
	idle time.Duration
}

func (c *idleConn) Read(p []byte) (int, error) {
	if c.idle > 0 {
		_ = c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	}
	return c.Conn.Read(p)
}

// ------------------------------------------------------------------ helpers --

func normalizeHostPort(hostport string, defaultPort int) (string, error) {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return "", errors.New("missing destination")
	}
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		if p == "" {
			return net.JoinHostPort(h, strconv.Itoa(defaultPort)), nil
		}
		return net.JoinHostPort(h, p), nil
	}
	// No port at all. A bracketed literal already carries its own brackets, and
	// net.JoinHostPort would add a second pair.
	return net.JoinHostPort(strings.Trim(hostport, "[]"), strconv.Itoa(defaultPort)), nil
}

func isLoopbackHost(addr net.Addr) bool {
	ta, ok := addr.(*net.TCPAddr)
	if !ok {
		return false
	}
	return ta.IP.IsLoopback()
}

// subtleEqualStr compares two strings without leaking their contents through
// timing. Length is compared first, which is not secret here -- both sides are
// short strings chosen by the operator.
func subtleEqualStr(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
