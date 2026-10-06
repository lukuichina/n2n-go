package edge

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// splitColonSegments splits "a:b:c:d" on colons that are not inside square
// brackets, so an IPv6 literal in either half survives intact.
func splitColonSegments(s string) ([]string, error) {
	var segs []string
	var cur strings.Builder
	inBracket := false
	for _, r := range s {
		switch {
		case r == '[':
			if inBracket {
				return nil, fmt.Errorf("nested '[' in %q", s)
			}
			inBracket = true
			cur.WriteRune(r)
		case r == ']':
			if !inBracket {
				return nil, fmt.Errorf("unmatched ']' in %q", s)
			}
			inBracket = false
			cur.WriteRune(r)
		case r == ':' && !inBracket:
			segs = append(segs, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if inBracket {
		return nil, fmt.Errorf("unterminated '[' in %q", s)
	}
	segs = append(segs, cur.String())
	return segs, nil
}

// ParsePortForwardSpec decodes one -L / -R entry of the form
// "BIND:PORT:TARGET:TPORT[/proto]".
//
// The PORT and TPORT fields accept a single port, a comma-separated list
// ("80,85"), or a half-open range ("80-85"). A bind address may be omitted
// (it then defaults to 127.0.0.1 for -L and 0.0.0.0 for -R), or given as "*"
// which means 0.0.0.0. A bind port of 0 asks the kernel for a free port.
//
// proto is `tcp` by default, `udp` for stateless forwarding, or `both` for
// two independent listeners (one TCP, one UDP) on the same bind address.
func ParsePortForwardSpec(spec string) ([]PortForwardSpec, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("empty port forward specification")
	}

	proto := "tcp"
	if i := strings.LastIndex(spec, "/"); i >= 0 {
		proto = strings.ToLower(spec[i+1:])
		spec = spec[:i]
	}
	switch proto {
	case "tcp", "udp", "both":
	default:
		return nil, fmt.Errorf("invalid protocol %q (want tcp, udp, or both)", proto)
	}

	segs, err := splitColonSegments(spec)
	if err != nil {
		return nil, fmt.Errorf("invalid port forward %q: %w", spec, err)
	}

	var bindPart, targetHost, tportStr string
	switch len(segs) {
	case 3:
		bindPart = segs[0]
		targetHost = segs[1]
		tportStr = segs[2]
	case 4:
		bindPart = segs[0] + ":" + segs[1]
		targetHost = segs[2]
		tportStr = segs[3]
	default:
		return nil, fmt.Errorf(
			"invalid port forward %q: want [BIND:]PORT:TARGET:TPORT, got %d field(s)", spec, len(segs))
	}

	bindAddr, err := ParseListenAddr(bindPart, "127.0.0.1", "0")
	if err != nil {
		return nil, fmt.Errorf("invalid port forward %q: %w", spec, err)
	}
	bh, bpStr, err := net.SplitHostPort(bindAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid port forward %q: %w", spec, err)
	}

	// The bind port may be a single port, a comma-separated list, or a range.
	// "*" means 0.0.0.0, which ParseListenAddr already turns into "0.0.0.0:0"
	// when the bind part is just "*"; a bare "*" as the whole bind part is
	// handled by ParseListenAddr returning "0.0.0.0:0".
	bindPorts, err := expandPorts(bpStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port forward %q: bind port %q: %w", spec, bpStr, err)
	}

	tports, err := expandPorts(tportStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port forward %q: target port %q: %w", spec, tportStr, err)
	}

	targetHost = strings.Trim(targetHost, "[]")
	if len(bindPorts) != len(tports) {
		return nil, fmt.Errorf(
			"invalid port forward %q: %d bind port(s) but %d target port(s)", spec, len(bindPorts), len(tports))
	}

	specs := make([]PortForwardSpec, 0, len(bindPorts))
	for i, bp := range bindPorts {
		target := net.JoinHostPort(targetHost, strconv.Itoa(tports[i]))
		if proto == "both" {
			// "both" is sugar for two independent listeners on the same
			// bind address: one TCP, one UDP. They share nothing but the
			// bind socket family, so they are returned as two specs and
			// started as two separate PortForwarders.
			specs = append(specs,
				PortForwardSpec{BindAddr: bh, BindPort: bp, Target: target, Proto: "tcp"},
				PortForwardSpec{BindAddr: bh, BindPort: bp, Target: target, Proto: "udp"},
			)
		} else {
			specs = append(specs, PortForwardSpec{
				BindAddr: bh,
				BindPort: bp,
				Target:   target,
				Proto:    proto,
			})
		}
	}
	return specs, nil
}

// expandPorts turns "80,85" into [80,85], "80-85" into [80,81,82,83,84,85],
// and "80" into [80]. A port of 0 is kept as 0, which asks the kernel for a
// free port; it cannot be combined with a range or a list, because a random
// port is not a number.
func expandPorts(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty port specification")
	}

	var ports []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("empty port in %q", s)
		}
		if i := strings.Index(part, "-"); i >= 0 {
			lo, err := strconv.Atoi(strings.TrimSpace(part[:i]))
			if err != nil {
				return nil, fmt.Errorf("invalid range start %q in %q", part[:i], s)
			}
			hi, err := strconv.Atoi(strings.TrimSpace(part[i+1:]))
			if err != nil {
				return nil, fmt.Errorf("invalid range end %q in %q", part[i+1:], s)
			}
			if lo > hi {
				return nil, fmt.Errorf("range %q: start %d > end %d", part, lo, hi)
			}
			if lo < 1 || hi > 65535 {
				return nil, fmt.Errorf("range %q: out of range 1-65535", part)
			}
			for p := lo; p <= hi; p++ {
				ports = append(ports, p)
			}
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 || n > 65535 {
			return nil, fmt.Errorf("invalid port %q in %q", part, s)
		}
		ports = append(ports, n)
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("empty port specification %q", s)
	}
	return ports, nil
}

// PortForwarder is a TCP or UDP port forwarder. It binds on BindAddr:BindPort
// and relays every accepted connection to Target, which the kernel routes
// into the TAP when it is inside the overlay.
//
// It is the port-forward analogue of the SOCKS5 ingress: same data path, no
// handshake. The overlay policy is shared via overlayAllows so the two cannot
// drift apart.
type PortForwarder struct {
	edge    *EdgeClient
	spec    PortForwardSpec
	policy  OverlayPolicy
	// overlaySourceFilter is true for -R forwards: the listener may be bound
	// on 0.0.0.0 (or any address), but only connections whose source is
	// inside the overlay are accepted. This is what keeps a remote forward
	// from becoming an open ingress to the whole internet: the bind address
	// says "listen everywhere", the source filter says "only overlay peers
	// may use it".
	overlaySourceFilter bool
	ln      net.Listener
	udpLn   *net.UDPConn
	once    sync.Once
	overlay []*net.IPNet

	accepted atomic.Int64
	dialled  atomic.Int64
	tunneled atomic.Uint64
	active   atomic.Int64
	rejected atomic.Uint64

	// DialTimeout is how long to wait for the target before giving up.
	// Default 10s; tests override it to fail fast.
	DialTimeout time.Duration

	mu    sync.Mutex
	cons  map[net.Conn]struct{}
	wg    sync.WaitGroup
	close sync.Once
}

// NewPortForwarder validates the spec and binds the listener. A bind failure
// is fatal for the same reason it is not deferred into a goroutine: a port
// clash the operator asked for should stop the edge.
//
// Two independent controls are passed in, because "may reach any target" and
// "may only be reached from the overlay" are different questions and conflating
// them makes the flag semantics impossible to express:
//
//   - policy controls where the forwarder dials: OverlayPolicyOverlay keeps
//     targets inside the TAP's subnet, OverlayPolicyAny lets it dial anything.
//     A -L forward is an ingress into the overlay, so overlay-only is the
//     safe default; a -R forward is an egress out of the overlay, so any is
//     the point of the flag.
//
//   - overlaySourceFilter, when true, rejects connections whose source is
//     outside the overlay at accept time, before a single byte is relayed.
//     This is what keeps a remote forward bound on 0.0.0.0 from becoming an
//     open ingress: the bind address says "listen everywhere", the source
//     filter says "only overlay peers may use it".
func NewPortForwarder(edge *EdgeClient, spec PortForwardSpec, policy OverlayPolicy, overlaySourceFilter bool) (*PortForwarder, error) {
	if spec.BindPort > 65535 {
		return nil, fmt.Errorf("invalid bind port %d", spec.BindPort)
	}
	if spec.Target == "" {
		return nil, fmt.Errorf("port forward %s has no target", spec)
	}

	// A bind port of 0 asks the kernel for a free port, which is what a test
	// wants and what an operator typing nothing means. It is not a validation
	// error, so do not reject it here.
	bindAddr := net.JoinHostPort(spec.BindAddr, strconv.Itoa(spec.BindPort))
	var ln net.Listener
	var udpLn *net.UDPConn
	var err error
	switch spec.Proto {
	case "tcp":
		ln, err = net.Listen("tcp", bindAddr)
		if err != nil {
			return nil, fmt.Errorf("cannot bind port forward %s: %w", spec, err)
		}
	case "udp":
		udpLn, err = net.ListenUDP("udp", mustUDPAddr(bindAddr))
		if err != nil {
			return nil, fmt.Errorf("cannot bind port forward %s: %w", spec, err)
		}
	default:
		return nil, fmt.Errorf("port forward %s: unsupported protocol %q (want tcp or udp)", spec, spec.Proto)
	}

	pf := &PortForwarder{
		edge:               edge,
		spec:               spec,
		policy:             policy,
		overlaySourceFilter: overlaySourceFilter,
		ln:                 ln,
		udpLn:              udpLn,
		cons:               make(map[net.Conn]struct{}),
		DialTimeout:        10 * time.Second,
	}
	pf.overlay = overlayNets(edge, &pf.overlay, &pf.once)
	if len(pf.overlay) == 0 {
		log.Printf("port forward %s: warning: could not determine the overlay subnet from the TAP; "+
			"every connection will be refused until the interface is up", spec)
	}
	return pf, nil
}

// Serve accepts connections until the listener is closed.
func (p *PortForwarder) Serve() {
	if p.udpLn != nil {
		p.serveUDP()
		return
	}
	log.Printf("port forward %s: listening on %s -> %s",
		p.spec, p.ln.Addr(), p.spec.Target)

	for {
		c, err := p.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("port forward %s: accept error: %v", p.spec, err)
			time.Sleep(50 * time.Millisecond)
			continue
		}

		p.accepted.Add(1)
		if p.overlaySourceFilter {
			if ok, err := overlayAllowsAddr(c.RemoteAddr(), p.overlay, OverlayPolicyOverlay); err != nil {
				p.rejected.Add(1)
				p.accepted.Add(-1)
				log.Printf("port forward %s: overlay unknown for %s: %v", p.spec, c.RemoteAddr(), err)
				c.Close()
				continue
			} else if !ok {
				p.rejected.Add(1)
				p.accepted.Add(-1)
				log.Printf("port forward %s: refused %s: source is outside the overlay", p.spec, c.RemoteAddr())
				c.Close()
				continue
			}
		}
		p.active.Add(1)
		p.mu.Lock()
		p.cons[c] = struct{}{}
		p.mu.Unlock()
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer p.active.Add(-1)
			defer func() {
				p.mu.Lock()
				delete(p.cons, c)
				p.mu.Unlock()
			}()
			defer c.Close()
			p.handle(c)
		}()
	}
}

// serveUDP is the stateless datagram path. Every packet is policy-checked and
// relayed independently, so a UDP port forward survives reboots of the target
// without any session state on this side.
func (p *PortForwarder) serveUDP() {
	log.Printf("port forward %s: listening on %s -> %s",
		p.spec, p.udpLn.LocalAddr(), p.spec.Target)

	buf := make([]byte, 65535)
	for {
		n, from, err := p.udpLn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("port forward %s: read error: %v", p.spec, err)
			time.Sleep(50 * time.Millisecond)
			continue
		}

		p.accepted.Add(1)
		if p.overlaySourceFilter {
			if ok, err := overlayAllowsAddr(from, p.overlay, OverlayPolicyOverlay); err != nil {
				p.rejected.Add(1)
				p.accepted.Add(-1)
				log.Printf("port forward %s: overlay unknown for %s: %v", p.spec, from, err)
				continue
			} else if !ok {
				p.rejected.Add(1)
				p.accepted.Add(-1)
				log.Printf("port forward %s: refused %s: source is outside the overlay", p.spec, from)
				continue
			}
		}
		p.wg.Add(1)
		go func(data []byte, client net.Addr) {
			defer p.wg.Done()
			p.handleUDP(data, client)
		}(append([]byte(nil), buf[:n]...), from)
	}
}

// handle dials the target, applies the overlay policy, and relays.
func (p *PortForwarder) handle(c net.Conn) {
	if ok, err := overlayAllowsPolicy(p.targetHost(), p.overlay, p.policy); err != nil {
		log.Printf("port forward %s: overlay unknown: %v", p.spec, err)
		return
	} else if !ok {
		log.Printf("port forward %s: refused %s: outside the overlay and policy=%s",
			p.spec, p.targetHost(), p.policy)
		return
	}

	// Increment dialled after the policy check passes, so the counter means
	// "a dial was actually attempted" rather than "a connection arrived".
	p.dialled.Add(1)
	up, err := net.DialTimeout("tcp", p.spec.Target, p.dialTimeout())
	if err != nil {
		log.Printf("port forward %s: dial %s: %v", p.spec, p.spec.Target, err)
		return
	}
	p.tunneled.Add(1)

	go func() {
		defer up.Close()
		io.Copy(up, c)
	}()
	io.Copy(c, up)
}

// handleUDP is the stateless datagram relay. It opens a fresh socket for every
// packet, which is wasteful but correct: a UDP forward has no connection state
// to tear down, and caching one would silently drop replies from a target
// that moved.
func (p *PortForwarder) handleUDP(data []byte, client net.Addr) {
	if ok, err := overlayAllowsPolicy(p.targetHost(), p.overlay, p.policy); err != nil {
		log.Printf("port forward %s: overlay unknown: %v", p.spec, err)
		return
	} else if !ok {
		log.Printf("port forward %s: refused %s: outside the overlay and policy=%s",
			p.spec, p.targetHost(), p.policy)
		return
	}

	p.dialled.Add(1)
	conn, err := net.DialTimeout("udp", p.spec.Target, p.dialTimeout())
	if err != nil {
		log.Printf("port forward %s: dial %s: %v", p.spec, p.spec.Target, err)
		return
	}
	defer conn.Close()

	p.tunneled.Add(1)
	if _, err := conn.Write(data); err != nil {
		log.Printf("port forward %s: write to %s: %v", p.spec, p.spec.Target, err)
		return
	}

	// Read one reply and bounce it back to whoever sent the request. A full
	// bidirectional relay would need a session table keyed by the client's
	// source port, which is the same complexity a userspace NAT has; for a
	// stateless forward, one reply per request is the honest contract.
	_ = conn.SetReadDeadline(time.Now().Add(p.dialTimeout()))
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("port forward %s: read reply from %s: %v", p.spec, p.spec.Target, err)
		return
	}
	if _, err := p.udpLn.WriteTo(buf[:n], client); err != nil {
		log.Printf("port forward %s: write reply to client: %v", p.spec, err)
	}
}

// targetHost returns the host part of the target for policy checks. Names are
// resolved by overlayAllows itself; this is only the literal to hand it.
func (p *PortForwarder) targetHost() string {
	h, _, err := net.SplitHostPort(p.spec.Target)
	if err != nil {
		return p.spec.Target
	}
	return h
}

// dialTimeout returns the configured dial timeout, defaulting to 10s.
func (p *PortForwarder) dialTimeout() time.Duration {
	if p.DialTimeout > 0 {
		return p.DialTimeout
	}
	return 10 * time.Second
}

// Stats snapshots the counters.
func (p *PortForwarder) Stats() PortForwardStats {
	listen := ""
	if p.ln != nil {
		listen = p.ln.Addr().String()
	} else if p.udpLn != nil {
		listen = p.udpLn.LocalAddr().String()
	}
	return PortForwardStats{
		Spec:     p.spec.String(),
		Listen:   listen,
		Policy:   string(p.policy),
		Accepted: p.accepted.Load(),
		Tunneled: p.tunneled.Load(),
		Active:   p.active.Load(),
		Rejected: p.rejected.Load(),
	}
}

// Close stops the listener and waits for in-flight connections to finish.
func (p *PortForwarder) Close() {
	p.close.Do(func() {
		if p.ln != nil {
			p.ln.Close()
		}
		if p.udpLn != nil {
			p.udpLn.Close()
		}
	})
	p.wg.Wait()
}

// PortForwardStats is the snapshot served by the management API.
type PortForwardStats struct {
	Spec     string `json:"spec"`
	Listen   string `json:"listen"`
	Policy   string `json:"policy"`
	Accepted int64  `json:"accepted"`
	Tunneled uint64 `json:"tunneled"`
	Active   int64  `json:"active"`
	Rejected uint64 `json:"rejected"`
}

func (f PortForwardSpec) String() string {
	s := fmt.Sprintf("%s:%d:%s", f.BindAddr, f.BindPort, f.Target)
	if f.Proto != "tcp" {
		s += "/" + f.Proto
	}
	return s
}

// mustUDPAddr parses "host:port" into a *net.UDPAddr and panics on failure,
// which is fine here because the spec was already validated by
// ParsePortForwardSpec.
func mustUDPAddr(hostport string) *net.UDPAddr {
	ua, err := net.ResolveUDPAddr("udp", hostport)
	if err != nil {
		panic(fmt.Sprintf("invalid udp address %q: %v", hostport, err))
	}
	return ua
}