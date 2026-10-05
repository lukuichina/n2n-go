package edge

// Parsing for the -L / --socks5-listen shorthand.
//
// The flag reads like a proxy URL, because that is how every other proxy in the
// world is configured and having to remember a separate --socks5-auth flag for
// the password is just one more thing to get wrong:
//
//	-L socks5                        -> socks5 on 127.0.0.1:1080
//	-L socks5://1.2.3.4:1080         -> socks5 on 1.2.3.4:1080
//	-L http://1.2.3.4:8080           -> same listener, HTTP-style URL
//	-L http://user:pwd@1.2.3.4:8080  -> credentials taken from the URL
//	-L 1.2.3.4:1080                  -> no scheme, read as a listen address
//
// One subtlety worth stating plainly: the scheme does not select a different
// listener. The ingress auto-detects SOCKS5 and HTTP on the same socket by
// peeking at the first byte, so socks5:// and http:// bind identically. What
// the URL actually carries that matters is the credentials -- and "http://user:pass@..."
// is how everyone already writes a password, so honouring it removes a flag.

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ProxyListenSpec is the decoded form of the -L value.
type ProxyListenSpec struct {
	// Addr is normalised to "host:port" and ready for net.Listen.
	Addr string
	// Scheme is "socks5" or "http"; purely informational, both bind the same.
	Scheme string
	// User and Pass come from the URL, empty when none were given.
	User string
	Pass string
}

// Auth renders the credentials back into the "user:pass" form the server takes,
// or "" when there are none.
func (s ProxyListenSpec) Auth() string {
	if s.User == "" && s.Pass == "" {
		return ""
	}
	return s.User + ":" + s.Pass
}

const (
	defaultProxyAddr    = "127.0.0.1"
	defaultProxyPort    = "1080"
	schemeSocks5        = "socks5"
	schemeHTTP          = "http"
	schemeHTTPSTerseTLS = "https"
)

// ParseProxyListenSpec decodes the -L shorthand.
func ParseProxyListenSpec(spec string) (ProxyListenSpec, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return ProxyListenSpec{}, fmt.Errorf("empty proxy listen specification")
	}

	var out ProxyListenSpec

	// A bare scheme word with nothing after it is the documented shorthand for
	// "the default address, default port".
	switch strings.ToLower(spec) {
	case schemeSocks5, schemeSocks5 + "://":
		out.Addr = defaultProxyAddr + ":" + defaultProxyPort
		out.Scheme = schemeSocks5
		return out, nil
	case schemeHTTP, schemeHTTP + "://":
		out.Addr = defaultProxyAddr + ":" + defaultProxyPort
		out.Scheme = schemeHTTP
		return out, nil
	}

	// Anything else needs to look like a URL. url.Parse would read a bare
	// "1.2.3.4:1080" as scheme "1.2.3.4" with opaque "1080", which is not what
	// anyone means, so give the parser a scheme when there isn't one.
	parseTarget := spec
	hasScheme := strings.Contains(spec, "://")
	if !hasScheme {
		// ":1080", "1080" and "1.2.3.4:1080" are addresses, not URLs.
		parseTarget = schemeSocks5 + "://" + spec
	}

	u, err := url.Parse(parseTarget)
	if err != nil {
		return ProxyListenSpec{}, fmt.Errorf("invalid proxy listen specification %q: %w", spec, err)
	}

	switch strings.ToLower(u.Scheme) {
	case schemeSocks5, schemeSocks5 + "5", "socks", "socks4":
		out.Scheme = schemeSocks5
	case schemeHTTP, schemeHTTPSTerseTLS:
		out.Scheme = schemeHTTP
	default:
		return ProxyListenSpec{}, fmt.Errorf(
			"invalid proxy listen specification %q: scheme must be socks5 or http", spec)
	}

	if u.User != nil {
		out.User = u.User.Username()
		out.Pass, _ = u.User.Password()
	}

	// u.Host is the authority; u.Opaque is set instead when the original
	// looked like "scheme:rest" with no "//" -- e.g. "socks5:1080".
	host := u.Host
	if host == "" {
		host = u.Opaque
	}

	// Reuse ParseListenAddr so that every address form it already understands
	// (bare port, omitted addr, bracketed and bare IPv6) behaves identically
	// here. Pass the authority minus any credentials.
	addr, err := ParseListenAddr(host, defaultProxyAddr, defaultProxyPort)
	if err != nil {
		return ProxyListenSpec{}, fmt.Errorf("invalid proxy listen address in %q: %w", spec, err)
	}
	out.Addr = addr

	return out, nil
}

// String renders the spec back into the canonical -L form, which is what the
// flag prints when the operator asks what they actually asked for.
func (s ProxyListenSpec) String() string {
	b := s.Scheme + "://"
	if s.User != "" || s.Pass != "" {
		b += s.User
		if s.Pass != "" {
			b += ":" + s.Pass
		}
		b += "@"
	}
	return b + s.Addr
}

// Redacted is String with the password replaced, for anything that gets
// printed or logged. The password must never reach a log line.
func (s ProxyListenSpec) Redacted() string {
	if s.Pass == "" {
		return s.String()
	}
	return s.Scheme + "://" + s.User + ":***@" + s.Addr
}

// ListenHost extracts just the host part of Addr, for the loopback check that
// decides whether an open relay needs a warning.
func (s ProxyListenSpec) ListenHost() string {
	h, _, err := net.SplitHostPort(s.Addr)
	if err != nil {
		return s.Addr
	}
	return h
}

// listenTCP exists so the spec tests can assert that a decoded address really
// binds, without importing net just for the test.
func listenTCP(addr string) (net.Listener, error) { return net.Listen("tcp", addr) }
