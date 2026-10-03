package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// perAddressDialTimeout bounds how long one candidate address gets before the
// next one in the family list is tried.
//
// This is what makes "IPv4 first, IPv6 only if IPv4 is unusable" different from
// "wait for the context to die". Without it, an address that blackholes SYNs --
// an AAAA record on a host with no IPv6 route, which is what 2026-10-03 hit on
// E2 -- consumes the entire handshake budget and leaves none for the address
// that would have worked. 10s matches the websocket.Dialer's HandshakeTimeout,
// so the worst case is no worse than the failure it replaces.
const perAddressDialTimeout = 10 * time.Second

// The remaining timeouts match what the proxy paths in wss.go already use.
const (
	familyDialTimeout = 10 * time.Second
	familyKeepAlive   = 30 * time.Second
)

// familyPinnedNetwork reports whether the caller named an address family in the
// network string.
func familyPinnedNetwork(network string) bool {
	switch network {
	case "tcp4", "tcp6", "udp4", "udp6", "ip4", "ip6":
		return true
	}
	return false
}

// IsFamilyPreferred reports whether an address is in the family
// NewFamilyDialContext tries first. Exists so the choice the dialer made can be
// logged once at connect time: when a connection lands on an unexpected family,
// the one fact needed to explain it is which family won.
func IsFamilyPreferred(ip net.IP, preferIPv6 bool) bool {
	return FamilyRank(ip, preferIPv6) == 0
}

// FamilyRank orders a single address: 0 for the preferred family, 1 for the
// other. IPv4-in-IPv6 form counts as IPv4, because that is what it dials as.
func FamilyRank(ip net.IP, preferIPv6 bool) int {
	isV4 := ip.To4() != nil
	switch {
	case preferIPv6 && !isV4:
		return 0
	case preferIPv6 && isV4:
		return 1
	case !preferIPv6 && isV4:
		return 0
	default:
		return 1
	}
}

// OrderByFamily returns the addresses with the preferred family first,
// preserving the resolver's order within each family so the first A or AAAA
// record is still the first one tried.
//
// SliceStable, not Slice: once the family is fixed the resolver's ordering is
// the only remaining preference signal, and there is no reason to discard it.
func OrderByFamily(ips []net.IPAddr, preferIPv6 bool) []net.IPAddr {
	out := make([]net.IPAddr, len(ips))
	copy(out, ips)

	sort.SliceStable(out, func(i, j int) bool {
		return FamilyRank(out[i].IP, preferIPv6) < FamilyRank(out[j].IP, preferIPv6)
	})
	return out
}

// NewFamilyDialContext returns a DialContext that walks a host's resolved
// addresses in a fixed order instead of racing them.
//
// net.Dialer already implements RFC 6555 fast fallback: it starts IPv6 and IPv4
// at once and keeps whichever answers first. That is the right default for a
// browser and the wrong one for the edge's control connection, for two reasons.
//
// First, it can settle on IPv6 even when IPv4 is healthy and closer. The
// control connection then lives on a path with a very different latency profile
// from the p2p socket the edge is about to punch a hole out of, and which family
// it picked depends on a race rather than on anything the operator chose.
//
// Second, on a host with no IPv6 route that does resolve AAAA records, the IPv6
// attempt does not fail fast. E2 could not start at all for this reason: DNS
// returned 2a06:98c1:3120::3 ahead of the A records, and the handshake ran out
// its budget on an address with no route out of the machine.
//
// Walking the list sequentially makes the choice explicit and makes the failover
// bounded: an unreachable preferred family costs at most
// perAddressDialTimeout, not the whole handshake.
func NewFamilyDialContext(preferIPv6 bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		newDialer := func() *net.Dialer {
			return &net.Dialer{Timeout: familyDialTimeout, KeepAlive: familyKeepAlive}
		}

		// An explicit tcp4/tcp6 is the caller pinning the family. Reordering
		// would be arguing with them, and the resolver's answer would be
		// discarded anyway.
		if familyPinnedNetwork(network) {
			return newDialer().DialContext(ctx, network, addr)
		}

		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			// Not host:port -- the resolver path below cannot handle it either.
			// Let the stock dialer produce the error users already know.
			return newDialer().DialContext(ctx, network, addr)
		}

		// A literal address is its own only candidate; reordering is a no-op.
		// Skip the resolver: it is the slow part of a dial and there is nothing
		// here for it to decide.
		if ip := net.ParseIP(host); ip != nil {
			return newDialer().DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		}

		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", host, err)
		}

		ordered := OrderByFamily(ips, preferIPv6)
		if len(ordered) == 0 {
			return nil, fmt.Errorf("dial %s: no usable addresses", host)
		}

		errs := make([]error, 0, len(ordered))
		for _, ip := range ordered {
			target := net.JoinHostPort(ip.String(), port)

			attemptCtx, cancel := context.WithTimeout(ctx, perAddressDialTimeout)
			conn, dialErr := newDialer().DialContext(attemptCtx, network, target)
			cancel()

			if dialErr == nil {
				return conn, nil
			}
			errs = append(errs, fmt.Errorf("%s: %w", target, dialErr))

			// A dead parent context means the caller gave up on the dial, not
			// just on this address. Walking the rest would ignore that.
			if ctx.Err() != nil {
				break
			}
		}

		return nil, joinAddressErrors(host, errs)
	}
}

// joinAddressErrors reports every address tried, not only the last one.
//
// "dial tcp: lookup n2ngo-ws.swings.one: i/o timeout" was the entirety of the
// E2 startup failure, with nothing hinting that an address had been skipped.
// Once the dialer walks a list, the list belongs in the error -- especially
// when the point of the list is that some of its entries are expected to fail.
func joinAddressErrors(host string, errs []error) error {
	switch len(errs) {
	case 0:
		return fmt.Errorf("dial %s: no addresses to try", host)
	case 1:
		return errs[0]
	}
	msgs := make([]string, 0, len(errs))
	for _, err := range errs {
		msgs = append(msgs, err.Error())
	}
	return fmt.Errorf("dial %s: all %d addresses failed: %s", host, len(errs), strings.Join(msgs, "; "))
}

// familyForwardDialer adapts NewFamilyDialContext to proxy.Dialer, which is the
// forward-dial hook proxy.SOCKS5 takes. Using it means the SOCKS5 proxy itself
// is reached in the preferred family, which is the only family choice this
// process actually makes when a proxy is in the path.
type familyForwardDialer struct {
	ctx  context.Context
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (f *familyForwardDialer) Dial(network, addr string) (net.Conn, error) {
	ctx := f.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return f.dial(ctx, network, addr)
}

// familyTLSDial is tls.Dial with the family ordering applied.
//
// tls.Dial has no DialContext form that accepts a custom dialer, and its
// internal resolution is exactly the behaviour being replaced -- so the TCP
// connection is made here and the handshake layered on top.
//
// ctx is used for the handshake only; the TCP connection carries its own
// per-address deadline from familyDial.
func familyTLSDial(
	ctx context.Context,
	dial func(ctx context.Context, network, addr string) (net.Conn, error),
	hostPort string,
	cfg *tls.Config,
) (*tls.Conn, error) {
	conn, err := dial(ctx, "tcp", hostPort)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	return tlsConn, nil
}
