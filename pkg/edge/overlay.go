package edge

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
)

// errOverlayUnknown is returned when the overlay subnet cannot be determined
// from the TAP. It is deliberately a sentinel rather than an inline string so
// callers can distinguish "policy refused because the subnet is unknown" from
// "policy refused because the destination is genuinely outside it".
var errOverlayUnknown = errors.New("overlay subnet is unknown (TAP not configured yet)")

// OverlayPolicy decides whether a forwarder may reach destinations outside the
// overlay. It is shared between the SOCKS5 ingress and the port forwarders so
// the two cannot drift apart.
type OverlayPolicy string

const (
	// OverlayPolicyOverlay only serves destinations that resolve into the
	// subnet configured on the TAP. This is the default for -L and for SOCKS5,
	// because it cannot turn the host into a relay for the internet.
	OverlayPolicyOverlay OverlayPolicy = "overlay"
	// OverlayPolicyAny serves any destination. This is the default for -R,
	// because a remote forward exists specifically to bridge the overlay out
	// to the wider network; refusing everything but the overlay would make the
	// flag useless.
	OverlayPolicyAny OverlayPolicy = "any"
)

// overlayNets resolves the subnets configured on the TAP. It prefers asking
// the interface, because that is what the kernel actually routes with, and
// falls back to the address the supernode handed us.
//
// It is shared between the SOCKS5 ingress and the port forwarders, so the
// overlay policy is one rule rather than two that can drift apart.
func overlayNets(edge *EdgeClient, cache *[]*net.IPNet, once *sync.Once) []*net.IPNet {
	once.Do(func() {
		if edge == nil {
			return
		}
		name := ""
		if edge.TAP != nil {
			name = edge.TAP.Name()
		} else if edge.config != nil {
			name = edge.config.TapName
		}
		if name != "" {
			if ifc, err := net.InterfaceByName(name); err == nil {
				if addrs, err := ifc.Addrs(); err == nil {
					for _, a := range addrs {
						if n, ok := a.(*net.IPNet); ok {
							*cache = append(*cache, n)
						}
					}
				} else {
					log.Printf("overlay: cannot list addresses of %s: %v", name, err)
				}
			} else {
				log.Printf("overlay: cannot look up interface %s: %v", name, err)
			}
		}
		if len(*cache) == 0 && edge.VirtualIP != "" {
			if _, n, err := net.ParseCIDR(edge.VirtualIP); err == nil {
				*cache = append(*cache, n)
			}
		}
	})
	return *cache
}

// ipInNets reports whether ip is contained by any of nets.
func ipInNets(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// overlayAllows reports whether host, an IP literal or a name, lands inside
// the overlay. Names are resolved here because the policy is about where the
// bytes end up, not about how they were spelled.
func overlayAllows(host string, nets []*net.IPNet) (bool, error) {
	if len(nets) == 0 {
		return false, errOverlayUnknown
	}
	if ip := net.ParseIP(host); ip != nil {
		return ipInNets(ip, nets), nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(context.Background(), host)
	if err != nil {
		return false, fmt.Errorf("cannot resolve %q: %w", host, err)
	}
	for _, a := range addrs {
		if ipInNets(a.IP, nets) {
			return true, nil
		}
	}
	return false, nil
}

// overlayAllowsPolicy is the policy-aware wrapper. It exists so the port
// forwarders and the SOCKS5 ingress share one implementation: a -L forward
// and a SOCKS5 proxy both default to overlay-only, while a -R forward defaults
// to any. Passing OverlayPolicyAny short-circuits the subnet check entirely.
func overlayAllowsPolicy(host string, nets []*net.IPNet, policy OverlayPolicy) (bool, error) {
	switch policy {
	case OverlayPolicyAny:
		return true, nil
	case OverlayPolicyOverlay:
		return overlayAllows(host, nets)
	default:
		return false, fmt.Errorf("unknown overlay policy %q (want %q or %q)",
			policy, OverlayPolicyOverlay, OverlayPolicyAny)
	}
}

// overlayAllowsAddr is the same check for a net.Addr, which is what an accept
// gives us: the remote peer's address before any bytes are read. It extracts
// the host and delegates to overlayAllowsPolicy.
func overlayAllowsAddr(addr net.Addr, nets []*net.IPNet, policy OverlayPolicy) (bool, error) {
	if addr == nil {
		return false, errOverlayUnknown
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		// Some addrs are not host:port; fall back to the raw string, which
		// overlayAllows handles by parsing it as an IP literal.
		host = addr.String()
	}
	return overlayAllowsPolicy(host, nets, policy)
}