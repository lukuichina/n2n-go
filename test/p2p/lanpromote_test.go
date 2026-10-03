package p2p_test

import (
	. "n2n-go/pkg/p2p"
	"net"
	"net/netip"
	"testing"
)

// The ranking fix was only half a fix. Reordering the peer's own addresses
// does nothing while the STUN-reflexive pubSocket is candidate 0, because
// that address is appended unconditionally before the assisted list is
// even read. For a peer sharing our LAN and NAT it is the worst candidate:
// reaching it requires hairpinning the local router, while the LAN address
// the peer already reported is one hop away.
func TestAddrInLocalPrefix(t *testing.T) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("192.168.10.0/24"),
		netip.MustParsePrefix("172.20.160.0/20"),
	}
	cases := []struct {
		ip   string
		want bool
	}{
		{"192.168.10.7", true},
		{"172.20.160.9", true},
		{"192.168.1.11", false}, // a different LAN, no better than public
		{"172.20.192.2", false},
		{"100.76.83.147", false}, // CGNAT
		{"111.101.5.1", false},   // public/STUN
		{"100.64.0.4", false},    // overlay tap, never a punch target
	}
	for _, c := range cases {
		if got := AddrInLocalPrefix(net.ParseIP(c.ip), prefixes); got != c.want {
			t.Errorf("AddrInLocalPrefix(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
	if AddrInLocalPrefix(nil, prefixes) {
		t.Error("nil IP must not match")
	}
}

func TestContainsAddr(t *testing.T) {
	udp := func(a string) *net.UDPAddr {
		ep, err := net.ResolveUDPAddr("udp", a)
		if err != nil {
			t.Fatalf("bad test address %q: %v", a, err)
		}
		return ep
	}
	list := []*net.UDPAddr{udp("192.168.10.7:61706"), udp("100.76.83.147:61706")}
	if !ContainsAddr(list, udp("100.76.83.147:61706")) {
		t.Error("expected membership by exact addr:port")
	}
	// Same IP, different port is a different candidate.
	if ContainsAddr(list, udp("100.76.83.147:9999")) {
		t.Error("port must be part of candidate identity")
	}
	if ContainsAddr(list, nil) {
		t.Error("nil must not match")
	}
}
