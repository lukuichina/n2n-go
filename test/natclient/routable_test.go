package natclient_test

import (
	. "n2n-go/pkg/natclient"
	"net"
	"testing"
)

// --- 2026-09-30: the NetBird address was read as the public one --------------
//
// E1 logged `NAT Setup: found public/routable local ip: 100.101.102.21` and the
// third host `... : 100.76.83.147`. Both are NetBird addresses inside
// 100.64.0.0/10. `!ip.IsPrivate()` accepts them, because Go's IsPrivate covers
// RFC1918 and nothing else, so an overlay address looked like a public one and
// the UPnP setup was skipped as unnecessary.
func TestIsPublicRoutableRejectsCGNATOverlay(t *testing.T) {
	overlays := map[string]bool{
		"100.101.102.21": false, // NetBird on E1
		"100.76.83.147":  false, // NetBird on the third host
		"100.64.0.4":     false, // an n2n tap that slipped through
		"100.127.255.1":  false, // far edge of the pool
	}
	for s, want := range overlays {
		if got := IsPublicRoutable(net.ParseIP(s)); got != want {
			t.Errorf("IsPublicRoutable(%s) = %v, want %v", s, got, want)
		}
	}

	// And the addresses that really are public must keep passing: this test
	// guards a filter that decides whether NAT traversal is attempted at all,
	// so treating a real public address as private would push every such host
	// into a pointless UPnP exchange.
	for _, s := range []string{"2.58.196.38", "57.129.106.133", "111.101.5.1", "8.8.8.8"} {
		if !IsPublicRoutable(net.ParseIP(s)) {
			t.Errorf("IsPublicRoutable(%s) = false, want true", s)
		}
	}

	// Private space is still private, just as before.
	for _, s := range []string{"10.137.189.93", "192.168.10.6", "172.17.0.2"} {
		if IsPublicRoutable(net.ParseIP(s)) {
			t.Errorf("IsPublicRoutable(%s) = true, want false", s)
		}
	}

	// The edges of the pool, checked because a /10 off-by-one here would either
	// admit a real overlay address or reject a routable one. 100.63.255.255 and
	// 100.128.0.0 sit just outside it and are ordinary public space.
	for _, s := range []string{"100.63.255.255", "100.128.0.0"} {
		if !IsPublicRoutable(net.ParseIP(s)) {
			t.Errorf("IsPublicRoutable(%s) = false; it is outside 100.64.0.0/10", s)
		}
	}
	for _, s := range []string{"100.64.0.0", "100.127.255.255"} {
		if IsPublicRoutable(net.ParseIP(s)) {
			t.Errorf("IsPublicRoutable(%s) = true; it is the first/last address of the pool", s)
		}
	}

	// Defensive cases.
	if IsPublicRoutable(nil) {
		t.Error("nil must not count as public")
	}
	if IsPublicRoutable(net.ParseIP("127.0.0.1")) {
		t.Error("loopback must not count as public")
	}
	if IsPublicRoutable(net.ParseIP("169.254.10.1")) {
		t.Error("link-local must not count as public")
	}
	if IsPublicRoutable(net.ParseIP("fe80::1")) {
		t.Error("IPv6 must not count as public here; the P2P socket is udp4")
	}
}
