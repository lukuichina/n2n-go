package p2p_test

import (
	. "n2n-go/pkg/p2p"
	"net"
	"testing"
)

// Restoring a tombstoned peer's raddr must also put it back in the socket
// index. The raddr is the NAT-rewritten address the peer is actually reachable
// at, so restoring it without indexing produces a peer that carries a
// plausible address and resolves to nobody -- the state looks recovered and
// is not reachable.
//
// Observed 2026-10-02: a peer that went missing and returned kept its raddr
// across the gap, then every inbound packet from that raddr missed
// GetPeerBySocket and the pair never re-promoted.
func TestGraceRestoredRaddrIsIndexed(t *testing.T) {
	reg := NewPeerRegistry("myc")
	mac := "52:eb:72:ed:64:1f"
	info := PeerInfo{
		MacAddr:     mustMAC(t, mac),
		VirtualIp:   "100.64.0.3",
		PubSocket:   "111.101.5.1:38806",
		P2PEndpoint: "192.168.10.13:38806",
	}

	p, err := reg.AddPeer(info, true)
	if err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	// The router's WAN address -- the only one packets ever arrive from.
	p.SetP2PRaddr("192.168.0.1:49653")
	reg.IndexPeerRaddr(p, "192.168.0.1:49653")

	reg.UnlistPeer(mac)
	back, err := reg.AddPeer(info, true)
	if err != nil {
		t.Fatalf("re-AddPeer: %v", err)
	}

	if got := back.GetP2PRaddr(); got != "192.168.0.1:49653" {
		t.Fatalf("raddr not restored from tombstone: got %q", got)
	}

	observed := &net.UDPAddr{IP: net.ParseIP("192.168.0.1"), Port: 49653}
	resolved, err := reg.GetPeerBySocket(observed)
	if err != nil {
		t.Fatalf("restored raddr is unindexed: %v", err)
	}
	if resolved != back {
		t.Fatalf("restored raddr resolved to the wrong peer: %v", resolved)
	}
}

// Every site that writes a peer's raddr must index it. This walks the
// registry's own consistency rule: a peer whose raddr is set must be
// reachable by socket lookup at that address. The edge-side writers are
// covered by the same invariant through their tests, but the registry is
// where the rule can be stated once.
func TestRaddrImpliesResolvable(t *testing.T) {
	reg := NewPeerRegistry("myc")
	mac := "aa:bc:3a:74:37:b1"
	info := PeerInfo{
		MacAddr:     mustMAC(t, mac),
		VirtualIp:   "100.64.0.4",
		PubSocket:   "111.101.5.1:38329",
		P2PEndpoint: "57.129.106.133:38329",
	}
	p, err := reg.AddPeer(info, true)
	if err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	ua, err := net.ResolveUDPAddr("udp", "57.129.106.133:38329")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	p.SetP2PRaddr(ua.String())
	reg.IndexPeerRaddr(p, ua.String())

	// Indexing must not have clobbered the advertised keys -- a retire pass
	// that mistakes an raddr for an advertisement strands the peer.
	if got, err := reg.GetPeerBySocket(ua); err != nil || got != p {
		t.Fatalf("raddr lookup failed: %v", err)
	}
	pub, err := net.ResolveUDPAddr("udp", "111.101.5.1:38329")
	if err != nil {
		t.Fatalf("resolve pub: %v", err)
	}
	if got, err := reg.GetPeerBySocket(pub); err != nil || got != p {
		t.Fatalf("pubSocket lookup broken after indexing raddr: %v", err)
	}
}
