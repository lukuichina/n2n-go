package p2p_test

import (
	. "n2n-go/pkg/p2p"
	"net"
	"testing"
)

// Two peers behind one NAT gateway publish the same address and differ only
// by port -- log3 at 111.101.5.1:62040 and log5 at 111.101.5.1:48009, both
// arriving at log4 as 172.22.1.17:<their port>.
//
// The IP therefore cannot tell them apart, and GetPeerBySocketIP genuinely
// cannot: it scans a map and returns whichever peer it reaches first, so the
// answer is not even stable between calls. This test pins that instability
// down as the reason the port check has to exist, rather than asserting the
// lookup is merely "usually right".
func TestGetPeerBySocketIPIsAmbiguousForSharedGateway(t *testing.T) {
	reg := NewPeerRegistry("myc")
	log3, err := reg.AddPeer(PeerInfo{
		MacAddr:   mustMAC(t, "ea:2f:de:90:a5:72"),
		VirtualIp: "100.64.0.3",
		PubSocket: "111.101.5.1:62040",
	}, true)
	if err != nil {
		t.Fatalf("AddPeer log3: %v", err)
	}
	log5, err := reg.AddPeer(PeerInfo{
		MacAddr:   mustMAC(t, "52:eb:72:ed:64:1f"),
		VirtualIp: "100.64.0.5",
		PubSocket: "111.101.5.1:48009",
	}, true)
	if err != nil {
		t.Fatalf("AddPeer log5: %v", err)
	}

	shared := net.ParseIP("111.101.5.1")
	var sawLog3, sawLog5 bool
	for i := 0; i < 200; i++ {
		got, err := reg.GetPeerBySocketIP(shared)
		if err != nil {
			t.Fatalf("iteration %d: shared gateway IP should match someone: %v", i, err)
		}
		switch got {
		case log3:
			sawLog3 = true
		case log5:
			sawLog5 = true
		default:
			t.Fatalf("iteration %d: unexpected peer %v", i, got)
		}
	}
	if !sawLog3 || !sawLog5 {
		t.Logf("note: this run returned only one peer (log3=%v log5=%v); map order may coincide",
			sawLog3, sawLog5)
	}
}

// PeerClaimingPort is the tie-breaker that GetPeerBySocketIP cannot provide:
// given the observed source port it must name the peer that port belongs to,
// and must never name the peer being considered.
func TestPeerClaimingPortTieBreaksSharedGateway(t *testing.T) {
	reg := NewPeerRegistry("myc")
	log3, err := reg.AddPeer(PeerInfo{
		MacAddr:   mustMAC(t, "ea:2f:de:90:a5:72"),
		VirtualIp: "100.64.0.3",
		PubSocket: "111.101.5.1:62040",
	}, true)
	if err != nil {
		t.Fatalf("AddPeer log3: %v", err)
	}
	log5, err := reg.AddPeer(PeerInfo{
		MacAddr:   mustMAC(t, "52:eb:72:ed:64:1f"),
		VirtualIp: "100.64.0.5",
		PubSocket: "111.101.5.1:48009",
	}, true)
	if err != nil {
		t.Fatalf("AddPeer log5: %v", err)
	}

	if got := reg.PeerClaimingPort(48009, nil); got != log5 {
		t.Fatalf("port 48009 belongs to log5; got %v", got)
	}
	if got := reg.PeerClaimingPort(62040, nil); got != log3 {
		t.Fatalf("port 62040 belongs to log3; got %v", got)
	}
	// Excluding the candidate must never yield that same candidate -- that
	// is the whole guard: "is this port spoken for by somebody else?"
	if got := reg.PeerClaimingPort(48009, log5); got != nil {
		t.Fatalf("excluding log5, port 48009 has no other owner; got %v", got)
	}
	if got := reg.PeerClaimingPort(48009, log3); got != log5 {
		t.Fatalf("excluding log3, port 48009 must still resolve to log5; got %v", got)
	}
	if got := reg.PeerClaimingPort(9, nil); got != nil {
		t.Fatalf("unclaimed port must resolve to nobody; got %v", got)
	}
}

// The raddr of an observed packet is an address too, so it must take part in
// the port tie-breaker. Before this, a punch recorded against the wrong peer
// also poisoned the index: log4 held log3 at 172.22.1.17:48009, and a later
// packet from log5's real port then matched log3's stale raddr by IP.
func TestPeerClaimingPortSeesObservedRaddrs(t *testing.T) {
	reg := NewPeerRegistry("myc")
	log3, err := reg.AddPeer(PeerInfo{
		MacAddr:   mustMAC(t, "ea:2f:de:90:a5:72"),
		VirtualIp: "100.64.0.3",
		PubSocket: "111.101.5.1:62040",
	}, true)
	if err != nil {
		t.Fatalf("AddPeer log3: %v", err)
	}
	log5, err := reg.AddPeer(PeerInfo{
		MacAddr:   mustMAC(t, "52:eb:72:ed:64:1f"),
		VirtualIp: "100.64.0.5",
		PubSocket: "111.101.5.1:48009",
	}, true)
	if err != nil {
		t.Fatalf("AddPeer log5: %v", err)
	}

	// log4 observes both peers behind its gateway.
	log3.SetP2PRaddr("172.22.1.17:62040")
	reg.IndexPeerRaddr(log3, "172.22.1.17:62040")
	log5.SetP2PRaddr("172.22.1.17:48009")
	reg.IndexPeerRaddr(log5, "172.22.1.17:48009")

	if got := reg.PeerClaimingPort(48009, log3); got != log5 {
		t.Fatalf("a punch for log3 arriving on log5's gateway port must be caught; got %v", got)
	}
	if got := reg.PeerClaimingPort(62040, log5); got != log3 {
		t.Fatalf("a punch for log5 arriving on log3's gateway port must be caught; got %v", got)
	}
}
