package p2p_test

import (
	. "n2n-go/pkg/p2p"
	"testing"
	"time"
)

// The tombstone exists so a peer that merely dropped out of one snapshot
// resumes on the path it already proved. It must not, however, resurrect an
// address that describes a socket which no longer exists.
//
// Observed 2026-10-04 on E1. log3/log4/log5 were unlisted at 02:32:06 and
// re-registered at 02:33:07-25 -- inside the 90s grace window -- with new
// STUN mappings:
//
//	log3  111.101.5.1:57443 -> 111.101.5.1:65060
//	log5  111.101.5.1:37557 -> 111.101.5.1:46112
//	log4  111.101.5.1:61401 -> 111.101.5.1:58813
//
// The restore handed back the old raddrs anyway, because AddPeer takes its
// not-exists branch here and pubSocketChangedAt -- the only thing that dates
// an raddr against a mapping move -- is set in the exists branch. E1 then
// punched 111.101.5.1:61401/37557/57443 for the next 27 minutes (516/178/106
// rounds) and never reached FullDuplex with any of them, while E2, whose
// mapping never moved, punched fine.
func TestGraceRestoreSkipsRaddrWhenMappingMoved(t *testing.T) {
	reg := NewPeerRegistry("myc")
	mac := "9e:6e:2d:8c:f5:db"

	p, err := reg.AddPeer(PeerInfo{
		MacAddr:     mustMAC(t, mac),
		VirtualIp:   "100.64.0.5",
		PubSocket:   "111.101.5.1:61401", // previous mapping
		P2PEndpoint: "172.22.2.44:61401",
	}, true)
	if err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	p.SetP2PRaddr("111.101.5.1:61401")

	if err := reg.UnlistPeer(mac); err != nil {
		t.Fatalf("UnlistPeer: %v", err)
	}

	// Back inside the grace window, but re-mapped by its NAT.
	back, err := reg.AddPeer(PeerInfo{
		MacAddr:     mustMAC(t, mac),
		VirtualIp:   "100.64.0.5",
		PubSocket:   "111.101.5.1:58813", // new mapping
		P2PEndpoint: "172.22.2.44:58813",
	}, true)
	if err != nil {
		t.Fatalf("re-AddPeer: %v", err)
	}

	if got := back.GetP2PRaddr(); got != "" {
		t.Fatalf("raddr %q was restored across a public mapping move "+
			"111.101.5.1:61401 -> 111.101.5.1:58813; it describes a closed socket", got)
	}
	// The stamp must still be set, or any raddr recorded from here on would
	// be undated and could outrank the fresh pubSocket again.
	if back.RaddrCoversCurrentMapping() {
		t.Error("RaddrCoversCurrentMapping must be false for a peer whose mapping moved")
	}
}

// The grace restore is still worth having when the mapping did NOT move: the
// raddr is then still the best record of the peer's address for inbound
// matching, and re-proving it costs a full punch round.
func TestGraceRestoreKeepsRaddrWhenMappingUnchanged(t *testing.T) {
	reg := NewPeerRegistry("myc")
	mac := "9e:6e:2d:8c:f5:db"

	p, err := reg.AddPeer(PeerInfo{
		MacAddr:     mustMAC(t, mac),
		VirtualIp:   "100.64.0.5",
		PubSocket:   "111.101.5.1:61401",
		P2PEndpoint: "172.22.2.44:61401",
	}, true)
	if err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	p.SetP2PRaddr("111.101.5.1:61401")

	if err := reg.UnlistPeer(mac); err != nil {
		t.Fatalf("UnlistPeer: %v", err)
	}

	back, err := reg.AddPeer(PeerInfo{
		MacAddr:     mustMAC(t, mac),
		VirtualIp:   "100.64.0.5",
		PubSocket:   "111.101.5.1:61401", // same mapping
		P2PEndpoint: "172.22.2.44:61401",
	}, true)
	if err != nil {
		t.Fatalf("re-AddPeer: %v", err)
	}
	if got := back.GetP2PRaddr(); got != "111.101.5.1:61401" {
		t.Fatalf("raddr %q not restored, want 111.101.5.1:61401 -- the mapping never moved", got)
	}
}

// The 90s window is short enough to look safe, which is exactly why this
// slipped through: the peers that returned had been gone long enough for
// their NAT to hand them a different port. Assert the window is still what
// the design intends, so nobody widens it without meeting this test.
func TestGraceWindowIsShort(t *testing.T) {
	if GraceUnlistedTTL > 2*time.Minute {
		t.Fatalf("GraceUnlistedTTL is %v; a peer that restarts inside the window "+
			"may re-map its NAT, so a wide window is how stale raddrs come back", GraceUnlistedTTL)
	}
}

// An expired tombstone must not restore anything, moved mapping or not.
func TestExpiredGraceTombstoneRestoresNothing(t *testing.T) {
	reg := NewPeerRegistry("myc")
	mac := "9e:6e:2d:8c:f5:db"

	p, err := reg.AddPeer(PeerInfo{
		MacAddr:     mustMAC(t, mac),
		VirtualIp:   "100.64.0.5",
		PubSocket:   "111.101.5.1:61401",
		P2PEndpoint: "172.22.2.44:61401",
	}, true)
	if err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	p.SetP2PRaddr("111.101.5.1:61401")
	if err := reg.UnlistPeer(mac); err != nil {
		t.Fatalf("UnlistPeer: %v", err)
	}

	reg.ExpireGraceTombstonesForTest(time.Now().Add(GraceUnlistedTTL + time.Second))

	back, err := reg.AddPeer(PeerInfo{
		MacAddr:     mustMAC(t, mac),
		VirtualIp:   "100.64.0.5",
		PubSocket:   "111.101.5.1:58813",
		P2PEndpoint: "172.22.2.44:58813",
	}, true)
	if err != nil {
		t.Fatalf("re-AddPeer: %v", err)
	}
	if got := back.GetP2PRaddr(); got != "" {
		t.Fatalf("raddr %q restored after the grace window expired", got)
	}
}
