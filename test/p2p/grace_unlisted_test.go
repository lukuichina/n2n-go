package p2p_test

import (
	. "n2n-go/pkg/p2p"
	"net"
	"testing"
	"time"
)

// A peer missing from one PeerInfoList must not lose the direct path it had
// already proven. Observed 2026-10-02: when log5 dropped, the refresh that
// followed also removed log4/E1/E2, and log3 lost a working 17ms P2P path to
// log4 because the peer was rebuilt at P2PUnknown with an empty P2PRaddr.
func TestUnlistPeerPreservesRaddrForGrace(t *testing.T) {
	reg := NewPeerRegistry("myc")
	mac := "9e:6e:2d:8c:f5:db"

	p, err := reg.AddPeer(PeerInfo{
		MacAddr:     mustMAC(t, mac),
		VirtualIp:   "100.64.0.5",
		PubSocket:   "111.101.5.1:53814",
		P2PEndpoint: "10.0.10.40:53814",
	}, true)
	if err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	p.SetP2PRaddr("172.22.2.44:53814")
	p.SetFullDuplex(true)

	if err := reg.UnlistPeer(mac); err != nil {
		t.Fatalf("UnlistPeer: %v", err)
	}

	// It must be gone from the active registry, or we would keep routing to
	// a machine that left.
	if _, err := reg.GetPeer(mac); err == nil {
		t.Fatal("peer still in reg.Peers after unlist")
	}

	// The address indexes must be released too, so a punch arriving in the
	// gap cannot resolve to a peer we are not routing to.
	if _, err := reg.GetPeerBySocketIP(net.ParseIP("10.0.10.40")); err == nil {
		t.Fatal("peerBySocket still resolves the unlisted peer")
	}

	// Reappearing within the grace window must bring the raddr back.
	back, err := reg.AddPeer(PeerInfo{
		MacAddr:     mustMAC(t, mac),
		VirtualIp:   "100.64.0.5",
		PubSocket:   "111.101.5.1:53814",
		P2PEndpoint: "10.0.10.40:53814",
	}, true)
	if err != nil {
		t.Fatalf("re-AddPeer: %v", err)
	}
	if got := back.GetP2PRaddr(); got != "172.22.2.44:53814" {
		t.Fatalf("raddr not restored across grace: got %q, want %q", got, "172.22.2.44:53814")
	}
}

// P2PStatus must NOT be restored: while the peer was absent we could not hear
// from it, so claiming the tunnel is still up is precisely the "control-plane
// state lies" failure. The raddr is what lets one punch round finish.
func TestGraceRestoreDoesNotClaimFullDuplex(t *testing.T) {
	reg := NewPeerRegistry("myc")
	mac := "9e:6e:2d:8c:f5:db"
	info := PeerInfo{
		MacAddr:     mustMAC(t, mac),
		VirtualIp:   "100.64.0.5",
		PubSocket:   "111.101.5.1:53814",
		P2PEndpoint: "10.0.10.40:53814",
	}
	p, _ := reg.AddPeer(info, true)
	p.SetP2PRaddr("172.22.2.44:53814")
	p.SetFullDuplex(true)

	reg.UnlistPeer(mac)
	back, _ := reg.AddPeer(info, true)

	if back.IsFullDuplex {
		t.Fatal("FullDuplex restored from tombstone; an unobserved peer must not claim a live tunnel")
	}
}

// An explicit Unregister is final and must never consult the tombstone.
func TestRemovePeerIsFinalAndDropsTombstone(t *testing.T) {
	reg := NewPeerRegistry("myc")
	mac := "9e:6e:2d:8c:f5:db"
	info := PeerInfo{
		MacAddr:     mustMAC(t, mac),
		VirtualIp:   "100.64.0.5",
		PubSocket:   "111.101.5.1:53814",
		P2PEndpoint: "10.0.10.40:53814",
	}
	p, _ := reg.AddPeer(info, true)
	p.SetP2PRaddr("172.22.2.44:53814")

	reg.UnlistPeer(mac)
	if reg.GraceUnlistedCountForTest() != 1 {
		t.Fatalf("expected 1 tombstone, got %d", reg.GraceUnlistedCountForTest())
	}

	// RemovePeer on an already-unlisted peer is a no-op and must leave the
	// tombstone alone; the final-forget path is expiry.
	if err := reg.RemovePeer(mac); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}
	if reg.GraceUnlistedCountForTest() != 1 {
		t.Fatal("RemovePeer consumed a tombstone; unlist and explicit removal are different intents")
	}
}

// Past the TTL the tombstone is swept, so a peer that never returns is
// genuinely forgotten rather than leaking state forever.
func TestGraceTombstoneExpires(t *testing.T) {
	reg := NewPeerRegistry("myc")
	mac := "9e:6e:2d:8c:f5:db"
	p, _ := reg.AddPeer(PeerInfo{
		MacAddr:     mustMAC(t, mac),
		VirtualIp:   "100.64.0.5",
		PubSocket:   "111.101.5.1:53814",
		P2PEndpoint: "10.0.10.40:53814",
	}, true)
	p.SetP2PRaddr("172.22.2.44:53814")
	reg.UnlistPeer(mac)

	reg.LockForTest()
	reg.ExpireGraceTombstonesForTest(time.Now().Add(GraceUnlistedTTL + time.Second))
	reg.UnlockForTest()

	if reg.GraceUnlistedCountForTest() != 0 {
		t.Fatal("expired tombstone was not swept")
	}

	// After expiry a reappearance must start clean, with no resurrected raddr.
	back, _ := reg.AddPeer(PeerInfo{
		MacAddr:     mustMAC(t, mac),
		VirtualIp:   "100.64.0.5",
		PubSocket:   "111.101.5.1:53814",
		P2PEndpoint: "10.0.10.40:53814",
	}, true)
	if got := back.GetP2PRaddr(); got != "" {
		t.Fatalf("raddr resurrected past grace: got %q", got)
	}
}
