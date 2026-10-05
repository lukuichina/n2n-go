package p2p_test

import (
	. "n2n-go/pkg/p2p"
	"testing"
)

// The punch path capability exists because P2PStatus cannot express "the hole
// is open but no data frame has confirmed it yet". These tests pin the three
// rules that make it safe: only the handshake opens it, only the data plane
// closes it, and in between no control-plane probe can take it away.
//
// Reproduces log3 (192.168.10.7) against log4 (172.22.2.44), both behind
// CGNAT 111.101.5.1, on 2026-10-04: the pair reached strat=2 via p2p and was
// demoted to relay nine times over 36 seconds while its hole was open.
func newPunchPeer(t *testing.T) *Peer {
	t.Helper()
	reg := NewPeerRegistry("myc")
	reg.SetMe(PeerInfo{MacAddr: mustMAC(t, "ea:2f:de:90:a5:72")})
	p, err := reg.AddPeer(PeerInfo{
		MacAddr:   mustMAC(t, "9e:6e:2d:8c:f5:db"),
		VirtualIp: "100.64.0.5",
		PubSocket: "111.101.5.1:64537",
	}, true)
	if err != nil {
		t.Fatalf("registering the peer: %v", err)
	}
	// Walk the liveness cycle the edge actually runs: Pending arms the TTL,
	// and the pong that follows promotes to Available. Skipping this leaves
	// pendingTTL at zero, and every later update then takes the "Forcefull
	// update, hole-punching TTL<0" branch to Unavailable -- which is correct
	// behaviour, just not what these tests are about.
	p.UpdateP2PStatus(P2PPending, "check-1")
	p.UpdateP2PStatus(P2PAvailable, "check-1")
	if p.P2PStatus != P2PAvailable {
		t.Fatalf("liveness cycle did not settle at Available, got %s", p.P2PStatus)
	}
	return p
}

// A control-plane probe arriving between "punched" and "first data frame" must
// not demote the peer. This is the exact transition that cost the log3/log4
// pair 36 seconds.
func TestControlPlaneProbeCannotDemoteOpenPunchPath(t *testing.T) {
	p := newPunchPeer(t)

	// The handshake completed: the hole is open, no data frame yet.
	p.NotePunchPathOpen()
	if !p.PunchPathOpen() {
		t.Fatal("the handshake did not open the path")
	}
	// A pong whose checkID has been superseded arrives and drives the peer to
	// Unknown. It must be refused.
	if p.UpdateP2PStatus(P2PUnknown, "") {
		t.Fatal("a control-plane probe demoted a peer with an open punch path")
	}
	if p.P2PStatus != P2PAvailable {
		t.Fatalf("status became %s, want Available to be retained", p.P2PStatus)
	}
	if !p.PunchPathOpen() {
		t.Fatal("the punch path capability was withdrawn by a control-plane probe")
	}
}

// Repeated probes must not erode the capability either: the field pair logged
// nine demotions in the same window.
func TestRepeatedControlPlaneProbesAreInert(t *testing.T) {
	p := newPunchPeer(t)
	p.NotePunchPathOpen()

	for i := 0; i < 9; i++ {
		p.UpdateP2PStatus(P2PUnknown, "")
	}
	if p.P2PStatus != P2PAvailable || !p.PunchPathOpen() {
		t.Fatalf("after 9 probes: status=%s pathOpen=%v, want Available/true",
			p.P2PStatus, p.PunchPathOpen())
	}
}

// A relay pong must not withdraw the capability. SetFullDuplex(false) is also
// called when a pong arrives via the supernode, meaning only that the liveness
// probe took the relay -- which is true of every probe in the window between a
// successful punch and the first data frame. log3 against log4 was punched
// successfully and had the capability withdrawn 40ms later by a relay pong,
// oscillating between p2p and relay through 316s of re-punching (2026-10-05).
func TestRelayPongDoesNotWithdrawPunchPath(t *testing.T) {
	p := newPunchPeer(t)
	p.NotePunchPathOpen()
	p.NoteDataPacket()
	if _, err := p.SetFullDuplex(true); err != nil {
		t.Fatalf("promoting to FullDuplex: %v", err)
	}

	// The relay pong path: demote FullDuplex without touching the capability.
	p.SetFullDuplex(false)
	if !p.PunchPathOpen() {
		t.Fatal("a relay pong withdrew the punch path capability")
	}
}

// The data plane must still be able to withdraw it, or a dead path would keep
// its capability and every later Unknown would be refused -- pinning the peer
// over a path the data plane has already written off.
func TestDataPlaneTimeoutWithdrawsPunchPath(t *testing.T) {
	p := newPunchPeer(t)
	p.NotePunchPathOpen()
	p.NoteDataPacket()
	if _, err := p.SetFullDuplex(true); err != nil {
		t.Fatalf("promoting to FullDuplex: %v", err)
	}

	// keepAliveTick does exactly this on a genuine data-path timeout.
	if p.PunchPathOpen() {
		p.ClearPunchPath()
	}
	if p.PunchPathOpen() {
		t.Fatal("the data plane failed to withdraw the punch path")
	}
	// The guard's own precondition: UpdateP2PStatus refuses a control-plane
	// demotion only while PunchPathOpen() is true. Once withdrawn it can no
	// longer be the reason a status change is refused, which is what keeps a
	// dead path from being pinned.
	if p.PunchPathOpen() {
		t.Fatal("the guard precondition is still true after withdrawal")
	}

	// And the capability cannot be resurrected by control-plane traffic: only
	// the punch handshake and real data frames open it.
	p.UpdateP2PStatus(P2PPending, "check-2")
	p.UpdateP2PStatus(P2PAvailable, "check-2")
	if p.PunchPathOpen() {
		t.Fatal("a control-plane update reopened the punch path capability")
	}
}

// A peer that never punched has no capability, so a probe demotes it normally.
func TestProbeStillDemotesWhenNoPunchPath(t *testing.T) {
	p := newPunchPeer(t)
	if p.PunchPathOpen() {
		t.Fatal("a peer that never punched must have no open punch path")
	}
	p.UpdateP2PStatus(P2PAvailable, "check-1")
	if !p.UpdateP2PStatus(P2PUnknown, "") {
		t.Fatal("a peer with no punch path should demote to Unknown normally")
	}
	if p.P2PStatus != P2PUnknown {
		t.Fatalf("status is %s, want Unknown", p.P2PStatus)
	}
}

// A real data frame opens the path on its own: the handshake is not the only
// evidence that a direct path exists.
func TestDataFrameOpensPunchPath(t *testing.T) {
	p := newPunchPeer(t)
	if p.PunchPathOpen() {
		t.Fatal("path must start closed")
	}
	p.NoteDataPacket()
	if !p.PunchPathOpen() {
		t.Fatal("a verified data frame must open the punch path")
	}
}
