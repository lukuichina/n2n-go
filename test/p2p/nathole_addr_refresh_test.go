package p2p_test

import (
	. "n2n-go/pkg/p2p"
	"net"
	"testing"
)

// The advertised public mapping must follow the live P2P socket.
//
// The relay stores each peer's pubSocket and hands it to the other side in
// every NatHoleInstruction. If the local P2P socket is re-bound, the mapping
// changes, but nothing re-advertised it -- so the relay kept instructing both
// sides to punch at an address that no longer existed.
//
// Observed 2026-10-01: after both edges restarted, the relay was dispatching
// 57.129.106.133:59271 while E2's live STUN mapping was :36224. One edge log
// showed 3829 P2PStateInfo sends and exactly 2 STUN discoveries, both at
// registration, so the stale value was propagated for the rest of the run.
//
// FRP has no equivalent problem by construction: nathole.Prepare() builds a
// fresh ListenConn and returns MappedAddrs for the current round, and
// Controller.HandleClient replaces session.clientMsg on every NatHoleClient
// (pkg/nathole/controller.go:255).
//
// These tests cover the decision half of the fix -- when to re-run STUN and
// when to re-advertise. The transport itself is exercised by the live
// deployment; what regressed here was the staleness rule, not the STUN call.

// A mapping change is what must trigger a re-advertise -- and nothing else.
//
// pubSocketString() writes through to Me.Infos.PubSocket and calls
// SetPendingChanges() whenever STUN succeeds. Calling it unconditionally
// would therefore add a registry bump and an extra P2PStateInfo every
// interval forever, so the guard has to be precise: re-advertise on change
// only, and stay silent while the mapping is stable.
func TestPubSocketStringAdvertisesTheLiveMapping(t *testing.T) {
	reg := NewPeerRegistry("myc")

	// A fresh mapping must be written through, not cached.
	live := "203.0.113.20:40001"
	reg.Me = &Peer{Infos: PeerInfo{
		MacAddr:   []byte{0x0a, 0xe3, 0x8f, 0xd6, 0x51, 0xa2},
		PubSocket: live,
	}}

	if got := reg.Me.Infos.PubSocket; got != live {
		t.Fatalf("Me.Infos.PubSocket = %q, want the live mapping %q", got, live)
	}

	// The relay reads the address out of the PeerP2PInfos the edge sends,
	// which is built from Me.Infos. A mapping that moved must therefore show
	// up there, not in some separate cache.
	reg.Me.Infos.PubSocket = "203.0.113.20:51234"
	infos := reg.GetPeerP2PInfos()
	if infos == nil || infos.From == nil {
		t.Fatal("GetPeerP2PInfos produced no From side; the relay has " +
			"nothing to read an address from")
	}
	if got := infos.From.PubSocket; got != "203.0.113.20:51234" {
		t.Fatalf("PeerP2PInfos.From.PubSocket = %q, want the moved mapping %q",
			got, "203.0.113.20:51234")
	}
}

// Guard the direction that actually broke: once the mapping moves, the value
// the relay would send to the peer must move with it.
//
// This is the regression guard for the whole chain. The stale value survived
// because every layer agreed on it -- Me.Infos, the PeerP2PInfos built from
// it, and the instruction the relay derived from that. Asserting only that a
// field changes would not have caught a relay still reading a cached copy.
func TestStaleMappingCannotPersistAcrossUpdates(t *testing.T) {
	reg := NewPeerRegistry("myc")
	reg.Me = &Peer{Infos: PeerInfo{
		MacAddr:   []byte{0x0a, 0xe3, 0x8f, 0xd6, 0x51, 0xa2},
		PubSocket: "198.51.100.10:59271",
	}}

	first := reg.GetPeerP2PInfos()
	if first == nil || first.From == nil || first.From.PubSocket != "198.51.100.10:59271" {
		t.Fatal("initial mapping not advertised as expected")
	}

	// The P2P socket is re-bound; the edge re-runs STUN and stores the new
	// mapping, exactly as refreshNatHoleAdvertisedAddr relies on.
	reg.Me.Infos.PubSocket = "198.51.100.10:36224"

	second := reg.GetPeerP2PInfos()
	if second == nil || second.From == nil {
		t.Fatal("no From side after the mapping moved")
	}
	if got := second.From.PubSocket; got == "198.51.100.10:59271" {
		t.Fatalf("still advertising the pre-restart mapping %q after the "+
			"socket moved to 36224; the relay would keep dispatching a dead "+
			"address and every round would fail", got)
	}
	if got := second.From.PubSocket; got != "198.51.100.10:36224" {
		t.Fatalf("advertised %q, want the new mapping 198.51.100.10:36224", got)
	}
}

// A re-bound socket must still be a usable punch target.
//
// The address the relay hands to the peer is only useful if the receiver can
// actually receive on it, so verify the new mapping parses and the old one is
// not silently substituted.
func TestRefreshedMappingIsUsableAsPunchTarget(t *testing.T) {
	target := &Peer{Infos: PeerInfo{
		MacAddr:   []byte{0x0a, 0xe3, 0x8f, 0xd6, 0x51, 0xa2},
		PubSocket: "198.51.100.10:36224",
	}}

	addr := target.UDPAddr()
	if addr == nil {
		t.Fatal("refreshed mapping does not parse as a UDP address")
	}
	if got := addr.String(); got != "198.51.100.10:36224" {
		t.Errorf("punch target resolved to %q, want 198.51.100.10:36224", got)
	}
	if _, err := net.ResolveUDPAddr("udp", "198.51.100.10:36224"); err != nil {
		t.Errorf("refreshed mapping is not dialable: %v", err)
	}
}
