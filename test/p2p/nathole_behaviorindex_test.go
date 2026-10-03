package p2p_test

import (
	. "n2n-go/pkg/p2p"
	"testing"
)

// A round that runs out of attempts deletes its own instruction (p2p.go:2360)
// before writing the failure report. Anything that re-derives the rung by
// scanning the cache after that point finds nothing and falls back to 0, so the
// relay penalises a rung that never ran.
//
// Observed 2026-09-30: E1/E4 exhausted a round of rung 4, the failure was
// reported as index 0, and the relay drove that rung's score to its -10 floor
// while continuing to re-arm the pair at the 300s cap.

func TestExhaustedRoundReportsTheRungItActuallyRan(t *testing.T) {
	reg := NewPeerRegistry("myc")
	reg.Me = &Peer{Infos: PeerInfo{MacAddr: []byte{0x52, 0xeb, 0x72, 0xed, 0x64, 0x1f}}}

	const rung = uint32(4)
	const mac = "0a:e3:8f:d6:51:a2"
	target := []byte{0x0a, 0xe3, 0x8f, 0xd6, 0x51, 0xa2}

	// What the round does: take a rung-4 instruction, run it, then clear it.
	instr := &NatHoleInstruction{TargetMac: target, BehaviorIndex: rung}
	reg.SetNatHoleInstructionsForTest(map[string]*NatHoleInstruction{mac: instr})

	// The instruction is deleted before the report is written, exactly as
	// ExecuteNatHolePunch does when the fifth attempt fails.
	delete(reg.NatHoleInstructionsForTest(), mac)
	reg.LockForTest()
	reg.RecordNatHolePunchResultForTest(
		mac,
		NatHolePunchState_PunchStateFailed,
		5,
		"exhausted 5 punch attempts",
		instr.GetBehaviorIndex(),
	)
	reg.UnlockForTest()

	got := reg.NatHolePunchResultsForTest()[mac]
	if got == nil {
		t.Fatal("no failure was recorded")
	}
	if got.BehaviorIndex != rung {
		t.Fatalf("failure blamed rung %d, want %d: the instruction was deleted "+
			"before the report, so a cache lookup would have returned 0",
			got.BehaviorIndex, rung)
	}
	if got.State != NatHolePunchState_PunchStateFailed {
		t.Fatalf("state = %v, want Failed", got.State)
	}
	if got.Attempts != 5 {
		t.Fatalf("attempts = %d, want 5", got.Attempts)
	}
}

// The cache lookup this replaced: after the instruction is gone it cannot find
// the rung. This is the behaviour the fix exists to avoid, pinned so that
// changing the ordering cannot reintroduce it unnoticed.
func TestCacheLookupCannotRecoverTheRungOnceTheInstructionIsDeleted(t *testing.T) {
	reg := NewPeerRegistry("myc")
	const mac = "0a:e3:8f:d6:51:a2"
	reg.SetNatHoleInstructionsForTest(map[string]*NatHoleInstruction{
		mac: {TargetMac: []byte{0x0a, 0xe3, 0x8f, 0xd6, 0x51, 0xa2}, BehaviorIndex: 4},
	})

	if got := reg.CurrentNatHoleBehaviorIndex(mac); got != 4 {
		t.Fatalf("with the instruction present, lookup returned %d, want 4", got)
	}

	delete(reg.NatHoleInstructionsForTest(), mac)
	if got := reg.CurrentNatHoleBehaviorIndex(mac); got != 0 {
		t.Fatalf("after deletion lookup returned %d; expected the 0 fallback", got)
	}
}

// Both writers must produce the same outcome. The failure path used to build
// the literal inline, which is how the two drifted apart in the first place.
func TestBothWritersProduceTheSameOutcome(t *testing.T) {
	const mac = "0a:e3:8f:d6:51:a2"

	viaExport := NewPeerRegistry("myc")
	viaExport.RecordNatHolePunchResult(mac, NatHolePunchState_PunchStateFailed, 5, "d", 4)

	viaLocked := NewPeerRegistry("myc")
	viaLocked.LockForTest()
	viaLocked.RecordNatHolePunchResultForTest(mac, NatHolePunchState_PunchStateFailed, 5, "d", 4)
	viaLocked.UnlockForTest()

	a := viaExport.NatHolePunchResultsForTest()[mac]
	b := viaLocked.NatHolePunchResultsForTest()[mac]
	if a == nil || b == nil {
		t.Fatal("one of the writers recorded nothing")
	}
	// protobuf messages carry an internal state field, so compare the fields
	// that are actually meaningful here.
	if a.State != b.State || a.Attempts != b.Attempts ||
		a.Detail != b.Detail || a.BehaviorIndex != b.BehaviorIndex {
		t.Fatalf("exported writer produced %+v, locked writer produced %+v", a, b)
	}
	if !viaLocked.HasPendingChanges() {
		t.Fatal("locked writer did not flag pending changes; the report would sit " +
			"in the map until an unrelated change triggered an update")
	}
}
