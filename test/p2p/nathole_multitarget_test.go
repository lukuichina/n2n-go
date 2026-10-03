package p2p_test

import (
	. "n2n-go/pkg/p2p"
	"testing"
)

// --- 2026-09-30: one punch round starved every peer but one ---------------------
//
// With three edges up, E1 was told to punch both E2 and the third host. E1's
// rounds went to the third host every time, and E2 -- sitting as receiver,
// punching an E1 that never punched back -- timed out five times and was marked
// P2PUnavailable. The pair then ran at relay speed (~343ms instead of ~16ms).
//
// The cause is the map key. SetNatHoleInstruction stored every instruction under
// OUR OWN MAC, which is identical for all of them, so each new instruction
// overwrote the one before it and only the last arrival survived. The tests
// below pin the per-target keying and the round-robin that together make every
// pending peer get served.

func mac(t *testing.T, s string) []byte {
	t.Helper()
	b := macOf(s)
	if len(b) != 6 {
		t.Fatalf("bad MAC %q", s)
	}
	return b
}

func mkInstr(target string, role NatHoleRole) *NatHoleInstruction {
	return &NatHoleInstruction{
		Role:           role,
		TargetMac:      macOf(target),
		SenderMac:      macOf("0a:e3:8f:d6:51:a2"),
		PortsRangeFrom: 0,
		PortsRangeTo:   0,
		Ttl:            7,
	}
}

func macOf(s string) []byte {
	var b []byte
	var v int
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		var d int
		switch {
		case c >= '0' && c <= '9':
			d = int(c - '0')
		case c >= 'a' && c <= 'f':
			d = int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = int(c-'A') + 10
		default:
			continue
		}
		v = v<<4 | d
		n++
		if n == 2 {
			b = append(b, byte(v))
			v, n = 0, 0
		}
	}
	return b
}

const (
	macE1 = "0a:e3:8f:d6:51:a2"
	macE2 = "aa:bc:3a:74:37:b1"
	macE3 = "ea:2f:de:90:a5:72"
)

// Instructions for different targets must coexist. Under the old own-MAC
// keying the second store silently clobbered the first, which is precisely how
// E2's punch went missing while E1 was punching the third host.
func TestSetNatHoleInstruction_KeepsOneEntryPerTarget(t *testing.T) {
	reg := NewPeerRegistry("myc")
	our := mac(t, macE1)

	reg.SetNatHoleInstruction(our, mkInstr(macE2, NatHoleRole_DetectRoleSender))
	reg.SetNatHoleInstruction(our, mkInstr(macE3, NatHoleRole_DetectRoleSender))

	if got := len(reg.NatHoleInstructionsForTest()); got != 2 {
		t.Fatalf("pending instructions = %d, want 2: one per target", got)
	}
	for _, want := range []string{macE2, macE3} {
		if _, ok := reg.NatHoleInstructionsForTest()[want]; !ok {
			t.Errorf("no instruction stored for %s; keys are now target MACs, got %v", want, keysOf(reg.NatHoleInstructionsForTest()))
		}
	}
}

// Re-broadcasting the same instruction every ~2s must not reset the attempt
// count -- otherwise a peer never gets past "attempt 1/5".
func TestSetNatHoleInstruction_ReBroadcastKeepsRetryCount(t *testing.T) {
	reg := NewPeerRegistry("myc")
	our := mac(t, macE1)

	reg.SetNatHoleInstruction(our, mkInstr(macE2, NatHoleRole_DetectRoleSender))
	reg.NatHoleRetryCountsForTest()[macE2] = 3

	// Identical instruction, same ports/TTL/role/target.
	reg.SetNatHoleInstruction(our, mkInstr(macE2, NatHoleRole_DetectRoleSender))

	if got := reg.NatHoleRetryCountsForTest()[macE2]; got != 3 {
		t.Errorf("retry count = %d, want 3: a re-broadcast of the same instruction must not reset it", got)
	}

	// A genuinely different target IS a new unit of work.
	reg.SetNatHoleInstruction(our, mkInstr(macE3, NatHoleRole_DetectRoleSender))
	if _, ok := reg.NatHoleRetryCountsForTest()[macE3]; !ok {
		t.Error("a new target has no retry-count entry")
	}
}

// The round-robin must visit every pending target, not just whichever one the
// map yielded first. Go randomises map iteration, so the old "range and break"
// selection was not merely unfair -- it made starvation the norm once two
// targets were pending.
func TestNextNatHoleInstruction_RotatesAcrossTargets(t *testing.T) {
	reg := NewPeerRegistry("myc")
	our := mac(t, macE1)
	reg.SetNatHoleInstruction(our, mkInstr(macE2, NatHoleRole_DetectRoleSender))
	reg.SetNatHoleInstruction(our, mkInstr(macE3, NatHoleRole_DetectRoleSender))
	reg.SetNatHoleInstruction(our, mkInstr("11:22:33:44:55:66", NatHoleRole_DetectRoleSender))

	seen := map[string]int{}
	for i := 0; i < 9; i++ {
		instr, key := reg.NextNatHoleInstruction()
		if instr == nil {
			t.Fatalf("round %d: no instruction selected, want one of the 3 pending", i)
		}
		seen[key]++
	}

	for _, want := range []string{macE2, macE3, "11:22:33:44:55:66"} {
		if seen[want] == 0 {
			t.Errorf("target %s was never selected across 9 rounds; got %v", want, seen)
		}
	}
	// 3 targets over 9 rounds with perfect rotation = exactly 3 each.
	for k, n := range seen {
		if n != 3 {
			t.Errorf("target %s selected %d times, want 3 (uneven rotation)", k, n)
		}
	}
}

// A peer that is already direct must not keep occupying the rotation: its
// entry is only waiting on the round that promoted it, and re-punching a
// working tunnel is pure overhead that would delay the peers still needing it.
func TestNextNatHoleInstruction_SkipsAlreadyFullDuplex(t *testing.T) {
	reg := NewPeerRegistry("myc")
	our := mac(t, macE1)
	reg.Peers[macE2] = &Peer{Infos: PeerInfo{MacAddr: mac(t, macE2)}, IsFullDuplex: true}
	reg.SetNatHoleInstruction(our, mkInstr(macE2, NatHoleRole_DetectRoleSender))
	reg.SetNatHoleInstruction(our, mkInstr(macE3, NatHoleRole_DetectRoleSender))

	instr, key := reg.NextNatHoleInstruction()
	if instr == nil {
		t.Fatal("no instruction selected")
	}
	if key == macE2 {
		t.Errorf("selected %s, which is already FullDuplex", key)
	}
	if key != macE3 {
		t.Errorf("selected %s, want %s", key, macE3)
	}
	if _, still := reg.NatHoleInstructionsForTest()[macE2]; still {
		t.Error("the FullDuplex peer's entry should have been dropped")
	}
}

// Re-arm is looked up by peer MAC. While the map held one entry keyed by our
// own MAC, this lookup missed every time -- which is why a tunnel that dropped
// after a successful punch never came back.
func TestReArmNatHoleInstruction_FindsPendingEntryByPeerMAC(t *testing.T) {
	reg := NewPeerRegistry("myc")
	our := mac(t, macE1)
	reg.SetNatHoleInstruction(our, mkInstr(macE2, NatHoleRole_DetectRoleSender))
	reg.SetNatHoleInstruction(our, mkInstr(macE3, NatHoleRole_DetectRoleSender))
	reg.NatHoleRetryCountsForTest()[macE2] = 4
	reg.NatHoleRetryCountsForTest()[macE3] = 4

	reg.ReArmNatHoleInstruction(mac(t, macE2))

	if got := reg.NatHoleRetryCountsForTest()[macE2]; got != 0 {
		t.Errorf("E2 retry count = %d, want 0: the re-arm did not find its own entry", got)
	}
	if got := reg.NatHoleRetryCountsForTest()[macE3]; got != 4 {
		t.Errorf("E3 retry count = %d, want 4: a re-arm for E2 must not touch E3", got)
	}
}

// A re-arm must still work while other peers have pending instructions. The old
// code early-returned whenever the map was non-empty and then reset whichever
// key the map yielded first, so the re-arm landed on the wrong peer.
func TestReArmNatHoleInstruction_WorksWithOtherPeersPending(t *testing.T) {
	reg := NewPeerRegistry("myc")
	our := mac(t, macE1)
	// E2's round already succeeded, so its entry is gone; E3 is still pending.
	reg.LastNatHoleInstrs()[macE2] = mkInstr(macE2, NatHoleRole_DetectRoleSender)
	reg.SetNatHoleInstruction(our, mkInstr(macE3, NatHoleRole_DetectRoleSender))

	reg.ReArmNatHoleInstruction(mac(t, macE2))

	if _, ok := reg.NatHoleInstructionsForTest()[macE2]; !ok {
		t.Errorf("E2 was not re-armed; keys are %v", keysOf(reg.NatHoleInstructionsForTest()))
	}
	if _, ok := reg.NatHoleInstructionsForTest()[macE3]; !ok {
		t.Error("E3's pending instruction was lost by the re-arm")
	}
}

// Clearing a succeeded target must not take the others down with it. The old
// "if my key vanished, clear everything" fallback was harmless with one entry
// and destructive with three.
func TestExecuteNatHolePunch_SuccessDoesNotClearOtherTargets(t *testing.T) {
	reg := NewPeerRegistry("myc")
	our := mac(t, macE1)
	reg.SetNatHoleInstruction(our, mkInstr(macE2, NatHoleRole_DetectRoleSender))
	reg.SetNatHoleInstruction(our, mkInstr(macE3, NatHoleRole_DetectRoleSender))

	// Mark the target that will be punched as already direct, so the round
	// completes instantly and takes the success path.
	reg.Peers[macE2] = &Peer{Infos: PeerInfo{MacAddr: mac(t, macE2)}, IsFullDuplex: true}
	reg.Peers[macE3] = &Peer{Infos: PeerInfo{MacAddr: mac(t, macE3)}}

	reg.ExecuteNatHolePunch(nil)

	if _, ok := reg.NatHoleInstructionsForTest()[macE2]; ok {
		t.Error("the succeeded target's entry should be cleared")
	}
	if _, ok := reg.NatHoleInstructionsForTest()[macE3]; !ok {
		t.Errorf("E3's entry was cleared by E2's success; keys are %v", keysOf(reg.NatHoleInstructionsForTest()))
	}
}

func keysOf(m map[string]*NatHoleInstruction) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
