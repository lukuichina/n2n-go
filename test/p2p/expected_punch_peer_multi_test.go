package p2p_test

import (
	"testing"

	. "n2n-go/pkg/p2p"
)

// Regression, observed 2026-10-03 on log3 (ea:2f:de:90:a5:72).
//
// ExpectedPunchPeerMAC used to end its scan with `return ""` inside the loop,
// so it examined exactly one pending instruction and gave up if that one named
// us. Which one it examined was whatever Go's randomised map iteration
// produced, and with several peers mid-punch at once that is a coin flip.
//
// The consequence was silent and expensive. When the scan came up empty the
// attribution window stayed closed, so a punch from the correct peer took the
// "Punch packet from unknown peer" branch -- which answers with an ACK but
// deliberately does *not* record the raddr. log3 therefore kept 52:eb:72:ed:64:1f
// indexed only under its advertised 192.168.10.13:33377, while the peer was
// actually arriving from 192.168.10.2:33377 -- a router in the path had
// rewritten the source, and no side had advertised that address. Each round
// reported "peer punched back" yet "data path not yet verified", burned its
// five attempts, and asked the relay to re-dispatch. Ten punches were answered
// that way before one round happened to draw a usable instruction; the tunnel
// closed 42s after it started, by luck.
func TestExpectedPunchPeerMACScansPastSelfDirectedInstructions(t *testing.T) {
	self := []byte{0x9e, 0x6e, 0x2d, 0x8c, 0xf5, 0xdb}
	peer := []byte{0x52, 0xeb, 0x72, 0xed, 0x64, 0x1f}
	other := []byte{0x0a, 0xe3, 0x8f, 0xd6, 0x51, 0xa2}

	reg := &PeerRegistry{}
	reg.Me = &Peer{Infos: PeerInfo{MacAddr: self}}
	reg.SetNatHoleInstructionsForTest(map[string]*NatHoleInstruction{
		// Key "a..." sorts first, so this self-directed instruction is the
		// one a stable scan meets first. Under the old random scan this
		// was hit only sometimes, which is what made the bug look flaky.
		"a-self-directed": {
			SenderMac: self,
			TargetMac: self,
		},
		"b-names-a-peer": {
			SenderMac: peer,
			TargetMac: peer,
		},
	})

	if got := reg.ExpectedPunchPeerMAC(); got != "52:eb:72:ed:64:1f" {
		t.Fatalf("ExpectedPunchPeerMAC() = %q, want %q -- a self-directed instruction "+
			"must not close the attribution window for the peers behind it",
			got, "52:eb:72:ed:64:1f")
	}

	// Same registry, minus the usable instruction: now "" is correct, and
	// only because there is genuinely nothing to attribute to. This is the
	// distinction the old code collapsed -- it returned "" for this case and
	// for the one above alike.
	reg.SetNatHoleInstructionsForTest(map[string]*NatHoleInstruction{
		"a-self-directed": {
			SenderMac: self,
			TargetMac: self,
		},
	})
	if got := reg.ExpectedPunchPeerMAC(); got != "" {
		t.Errorf("ExpectedPunchPeerMAC() = %q, want \"\" when every instruction names us", got)
	}

	// A malformed instruction (nil MACs) must be skipped rather than
	// aborting the scan, same as a self-directed one.
	reg.SetNatHoleInstructionsForTest(map[string]*NatHoleInstruction{
		"a-empty": {},
		"b-peer":  {TargetMac: other},
	})
	if got := reg.ExpectedPunchPeerMAC(); got != "0a:e3:8f:d6:51:a2" {
		t.Errorf("ExpectedPunchPeerMAC() = %q, want %q -- an empty instruction must be skipped",
			got, "0a:e3:8f:d6:51:a2")
	}
}

// The answer must not change between calls on the same registry. Go randomises
// map iteration, so a scan that consulted every entry in whatever order the
// runtime produced would still pass the case above only intermittently -- and
// an attribution window that flickers open and shut between two reads in the
// same punch round reproduces the original symptom even once the early
// `return ""` is gone.
func TestExpectedPunchPeerMACIsStableAcrossCalls(t *testing.T) {
	self := []byte{0x9e, 0x6e, 0x2d, 0x8c, 0xf5, 0xdb}

	reg := &PeerRegistry{}
	reg.Me = &Peer{Infos: PeerInfo{MacAddr: self}}
	instrs := map[string]*NatHoleInstruction{}
	for i := 0; i < 8; i++ {
		// Half name us, half name a real peer.
		mac := []byte{0x52, 0xeb, 0x72, 0xed, 0x64, byte(i + 1)}
		if i%2 == 0 {
			mac = self
		}
		instrs[string(rune('a'+i))] = &NatHoleInstruction{SenderMac: mac, TargetMac: mac}
	}
	reg.SetNatHoleInstructionsForTest(instrs)

	first := reg.ExpectedPunchPeerMAC()
	if first == "" {
		t.Fatal("ExpectedPunchPeerMAC() = \"\" with peers present -- attribution window would be closed every round")
	}
	for i := 0; i < 200; i++ {
		if got := reg.ExpectedPunchPeerMAC(); got != first {
			t.Fatalf("ExpectedPunchPeerMAC() returned %q then %q on an unchanged registry; "+
				"the answer must be deterministic", first, got)
		}
	}
}
