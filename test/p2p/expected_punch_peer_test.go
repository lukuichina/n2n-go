package p2p_test

import (
	. "n2n-go/pkg/p2p"
)

import "testing"

// The attribution window is what lets a punch whose source address was
// rewritten in transit (a router SNATing it, a carrier NAT hairpin) be
// recorded against the right peer instead of being dropped as "unknown".
// It names exactly one MAC, and the edge rebuilds NatHoleInstruction with
// SenderMac overwritten to *our own* MAC -- so reading SenderMac here named
// ourselves, GetPeer(ours) always missed, and every rewritten punch fell
// through to the answer-once fallback. The peer then never learned its
// raddr, so UDPAddrWithStrategy had nothing verified to send to and the
// direct path could never be promoted, however good the punch was.
func TestExpectedPunchPeerMACNamesTheOtherPeer(t *testing.T) {
	self := []byte{0x9e, 0x6e, 0x2d, 0x8c, 0xf5, 0xdb}
	peer := []byte{0x52, 0xeb, 0x72, 0xed, 0x64, 0x1f}

	cases := []struct {
		name    string
		sender  []byte
		target  []byte
		want    string
		comment string
	}{
		{
			name:   "receiver instruction, sender field clobbered to us",
			sender: self,
			target: peer,
			want:   "52:eb:72:ed:64:1f",
		},
		{
			name:   "sender instruction, target is the receiver",
			sender: peer,
			target: peer,
			want:   "52:eb:72:ed:64:1f",
		},
		{
			name:   "target missing, fall back to a foreign sender",
			sender: peer,
			target: nil,
			want:   "52:eb:72:ed:64:1f",
		},
		{
			name:   "both name us -- no peer to attribute to",
			sender: self,
			target: self,
			want:   "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := &PeerRegistry{}
			reg.Me = &Peer{Infos: PeerInfo{MacAddr: self}}
			reg.SetNatHoleInstructionsForTest(map[string]*NatHoleInstruction{
				string(self): {
					SenderMac: tc.sender,
					TargetMac: tc.target,
				},
			})

			if got := reg.ExpectedPunchPeerMAC(); got != tc.want {
				t.Errorf("ExpectedPunchPeerMAC() = %q, want %q", got, tc.want)
			}
		})
	}
}
