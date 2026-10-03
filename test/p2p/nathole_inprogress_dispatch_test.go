package p2p_test

import (
	. "n2n-go/pkg/p2p"
	"net"
	"strings"
	"testing"
	"time"
)

// A dispatched punch must be reported to the relay as InProgress before the
// round finishes.
//
// Before this, ExecuteNatHolePunch reported exactly two things: InProgress
// from handlePunchDatagram, which fires only when the PEER's packet lands, and
// Failed once all five attempts burn out. Nothing in between. So for the whole
// punch phase -- up to five sends plus a waitForPunchSuccess -- the relay held
// no record that a round was even running, and a peer that never answered was
// indistinguishable from one that had not started.
//
// The relay's state machine needs the difference: state 1 is inert (no
// failCount, no backoff re-arm), which is what lets it treat a slow round as
// slow rather than escalating it.
//
// This drives the real function and watches the result map from another
// goroutine, so a regression that defers the report to the end of the round
// fails here rather than in a field log.

func TestPunchDispatchIsReportedBeforeTheRoundEnds(t *testing.T) {
	reg := NewPeerRegistry("myc")

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Skipf("cannot bind loopback UDP: %v", err)
	}
	defer conn.Close()

	// Loopback port 9 is the discard port: sends succeed, nothing answers.
	// That is the case the fix exists for -- a round that starts and is never
	// observed by the peer.
	const rung = uint32(4)
	targetMAC := []byte{0x0a, 0xe3, 0x8f, 0xd6, 0x51, 0xa2}
	targetStr := "0a:e3:8f:d6:51:a2"

	reg.Me = &Peer{Infos: PeerInfo{
		MacAddr:   []byte{0x52, 0xeb, 0x72, 0xed, 0x64, 0x1f},
		PubSocket: "127.0.0.1:52840",
		VirtualIp: "100.64.0.3",
	}}
	reg.Peers[targetStr] = &Peer{
		Infos: PeerInfo{
			MacAddr:   targetMAC,
			PubSocket: "127.0.0.1:9",
			VirtualIp: "100.64.0.1",
			NatType:   "EasyNAT",
		},
		P2PEndpoint: "127.0.0.1:9",
		P2PStatus:   P2PUnavailable,
	}

	instr := &NatHoleInstruction{
		TargetMac:         targetMAC,
		Role:              NatHoleRole_DetectRoleReceiver,
		SenderPubSocket:   "127.0.0.1:9",
		SenderP2PEndpoint: "127.0.0.1:9",
		Mode:              NatHoleModeEasyNATPair,
		BehaviorIndex:     rung,
		Ttl:               0,
		PortsRangeFrom:    0,
		PortsRangeTo:      0,
	}
	reg.SetNatHoleInstructionsForTest(map[string]*NatHoleInstruction{targetStr: instr})
	// Start a fresh round rather than the exhausted one, so the punch loop
	// actually sends and reportPunchStarted is reached.
	reg.SetNatHoleRetryCountsForTest(map[string]int{targetStr: 0})

	done := make(chan struct{})
	go func() {
		defer close(done)
		reg.ExecuteNatHolePunch(conn)
	}()

	// Watch for the InProgress report while the round is still running. The
	// Watch for the dispatch report while the round is still running. The
	// budget is generous: the point is only to observe the report before the
	// function returns, and the round's own wait dominates the runtime.
	//
	// Matched on the dispatch detail, not on state 1 alone. The round also
	// writes an InProgress of its own at the end of each attempt, with the
	// detail "retrying" (p2p.go:2471) -- and that site fires *after* the
	// round's long wait, which is exactly the blind window this change
	// closes. Asserting on bare state 1 would let the pre-existing site
	// satisfy the test and the regression would go unnoticed.
	const dispatchPrefix = "punch dispatched to"
	deadline := time.After(30 * time.Second)
	for {
		select {
		case <-done:
			t.Fatalf("round finished without ever reporting a dispatch mid-round "+
				"(final detail %q). The dispatch report must land when the first "+
				"punch is sent, not when the round ends",
				func() string {
					if g := reg.NatHolePunchResultsForTest()[targetStr]; g != nil {
						return g.Detail
					}
					return "<none>"
				}())
		case <-deadline:
			t.Fatal("ExecuteNatHolePunch did not return within 30s; the silent peer " +
				"should not be able to hold it open this long")
		default:
		}

		if got := reg.NatHolePunchResultsForTest()[targetStr]; got != nil &&
			got.State == NatHolePunchState_PunchStateInProgress &&
			strings.HasPrefix(got.Detail, dispatchPrefix) {
			// The rung must be attributed on this report too: the relay
			// credits the strategy that actually ran.
			if got.BehaviorIndex != rung {
				t.Fatalf("dispatch report carried rung %d, want %d", got.BehaviorIndex, rung)
			}
			// Attempts reflects the candidate that went out, so the relay can
			// tell a first-candidate dispatch from a later one.
			if got.Attempts == 0 {
				t.Error("dispatch report carried attempts=0; the candidate index " +
					"that opened the mapping is lost")
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}
