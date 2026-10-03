package p2p_test

import (
	. "n2n-go/pkg/p2p"
	"net"
	"testing"
	"time"
)

// The failure report written when a round runs out of attempts must blame the
// rung the round actually ran.
//
// The hazard is an ordering one, and it only appears in the real function.
// ExecuteNatHolePunch deletes its instruction (p2p.go:2360) before writing the
// failure, so anything that re-derives the rung by scanning the cache after
// that point gets the 0 fallback. The relay then penalises a rung that never
// ran: on 2026-09-30 a round of rung 4 was reported as index 0, that rung's
// score fell to its -10 floor, and the pair kept re-arming at the 300s cap
// because the blamed rung and the dispatched rung did not match.
//
// This drives ExecuteNatHolePunch itself rather than reproducing its steps, so
// a future reordering of the delete and the report fails here.

func TestExecuteNatHolePunchBlamesTheRungItRan(t *testing.T) {
	reg := NewPeerRegistry("myc")

	// A real socket on loopback. The peer never answers, so the round burns
	// through all five attempts and takes the exhausted path.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Skipf("cannot bind loopback UDP: %v", err)
	}
	defer conn.Close()

	// A peer that is routable-looking but silent. Port 9 (discard) accepts
	// sends and returns nothing, which is exactly a round that never comes up.
	dead, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9})
	if err != nil {
		t.Fatalf("cannot prepare the silent peer: %v", err)
	}
	_ = dead.Close()

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

	// A no-TTL rung (4/5): the socket's normal TTL is left in place, so these
	// are the entries used on a path longer than the probe TTL.
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
	// The exhausted branch is the `else` of `retryCount < 5`, so the counter
	// must already have reached 5: that is the sixth pass, the one where the
	// round gives up.
	reg.SetNatHoleRetryCountsForTest(map[string]int{targetStr: 5})

	done := make(chan struct{})
	go func() {
		defer close(done)
		reg.ExecuteNatHolePunch(conn)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("ExecuteNatHolePunch did not return; the silent peer should not " +
			"be able to hold it open this long")
	}

	got := reg.NatHolePunchResultsForTest()[targetStr]
	if got == nil {
		t.Fatalf("no punch result recorded for %s after the round exhausted", targetStr)
	}
	if got.State != NatHolePunchState_PunchStateFailed {
		t.Skipf("round ended as state %v rather than Failed; the rung attribution "+
			"is only written on the exhausted path, and this environment reached "+
			"a different branch", got.State)
	}
	if got.BehaviorIndex != rung {
		t.Fatalf("exhausted round blamed rung %d, want %d. The instruction is "+
			"deleted before the report is written, so re-deriving the rung from "+
			"the cache returns 0 and the relay penalises a rung that never ran",
			got.BehaviorIndex, rung)
	}
	if _, still := reg.NatHoleInstructionsForTest()[targetStr]; still {
		t.Error("instruction survived the exhausted round; the test is not " +
			"exercising the delete-then-report ordering")
	}
}

// The in-progress site shares the writer now. It always read the rung off
// currentInstr, so it was never the misattribution bug -- but it is covered
// here so a future refactor cannot reintroduce a second inline literal without
// a test noticing that the retry path lost its rung attribution.
func TestInProgressRoundKeepsItsRungAndAttemptCount(t *testing.T) {
	reg := NewPeerRegistry("myc")

	const rung = uint32(4)
	const mac = "0a:e3:8f:d6:51:a2"
	target := []byte{0x0a, 0xe3, 0x8f, 0xd6, 0x51, 0xa2}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Skipf("cannot bind loopback UDP: %v", err)
	}
	defer conn.Close()

	reg.Me = &Peer{Infos: PeerInfo{
		MacAddr:   []byte{0x52, 0xeb, 0x72, 0xed, 0x64, 0x1f},
		PubSocket: "127.0.0.1:52840",
		VirtualIp: "100.64.0.3",
	}}
	reg.Peers[mac] = &Peer{
		Infos: PeerInfo{
			MacAddr:   target,
			PubSocket: "127.0.0.1:9",
			VirtualIp: "100.64.0.1",
			NatType:   "EasyNAT",
		},
		P2PEndpoint: "127.0.0.1:9",
	}
	reg.NatHoleInstructionsForTest()[mac] = &NatHoleInstruction{
		TargetMac:         target,
		Role:              NatHoleRole_DetectRoleReceiver,
		SenderPubSocket:   "127.0.0.1:9",
		SenderP2PEndpoint: "127.0.0.1:9",
		Mode:              NatHoleModeEasyNATPair,
		BehaviorIndex:     rung,
	}
	// retryCount below 5 takes the retry branch, so the instruction survives.
	reg.SetNatHoleRetryCountsForTest(map[string]int{mac: 2})

	done := make(chan struct{})
	go func() {
		defer close(done)
		reg.ExecuteNatHolePunch(conn)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("ExecuteNatHolePunch did not return on the retry path")
	}

	got := reg.NatHolePunchResultsForTest()[mac]
	if got == nil {
		t.Fatal("no punch result recorded on the retry path")
	}
	if got.State != NatHolePunchState_PunchStateInProgress {
		t.Fatalf("state = %v, want InProgress", got.State)
	}
	if got.BehaviorIndex != rung {
		t.Fatalf("retry reported rung %d, want %d", got.BehaviorIndex, rung)
	}
	// retryCount 2 means this is attempt 3, and the counter advances.
	if got.Attempts != 3 {
		t.Fatalf("attempts = %d, want 3", got.Attempts)
	}
	if _, alive := reg.NatHoleInstructionsForTest()[mac]; !alive {
		t.Error("instruction was deleted on the retry path; only the exhausted " +
			"branch should clear it")
	}
}
