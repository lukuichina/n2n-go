package p2p_test

import (
	. "n2n-go/pkg/p2p"
	"testing"
)

// A punch outcome is an event, not a level: the relay only needs to hear it
// once, because it keeps the verdict in its own natHolePunchState.
//
// The entry used to stay in natHolePunchResults forever, so every 2s publish
// replayed the same verdict. That is not cosmetic -- the relay feeds each
// report into its rung analyzer, so a single success that kept getting
// re-delivered pushed the rung score to its ceiling and buried the signal the
// ladder reads. On 2026-10-03 one pair logged 1332 + 619 + 74 + 45 identical
// "succeeded" records, and the "score 10" in that trace is the score, spent.
//
// These tests pin the one-shot delivery and the status field it used to hide
// behind.

func newPunchResultRegistry(t *testing.T) (*PeerRegistry, string, []byte) {
	t.Helper()
	reg := NewPeerRegistry("myc")

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
	return reg, targetStr, targetMAC
}

func rowFor(infos *PeerP2PInfos, mac string) *PeerInfo {
	for _, row := range infos.GetTo() {
		if row.GetPunchResultPeerMac() == mac || macAddrString(row.GetMacAddr()) == mac {
			return row
		}
	}
	return nil
}

func macAddrString(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 0, len(b)*3-1)
	for i, c := range b {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, hex[c>>4], hex[c&0x0f])
	}
	return string(out)
}

// The verdict reaches the relay exactly once. Everything the relay derives
// from it -- whether to keep dispatching, how the rung scores -- is computed
// from that single delivery, so replaying it can only corrupt the score.
func TestPunchResultIsDeliveredOnceThenConsumed(t *testing.T) {
	reg, targetStr, _ := newPunchResultRegistry(t)

	reg.RecordNatHolePunchResult(targetStr, NatHolePunchState_PunchStateSucceeded, 3,
		"verified by real data frame from 172.22.1.17:64165", 1, 0)

	first := rowFor(reg.GetPeerP2PInfos(), targetStr)
	if first == nil {
		t.Fatal("target peer missing from first publish")
	}
	if first.GetPunchResult() == nil {
		t.Fatal("first publish dropped the punch result; relay would never learn the verdict")
	}
	if got := first.GetPunchResult().GetState(); got != NatHolePunchState_PunchStateSucceeded {
		t.Fatalf("state = %v, want Succeeded", got)
	}
	if got := first.GetPunchResult().GetDetail(); got != "verified by real data frame from 172.22.1.17:64165" {
		t.Fatalf("detail = %q, want the reported detail", got)
	}

	second := rowFor(reg.GetPeerP2PInfos(), targetStr)
	if second == nil {
		t.Fatal("target peer missing from second publish")
	}
	if second.GetPunchResult() != nil {
		t.Fatalf("second publish replayed the verdict: %v", second.GetPunchResult().GetDetail())
	}
}

// The consumed entry is gone from the map itself, not merely skipped, so it
// cannot be re-delivered by a later code path.
func TestConsumedPunchResultLeavesTheMap(t *testing.T) {
	reg, targetStr, _ := newPunchResultRegistry(t)

	reg.RecordNatHolePunchResult(targetStr, NatHolePunchState_PunchStateFailed, 5, "exhausted", 2, 0)
	if reg.NatHolePunchResultsForTest()[targetStr] == nil {
		t.Fatal("result missing from map before publish")
	}

	reg.GetPeerP2PInfos()

	reg.LockForTest()
	remaining := reg.NatHolePunchResultsSnapshotLocked()[targetStr]
	reg.UnlockForTest()
	if remaining != nil {
		t.Fatalf("consumed result still resident: %+v", remaining)
	}
}

// A round that starts after the previous verdict was consumed must still be
// reported. Deleting by key has to drop the entry that was actually reported,
// never a fresher verdict recorded in between.
func TestFreshResultRecordedAfterConsumptionIsStillDelivered(t *testing.T) {
	reg, targetStr, _ := newPunchResultRegistry(t)

	reg.RecordNatHolePunchResult(targetStr, NatHolePunchState_PunchStateFailed, 5, "round one", 2, 0)
	reg.GetPeerP2PInfos() // consumes round one

	reg.RecordNatHolePunchResult(targetStr, NatHolePunchState_PunchStateInProgress, 1,
		"punch dispatched to 172.22.1.17:64165", 1, 0)

	row := rowFor(reg.GetPeerP2PInfos(), targetStr)
	if row == nil || row.GetPunchResult() == nil {
		t.Fatal("round two was swallowed; the relay would think no round is running")
	}
	if got := row.GetPunchResult().GetDetail(); got != "punch dispatched to 172.22.1.17:64165" {
		t.Fatalf("detail = %q, want round two's detail", got)
	}
}

// P2PStatus used to be set inside the `res != nil` branch, so a peer reported
// no status at all unless it had just been punched -- precisely the peer whose
// status the relay most needs. The relay reads it back off to[].p2pStatus (see
// shouldRetireSuccess in the Worker) and treats a missing value as
// "unobservable", which makes a live FullDuplex tunnel look like it needs
// re-punching.
func TestP2PStatusIsReportedEvenWithNoPunchResultPending(t *testing.T) {
	reg, targetStr, _ := newPunchResultRegistry(t)

	// No punch recorded at all -- the map is empty.
	if got := reg.NatHolePunchResultsForTest()[targetStr]; got != nil {
		t.Fatalf("precondition: expected no punch result, got %+v", got)
	}

	row := rowFor(reg.GetPeerP2PInfos(), targetStr)
	if row == nil {
		t.Fatal("target peer missing from publish")
	}
	if row.GetPunchResult() != nil {
		t.Fatal("precondition: unexpected punch result")
	}
	if got := row.GetP2PStatus(); got != uint32(P2PUnavailable) {
		t.Fatalf("P2PStatus = %d, want %d (Unavailable) with no punch result pending",
			got, P2PUnavailable)
	}
}

// A peer holding a live tunnel must keep reporting that status across
// publishes, including the many that carry no punch result -- that is the
// signal the relay uses to retire a stale success instead of re-punching a
// healthy pair.
func TestP2PStatusSurvivesRepeatedPublishes(t *testing.T) {
	reg, targetStr, _ := newPunchResultRegistry(t)

	reg.LockForTest()
	reg.Peers[targetStr].P2PStatus = P2PFullDuplex
	reg.UnlockForTest()

	for i := 0; i < 5; i++ {
		row := rowFor(reg.GetPeerP2PInfos(), targetStr)
		if row == nil {
			t.Fatalf("publish %d: target peer missing", i)
		}
		if row.GetPunchResult() != nil {
			t.Fatalf("publish %d: unexpected punch result", i)
		}
		if got := row.GetP2PStatus(); got != uint32(P2PFullDuplex) {
			t.Fatalf("publish %d: P2PStatus = %d, want FullDuplex (%d)",
				i, got, P2PFullDuplex)
		}
	}
}

// Status and outcome travel together in the same publish, so the relay can
// tell whether the success it is about to record still describes a live tunnel.
func TestStatusAndOutcomeArriveTogether(t *testing.T) {
	reg, targetStr, _ := newPunchResultRegistry(t)

	reg.LockForTest()
	reg.Peers[targetStr].P2PStatus = P2PFullDuplex
	reg.UnlockForTest()

	reg.RecordNatHolePunchResult(targetStr, NatHolePunchState_PunchStateSucceeded, 3,
		"verified by real data frame from 172.22.1.17:64165", 1, 0)

	row := rowFor(reg.GetPeerP2PInfos(), targetStr)
	if row == nil || row.GetPunchResult() == nil {
		t.Fatal("publish dropped the outcome")
	}
	if got := row.GetP2PStatus(); got != uint32(P2PFullDuplex) {
		t.Fatalf("P2PStatus = %d, want FullDuplex (%d) alongside the outcome", got, P2PFullDuplex)
	}
	if row.GetPunchResultPeerMac() != targetStr {
		t.Fatalf("PunchResultPeerMac = %q, want %q so the relay knows whose round this was",
			row.GetPunchResultPeerMac(), targetStr)
	}
}
