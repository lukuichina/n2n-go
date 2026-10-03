package edge_test

import (
	. "n2n-go/pkg/edge"
	"testing"
	"time"
)

// The refresh must be frequent enough to matter.
//
// The relay stores each peer's pubSocket and hands it to the other side in
// every NatHoleInstruction. A re-bound P2P socket therefore goes stale the
// moment the port changes, and the stale value survives until something
// re-advertises it -- which, before this interval existed, was never.
//
// Observed 2026-10-01: the relay dispatched 57.129.106.133:59271 while the
// live STUN mapping was :36224, with 3829 P2PStateInfo sends and only 2 STUN
// discoveries in the whole run.
func TestNatHoleAddrRefreshInterval(t *testing.T) {
	if NatHoleAddrRefreshInterval <= 0 {
		t.Fatal("refresh interval must be positive")
	}

	// The relay's own retry cadence is a punch round of a few seconds plus a
	// backoff window. Refreshing much slower than that lets several rounds be
	// dispatched at an address that no longer exists before the new one can
	// possibly be known.
	const maxAcceptable = 30 * time.Second
	if NatHoleAddrRefreshInterval > maxAcceptable {
		t.Errorf("refresh interval %v exceeds %v; a re-bound socket stays "+
			"stale long enough for the relay to burn several rounds on a dead "+
			"address", NatHoleAddrRefreshInterval, maxAcceptable)
	}
}

// The refresh has to outlive a single punch round but stay well inside any
// backoff window, otherwise a pair in backoff would keep re-deciding against
// the same stale address.
func TestNatHoleAddrRefreshIntervalBounds(t *testing.T) {
	const minUseful = 2 * time.Second
	if NatHoleAddrRefreshInterval < minUseful {
		t.Errorf("refresh interval %v is below %v; that is closer to the "+
			"2s P2PStateInfo tick than to a mapping change and adds STUN "+
			"traffic without adding information",
			NatHoleAddrRefreshInterval, minUseful)
	}
}
