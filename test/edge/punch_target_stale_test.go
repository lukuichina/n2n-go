package edge_test

import (
	. "n2n-go/pkg/edge"
	"strings"
	"testing"
)

// Observed 2026-10-03 on the two lab Windows hosts against E1/E2. log3 and
// log4 share one public address (111.101.5.1) behind one carrier NAT and
// share their MAC across restarts, because the MAC is derived from the
// machine id. Each run allocates a new P2P socket port, so:
//
//   - 14:35 log3 (previous run) was 111.101.5.1:63654; this run is :53781
//   - 14:35 log4 (previous run) was 111.101.5.1:60735; this run is :49570
//
// E1 and E2 punched 63654 101 and 84 times and 60735 84 and 76 times, and
// never once punched a current port. Their registry held an raddr observed
// against the previous runs' sockets, and ResolvePunchTarget gave an observed
// raddr the highest rank unconditionally -- correctly, since an address a
// packet actually arrived from is the best evidence available -- but not when
// the peer has since announced a different public mapping, which proves the
// socket it describes is gone.
func TestStaleObservedRaddrLosesToFreshPubSocket(t *testing.T) {
	for _, tc := range []struct {
		name        string
		staleRaddr  string
		freshPub    string
		peerMAC     string
		wantAddr    string
		wantInNote  string
		wantDropped bool
	}{
		{
			name:        "log3 previous run's port",
			staleRaddr:  "111.101.5.1:63654",
			freshPub:    "111.101.5.1:53781",
			peerMAC:     "ea:2f:de:90:a5:72",
			wantAddr:    "111.101.5.1:53781",
			wantInNote:  "dropped stale observed raddr=111.101.5.1:63654",
			wantDropped: true,
		},
		{
			name:        "log4 previous run's port",
			staleRaddr:  "111.101.5.1:60735",
			freshPub:    "111.101.5.1:49570",
			peerMAC:     "9e:6e:2d:8c:f5:db",
			wantAddr:    "111.101.5.1:49570",
			wantInNote:  "dropped stale observed raddr=111.101.5.1:60735",
			wantDropped: true,
		},
		{
			// The on-link case is the reason the stale raddr is dropped
			// rather than demoted. log4's frames arrive from its LAN address
			// because the router SNATs them, so an old raddr is on-link and
			// would still outrank a public pubSocket at a lower rank.
			name:        "stale on-link raddr",
			staleRaddr:  "172.22.2.44:60735",
			freshPub:    "111.101.5.1:49570",
			peerMAC:     "9e:6e:2d:8c:f5:db",
			wantAddr:    "111.101.5.1:49570",
			wantInNote:  "dropped stale observed raddr=172.22.2.44:60735",
			wantDropped: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, note := ResolvePunchTarget(
				tc.staleRaddr, tc.freshPub, "192.168.10.7:53781", "192.168.10.7:53781",
				tc.peerMAC, false, false)
			if got != tc.wantAddr {
				t.Errorf("chose %s, want the current mapping %s (note: %s)", got, tc.wantAddr, note)
			}
			if tc.wantDropped && !strings.Contains(note, tc.wantInNote) {
				t.Errorf("note does not record the drop: %s", note)
			}
		})
	}
}

// With the raddr dropped, a private relay endpoint on its own is not a
// substitute: punching it leaves this host with no flow toward the peer, which
// is what makes the cloud provider's stateful ingress discard the reply.
func TestStaleRaddrFallsBackToPubSocketNotPrivateEndpoint(t *testing.T) {
	got, note := ResolvePunchTarget(
		"111.101.5.1:63654", "111.101.5.1:53781", "192.168.10.7:53781", "192.168.10.7:53781",
		"ea:2f:de:90:a5:72", false, false)
	if got != "111.101.5.1:53781" {
		t.Fatalf("chose %s, want the public mapping; note: %s", got, note)
	}
}

// A fresh raddr must keep winning. This is the whole reason it outranks
// everything: under SNAT the peer's frames arrive from its router's WAN
// address, which appears in neither pubSocket nor the assisted set. Dropping
// it on every round would put symmetric-NAT peers back on the advertised
// address, which is precisely the address their return traffic cannot match.
func TestFreshObservedRaddrStillWins(t *testing.T) {
	for _, tc := range []struct{ raddr, want string }{
		{"172.22.2.44:60735", "172.22.2.44:60735"}, // on-link, log4 behind SNAT
		{"111.101.5.1:53781", "111.101.5.1:53781"}, // observed from the peer itself
	} {
		got, note := ResolvePunchTarget(
			tc.raddr, "111.101.5.1:53781", "192.168.10.7:53781", "", "9e:6e:2d:8c:f5:db", true, false)
		if got != tc.want {
			t.Errorf("chose %s, want the observed %s (note: %s)", got, tc.want, note)
		}
		if strings.Contains(note, "dropped stale") {
			t.Errorf("a fresh raddr must not be dropped: %s", note)
		}
	}
}

// With nothing but a stale raddr, the round is skipped and the note says why.
// Punching a closed port would spend five retries and produce a timeout that
// reads like a network problem rather than a bookkeeping one.
func TestStaleRaddrAloneIsReportedNotPunched(t *testing.T) {
	got, note := ResolvePunchTarget(
		"111.101.5.1:63654", "", "", "", "ea:2f:de:90:a5:72", false, false)
	if got != "" {
		t.Fatalf("chose %s, want no target", got)
	}
	if !strings.Contains(note, "stale") {
		t.Errorf("note must name the staleness as the reason: %s", note)
	}
}
