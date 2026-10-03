package edge_test

import (
	. "n2n-go/pkg/edge"
	"strings"
	"testing"
)

// The regression the user spotted, 2026-10-03. On log3, peer 9e:6e advertised
// 111.101.5.1:60735 (STUN) and 10.0.10.40:60735 (its real LAN address), yet
// its frames consistently arrived from 172.22.2.44:60735 -- the router's WAN
// address after one SNAT hop, port preserved.
//
// Neither advertised address is where the peer's traffic actually comes
// from, so punching either one leaves our NAT tracking a flow the peer's
// return traffic cannot match. The receiver therefore spun through 7
// instructions and 62 seconds before the direct path came up.
//
// The observed raddr is the one candidate with direct evidence behind it: a
// packet from that address already reached us. It must win.
func TestResolvePunchTargetPrefersObservedSNATAddress(t *testing.T) {
	const observed = "172.22.2.44:60735"
	got, note := ResolvePunchTarget(observed, "111.101.5.1:60735", "10.0.10.40:60735", "", "9e:6e:2d:8c:f5:db", true)
	if got != observed {
		t.Fatalf("chose %q, want the observed source %q (note: %s)", got, observed, note)
	}
	if !strings.Contains(note, "observed-source") {
		t.Fatalf("note %q should mark the choice as observed-source", note)
	}
}

// The observed raddr must not become a back door for punching ourselves.
// A peer that reflects our own punch back at us would otherwise get its
// reflection adopted as the top-ranked target.
func TestResolvePunchTargetRejectsObservedSelfAddress(t *testing.T) {
	addrs := localIPv4AddrsForTest()
	if len(addrs) == 0 {
		t.Skip("host has no non-loopback IPv4 address")
	}
	own := addrs[0]
	// Registry pubSocket is empty, so the observed self address would be the
	// only candidate if it were not rejected.
	got, note := ResolvePunchTarget(own, "", "", "", "aa:bc:3a:74:37:b1", true)
	if got != "" {
		t.Fatalf("chose %q, want empty -- our own address is not a target (note: %s)", got, note)
	}
}

// With no observation yet, resolution must still fall back sanely: a public
// STUN mapping beats an off-link private address, exactly as before.
func TestResolvePunchTargetFallsBackWhenNoObservationYet(t *testing.T) {
	got, _ := ResolvePunchTarget("", "111.101.5.1:60735", "10.0.10.40:60735", "", "9e:6e:2d:8c:f5:db", true)
	if got != "111.101.5.1:60735" {
		t.Fatalf("chose %q, want the public STUN mapping", got)
	}
}

// An on-link peer that we have never heard from is still the better target
// than its public mapping -- no NAT, no hairpin. This guards the ranking
// order from being flattened by the raddr change.
func TestResolvePunchTargetStillPrefersOnLinkWhenUnobserved(t *testing.T) {
	addrs := localSubnetPeerForTest(t)
	if addrs == "" {
		t.Skip("no usable on-link peer address to construct")
	}
	got, note := ResolvePunchTarget("", "111.101.5.1:56436", addrs, "", "52:eb:72:ed:64:1f", true)
	if got != addrs {
		t.Fatalf("chose %q, want the on-link %s (note: %s)", got, addrs, note)
	}
}
