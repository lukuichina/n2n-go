package p2p_test

import (
	. "n2n-go/pkg/p2p"
	"net/netip"
	"testing"
)

// A CGNAT-pool address is never a shared-LAN signal, so AffinityScore scores it
// 0 even when the caller hands us a prefix that contains it.
//
// This test used to assert the opposite -- that a 100.64.0.0/24 left in the
// local list ties with the real /24 and lets the sort promote the peer's tap
// address. It pinned the hazard on purpose, back when the only defence was the
// caller excluding the tap in LocalNATPunchPrefixes. That defence is no longer
// the only one: AffinityScore rejects the whole CGNAT pool directly, so the tie
// can no longer form. NetBird on both ends (2026-09-30) is what made that
// necessary -- a shared overlay subnet that no caller knew to exclude.
func TestCGNATAddressScoresZeroEvenWithMatchingLocalPrefix(t *testing.T) {
	local := mustPrefixes(t, "192.168.10.0/24", "100.64.0.0/24")
	if s := AffinityScore(mustAddr("100.64.0.4"), local); s != 0 {
		t.Fatalf("CGNAT address must score 0 regardless of local prefixes, got %d", s)
	}
	if s := AffinityScore(mustAddr("192.168.10.7"), local); s == 0 {
		t.Fatal("real LAN address must still score above zero")
	}
	// And the sort must now lead with the real LAN rather than the tap.
	reported := []string{
		"100.76.83.147:59708",
		"100.64.0.4:59708", // peer's n2n tap -- must not lead
		"192.168.10.7:59708",
	}
	if got := SortAssistedByLocalAffinity(reported, local); got[0] != "192.168.10.7:59708" {
		t.Fatalf("real LAN must lead, got %v", got)
	}
}

// With the tap's prefix removed, the peer's tap address must fall to the back
// and the real LAN must lead.
func TestOverlaySubnetRejectedWhenTapExcluded(t *testing.T) {
	// This is what LocalNATPunchPrefixes returns once selfTapName removed it.
	local := mustPrefixes(t, "192.168.10.0/24", "172.20.0.0/16", "100.101.0.0/16")
	reported := []string{
		"100.64.0.4:59708", // peer's n2n tap -- must not lead
		"100.101.102.1:59708",
		"172.20.160.1:59708",
		"192.168.10.7:59708", // the one that can actually connect
	}
	got := SortAssistedByLocalAffinity(reported, local)
	if got[0] != "192.168.10.7:59708" {
		t.Fatalf("real LAN did not lead: %v", got)
	}
	if AffinityScore(mustAddr("100.64.0.4"), local) != 0 {
		t.Fatalf("excluded overlay subnet still scores as shared: %v",
			AffinityScore(mustAddr("100.64.0.4"), local))
	}
}

// The real interface enumeration must exclude exactly the named interface and
// nothing else. A blank name must behave as "exclude nothing".
func TestLocalPrefixesExcludeNamedInterfaceOnly(t *testing.T) {
	all := LocalNATPunchPrefixes("", "", "")
	if len(all) == 0 {
		t.Skip("no usable IPv4 interfaces in this environment")
	}
	for _, p := range all {
		if p.Addr().IsLoopback() {
			t.Fatalf("loopback leaked into local prefixes: %v", p)
		}
	}
	// Excluding a name that cannot exist must change nothing.
	same := LocalNATPunchPrefixes("definitely-not-an-interface-xyz", "", "")
	if len(same) != len(all) {
		t.Fatalf("excluding an absent interface altered the set: %d -> %d", len(all), len(same))
	}
	// Excluding loopback by name must actually shrink the set.
	shrunk := LocalNATPunchPrefixes("lo", "", "")
	if len(shrunk) > len(all) {
		t.Fatalf("excluding a real interface grew the set: %d -> %d", len(all), len(shrunk))
	}
}

// The field failure: on Windows the tap is an ordinary adapter with a
// system-assigned name, so InterfaceByName("n2n_tap0") fails and a
// name-only exclusion silently excludes nothing. The virtual IP must be
// sufficient on its own -- no interface name supplied at all.
func TestOverlayExcludedByVirtualIPAlone(t *testing.T) {
	// A name that cannot exist, plus the address we were actually assigned.
	local := LocalNATPunchPrefixes("n2n_tap0-not-a-windows-adapter-name", "100.64.0.3", "")
	for _, p := range local {
		if p.Contains(netip.MustParseAddr("100.64.0.4")) {
			t.Fatalf("overlay prefix survived exclusion by virtual IP: %v", p)
		}
	}
	if AffinityScore(netip.MustParseAddr("100.64.0.4"), local) != 0 {
		t.Fatal("peer's tap address still scores as shared")
	}
}

// Blank virtual IP (not yet registered) must not silently drop real subnets.
func TestBlankVirtualIPExcludesNothing(t *testing.T) {
	withIP := LocalNATPunchPrefixes("", "100.64.0.3", "")
	blank := LocalNATPunchPrefixes("", "", "")
	if len(blank) < len(withIP) {
		t.Fatalf("blank virtual IP removed prefixes: %d -> %d", len(blank), len(withIP))
	}
}
