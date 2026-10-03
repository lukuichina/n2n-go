package p2p_test

import (
	. "n2n-go/pkg/p2p"
	"net"
	"net/netip"
	"testing"
)

// mustPrefixes is a small helper for readable table setup.
func mustPrefixes(t *testing.T, ss ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			t.Fatalf("bad prefix %q: %v", s, err)
		}
		out = append(out, p)
	}
	return out
}

// The observed edge3/edge4 failure, verbatim from the field logs. Both hosts
// are templates sharing an interface set; they differ only in the last octet
// of the real LAN. edge3 reported all seven of these to edge4, and
// 192.168.10.7 -- the one address on the shared broadcast domain -- landed at
// index 5, behind a tap address, a NetBird address, a docker bridge and two
// other virtual interfaces. It must now come first.
func TestSortAssistedSameSubnetFirst_RealEdge3Edge4(t *testing.T) {
	local := mustPrefixes(t,
		"192.168.10.0/24", // the real LAN (.13 on the punching host)
		"172.20.0.0/16",   // docker bridge
		"100.64.0.0/10",   // n2n tap
		"192.168.192.0/24",
	)
	reported := []string{
		"100.76.83.147:59708",
		"100.101.102.1:59708",
		"172.20.160.1:59708",
		"100.64.0.4:59708",
		"192.168.1.11:59708",
		"192.168.10.7:59708",
		"192.168.192.2:59708",
	}
	got := SortAssistedByLocalAffinity(reported, local)

	if got[0] != "192.168.10.7:59708" {
		t.Fatalf("same-subnet address is not first, got %v", got)
	}
	// Nothing may be lost: sorting reorders, it never drops a claim.
	if len(got) != len(reported) {
		t.Fatalf("candidate count changed: %d -> %d", len(reported), len(got))
	}
	seen := map[string]int{}
	for i, v := range got {
		seen[v] = i
	}
	for _, orig := range reported {
		if _, ok := seen[orig]; !ok {
			t.Fatalf("candidate %s was dropped", orig)
		}
	}
}

// A wide virtual interface must not out-rank the genuine LAN: longest-prefix
// match is what makes this correct, not "any match counts".
func TestLongestPrefixWins(t *testing.T) {
	local := mustPrefixes(t, "10.0.0.0/8", "192.168.10.0/24")
	got := SortAssistedByLocalAffinity(
		[]string{"10.9.9.9:1000", "192.168.10.7:59708"}, local)
	if got[0] != "192.168.10.7:59708" {
		t.Fatalf("a /8 match outranked a /24 match: %v", got)
	}
}

// Stability matters: a multi-homed peer ranks its own addresses, and equal
// affinity must leave that ranking alone.
func TestEqualAffinityKeepsReportedOrder(t *testing.T) {
	local := mustPrefixes(t, "192.168.0.0/16")
	rep := []string{"192.168.5.1:1000", "192.168.6.1:1000", "192.168.7.1:1000"}
	got := SortAssistedByLocalAffinity(rep, local)
	if !SameOrder(rep, got) {
		t.Fatalf("equal-affinity entries were reordered: %v", got)
	}
}

// No shared subnet must be a no-op -- the peer is genuinely remote and its
// reported order is all we have.
func TestNoSharedSubnetIsNoOp(t *testing.T) {
	local := mustPrefixes(t, "192.168.10.0/24")
	rep := []string{"8.8.8.8:1000", "1.1.1.1:2000"}
	if got := SortAssistedByLocalAffinity(rep, local); !SameOrder(rep, got) {
		t.Fatalf("remote peer was reordered: %v", got)
	}
}

// A malformed or unresolvable entry must keep its place rather than vanish:
// dropping a peer's claim is how a working candidate goes missing.
func TestUnparseableEntryIsPreserved(t *testing.T) {
	local := mustPrefixes(t, "192.168.10.0/24")
	rep := []string{"not-an-addr", "192.168.10.7:59708", "999.1.1.1:5"}
	got := SortAssistedByLocalAffinity(rep, local)
	if len(got) != 3 {
		t.Fatalf("entries lost: %v", got)
	}
	if got[0] != "192.168.10.7:59708" {
		t.Fatalf("valid same-subnet entry should lead: %v", got)
	}
	for _, orig := range rep {
		found := false
		for _, g := range got {
			if g == orig {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s dropped", orig)
		}
	}
}

// An entry with no port must still rank, not be treated as malformed.
func TestHostWithoutPortRanks(t *testing.T) {
	local := mustPrefixes(t, "192.168.10.0/24")
	got := SortAssistedByLocalAffinity([]string{"8.8.8.8:1", "192.168.10.7"}, local)
	if got[0] != "192.168.10.7" {
		t.Fatalf("portless same-subnet entry did not lead: %v", got)
	}
}

// The host's own prefixes must be discovered from the real interfaces and
// must never include loopback or link-local.
func TestLocalPrefixesExcludeLoopbackAndLinkLocal(t *testing.T) {
	for _, p := range LocalNATPunchPrefixes("", "", "") {
		if !p.Addr().Is4() {
			t.Fatalf("non-IPv4 prefix reported: %v", p)
		}
		if p.Addr().IsLoopback() || p.Addr().IsLinkLocalUnicast() {
			t.Fatalf("useless prefix reported: %v", p)
		}
	}
}

func mustAddr(s string) netip.Addr {
	a, _ := netip.ParseAddr(s)
	return a
}

// --- 2026-09-30: NetBird on both ends hijacked the punch candidate list -----
//
// E1 (2.58.196.38) and the third Windows host both ran NetBird. NetBird
// assigns from 100.64.0.0/10, so each end owned a "same-subnet" address on
// the shared overlay (100.101.102.21 and 100.101.102.1). The affinity sort
// scored that /10 above the genuine public candidate and punched the overlay
// address instead: the punch reported success, but the bytes travelled over
// NetBird, and P2PRaddr flapped between 100.101.102.x and the public address
// as packets arrived on either path.
//
// A shared overlay is not a shared LAN. CollectLocalPrefixes must not hand out
// a same-subnet bonus for any address in the CGNAT pool, so the public
// candidate is the one that wins.
func TestCollectLocalPrefixesExcludesCGNATOverlay(t *testing.T) {
	// Every local prefix this host actually has must be outside the CGNAT
	// pool: that is the invariant the exclusion in CollectLocalPrefixes
	// maintains, and it is what keeps AffinityScore from rating an overlay
	// address as a same-subnet match.
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("cannot enumerate interfaces: %v", err)
	}
	prefixes := CollectLocalPrefixes(ifaces, "", nil, netip.Prefix{}, false)
	for _, p := range prefixes {
		if IsCGNATOverlay(p.Addr()) {
			t.Errorf("CGNAT overlay prefix %v leaked into local prefixes: %v", p, prefixes)
		}
	}
}

// The overlay address must not score as a same-subnet match, so the real LAN
// leads the sort even though the overlay was reported first.
//
// Note what this does and does not claim: the peer's public address is not
// part of `assisted` at all (it arrives via pubSocket/P2PRaddr and is
// appended separately), so this asserts the ordering among the peer's own
// reported addresses, not that a public address is pulled forward from
// somewhere it never was.
func TestSharedNetBirdOverlayDoesNotOutrankRealLAN(t *testing.T) {
	// A LAN on this host, plus the NetBird overlay it must no longer count.
	local := mustPrefixes(t, "192.168.10.0/24", "10.137.189.0/24", "100.64.0.0/10")
	reported := []string{
		"100.101.102.1:55028", // peer's NetBird overlay address -- must not lead
		"100.64.0.4:55028",    // peer's n2n tap address
		"192.168.1.11:55028",  // peer's docker bridge
		"192.168.10.7:55028",  // peer's real LAN address -- must lead
	}
	got := SortAssistedByLocalAffinity(reported, local)
	if got[0] != "192.168.10.7:55028" {
		t.Fatalf("real LAN must lead, got %v", got)
	}
}

func TestIsCGNATOverlay(t *testing.T) {
	cases := map[string]bool{
		"100.101.102.1":  true,  // NetBird / n2n overlay
		"100.64.0.4":     true,  // edge of the CGNAT pool
		"100.127.255.1":  true,  // edge of the CGNAT pool
		"111.101.5.1":    false, // public
		"57.129.106.133": false, // public
		"2.58.196.38":    false, // public
		"192.168.10.6":   false, // RFC1918 LAN
		"10.137.189.93":  false, // RFC1918 LAN
		"100.63.255.255": false, // just below the pool
		"100.128.0.0":    false, // just above the pool
	}
	for s, want := range cases {
		if got := IsCGNATOverlay(netip.MustParseAddr(s)); got != want {
			t.Errorf("IsCGNATOverlay(%s) = %v, want %v", s, got, want)
		}
	}
}

// AddrInLocalPrefix is what actually promotes a candidate ahead of the public
// address (the "lanFirst" reordering in p2p.go), so it is the predicate that
// has to refuse a CGNAT overlay address even when a prefix list contains one.
func TestAddrInLocalPrefixRejectsCGNATOverlay(t *testing.T) {
	prefixes := mustPrefixes(t, "192.168.10.0/24", "100.101.102.0/24")
	if AddrInLocalPrefix(net.ParseIP("100.101.102.1"), prefixes) {
		t.Error("NetBird overlay address must not count as same-subnet")
	}
	if AddrInLocalPrefix(net.ParseIP("100.64.0.4"), prefixes) {
		t.Error("n2n tap address must not count as same-subnet")
	}
	if !AddrInLocalPrefix(net.ParseIP("192.168.10.7"), prefixes) {
		t.Error("real LAN address must still count as same-subnet")
	}
	if AddrInLocalPrefix(net.ParseIP("111.101.5.1"), prefixes) {
		t.Error("a public address is not on any of our subnets and must not match")
	}
	if AddrInLocalPrefix(net.ParseIP("192.168.10.7"), nil) {
		t.Error("an empty prefix list must match nothing")
	}
}
