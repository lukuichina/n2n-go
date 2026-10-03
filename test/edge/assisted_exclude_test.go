package edge_test

import (
	. "n2n-go/pkg/edge"
	"n2n-go/pkg/p2p"
	"net"
	"testing"
)

// The exclusion must remove exactly the named interface's addresses and leave
// every other address alone. loopback ("lo") is used as the stand-in because
// it always exists, but it is also independently filtered -- so this asserts
// the "nothing else changed" property against a real interface, not just the
// happy path.
func TestListLocalIPsForNatHoleExcluding_OnlyDropsNamedInterface(t *testing.T) {
	baseline := ListLocalIPsForNatHole(MaxAssistedAddrs)
	if len(baseline) == 0 {
		t.Skip("no usable IPv4 interfaces in this environment")
	}

	// Excluding an interface that cannot exist must be a no-op.
	same := ListLocalIPsForNatHoleExcluding(MaxAssistedAddrs, "definitely-not-an-iface-xyz", "", "")
	if len(same) != len(baseline) {
		t.Fatalf("absent interface changed the list: %d -> %d", len(baseline), len(same))
	}

	// Pick a real non-loopback interface with an address and exclude it.
	var victimName string
	var victimIP string
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("net.Interfaces: %v", err)
	}
	for i := range ifaces {
		ifc := &ifaces[i]
		if ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, aerr := ifc.Addrs()
		if aerr != nil {
			continue
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP != nil && n.IP.To4() != nil &&
				!n.IP.IsLoopback() && !n.IP.IsLinkLocalUnicast() {
				victimName, victimIP = ifc.Name, n.IP.String()
				break
			}
		}
		if victimName != "" {
			break
		}
	}
	if victimName == "" {
		t.Skip("no non-loopback IPv4 interface available to exclude")
	}

	got := ListLocalIPsForNatHoleExcluding(MaxAssistedAddrs, victimName, "", "")
	for _, ip := range got {
		if ip == victimIP {
			t.Fatalf("address %s of excluded interface %q still reported", victimIP, victimName)
		}
	}
	// Nothing may be lost beyond the victim.
	if len(got) != len(baseline)-1 {
		t.Fatalf("expected exactly one address dropped: %d -> %d (victim %s/%s)",
			len(baseline), len(got), victimName, victimIP)
	}
}

// A blank name must preserve the FRP-parity behaviour exactly.
func TestListLocalIPsForNatHoleExcluding_BlankNameIsFRPParity(t *testing.T) {
	a := ListLocalIPsForNatHole(MaxAssistedAddrs)
	b := ListLocalIPsForNatHoleExcluding(MaxAssistedAddrs, "", "", "")
	if len(a) != len(b) {
		t.Fatalf("blank name changed behaviour: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("blank name changed order at %d: %s vs %s", i, a[i], b[i])
		}
	}
}

// loopback and link-local must never be reported, exclusion or not: the peer
// cannot reach them and each is a guaranteed wasted sendto.
func TestListLocalIPsForNatHole_NeverReportsUnreachable(t *testing.T) {
	for _, ip := range ListLocalIPsForNatHole(MaxAssistedAddrs) {
		p := net.ParseIP(ip)
		if p == nil {
			t.Fatalf("unparseable entry %q", ip)
		}
		if p.IsLoopback() {
			t.Fatalf("loopback reported: %s", ip)
		}
		if p.IsLinkLocalUnicast() {
			t.Fatalf("link-local reported: %s", ip)
		}
		if p.To4() == nil {
			t.Fatalf("non-IPv4 reported: %s", ip)
		}
	}
}

// The field failure, in the reporting path: a name that cannot resolve must
// not be the only thing standing between the tap address and the wire. The
// virtual IP is passed alone and must be enough.
func TestListLocalIPsForNatHoleExcluding_TapIPAloneIsSufficient(t *testing.T) {
	all := ListLocalIPsForNatHole(MaxAssistedAddrs)
	if len(all) == 0 {
		t.Skip("no usable IPv4 interfaces in this environment")
	}
	// Find an address that would otherwise be reported, and name it as the
	// tap IP with a deliberately unresolvable interface name.
	victim := all[0]
	got := ListLocalIPsForNatHoleExcluding(MaxAssistedAddrs, "n2n_tap0", victim, "")
	for _, ip := range got {
		if ip == victim {
			t.Fatalf("tap IP %s still reported when named directly", victim)
		}
	}
	if len(got) != len(all)-1 {
		t.Fatalf("expected exactly one dropped: %d -> %d", len(all), len(got))
	}
}

// The field failure, reproduced exactly. On Windows the TAP adapter is an
// ordinary adapter with a system name, so InterfaceByName("n2n_tap0") always
// fails; the adapter also persists across runs with its previous overlay
// address still configured, so a stale 100.64.0.4 sat in the list on every
// start. At that moment the registration response has not arrived, so the
// virtual IP is unknown too.
//
// The tap MAC is the only identifier available, and it must be enough.
func TestExcludeByMACAloneWithStaleTapAddress(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("no interfaces: %v", err)
	}
	// Find a real interface to impersonate the tap: one with a MAC and an IPv4.
	var mac string
	var ip string
	for i := range ifaces {
		ifc := &ifaces[i]
		if len(ifc.HardwareAddr) == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP != nil && n.IP.To4() != nil &&
				!n.IP.IsLoopback() && !n.IP.IsLinkLocalUnicast() {
				mac, ip = ifc.HardwareAddr.String(), n.IP.String()
				break
			}
		}
		if mac != "" {
			break
		}
	}
	if mac == "" {
		t.Skip("no IPv4 interface with a MAC to use as a stand-in tap")
	}

	all := ListLocalIPsForNatHole(MaxAssistedAddrs)
	// Sanity: the victim really is reportable, so the drop below is meaningful.
	found := false
	for _, a := range all {
		if a == ip {
			found = true
		}
	}
	if !found {
		t.Skipf("chosen address %s not in the baseline list", ip)
	}

	// Name that cannot resolve, no virtual IP -- exactly the Windows case.
	got := ListLocalIPsForNatHoleExcluding(MaxAssistedAddrs, "n2n_tap0", "", mac)
	for _, a := range got {
		if a == ip {
			t.Fatalf("tap address %s still reported: name lookup and virtual IP both unavailable", ip)
		}
	}
	if len(got) != len(all)-1 {
		t.Fatalf("expected exactly the tap address dropped: %d -> %d", len(all), len(got))
	}
}

// --- 2026-09-30: the NetBird address was advertised in the first place ------
//
// The peer logged `senderAssisted=[100.101.102.21:51478,10.137.189.93:51478]`
// and then punched the overlay address instead of the public one. The address
// never reached the scoring path to be rejected: ListLocalIPsForNatHoleExcluding
// filtered our own tap and nothing else, so any other overlay tunnel on the
// host went straight into the assisted list. Filtering has to happen here, at
// the entry point, not only in p2p.AffinityScore further down.
func TestAssistedAddressesExcludeCGNATOverlay(t *testing.T) {
	// Driven through the predicate, not CollectAssistedIPs: the collector reads
	// the real interface list, which on a host with no overlay holds nothing this
	// rejects, so a test through it passes with or without the rule. That is how
	// the NetBird address shipped in the first place -- CI has no NetBird.
	for _, s := range []string{"100.101.102.21", "100.76.83.147", "100.64.0.4"} {
		if AssistedAddrAcceptable(net.ParseIP(s)) {
			t.Errorf("overlay address %s must not be advertised as assisted", s)
		}
	}
	// Everything a normal host advertises has to keep working: this filter runs
	// on every address on every interface, so a mistake here would silently drop
	// the real LAN and turn same-LAN peers back into relay traffic.
	for _, s := range []string{"192.168.10.6", "10.137.189.93", "111.101.5.1", "2.58.196.38"} {
		if !AssistedAddrAcceptable(net.ParseIP(s)) {
			t.Errorf("address %s must still be advertised as assisted", s)
		}
	}
}

func TestIsCGNATOverlayAddrCoversNetBirdRange(t *testing.T) {
	cases := map[string]bool{
		"100.101.102.21": true, // NetBird on E1
		"100.76.83.147":  true, // NetBird on the third host
		"100.64.0.4":     true, // an n2n tap that slipped past the MAC exclusion
		"111.101.5.1":    false,
		"2.58.196.38":    false,
		"192.168.10.6":   false,
	}
	for s, want := range cases {
		if got := p2p.IsCGNATOverlayAddr(net.ParseIP(s)); got != want {
			t.Errorf("IsCGNATOverlayAddr(%s) = %v, want %v", s, got, want)
		}
	}
	if p2p.IsCGNATOverlayAddr(nil) {
		t.Error("nil must not be treated as an overlay address")
	}
}
