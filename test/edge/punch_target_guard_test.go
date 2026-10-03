package edge_test

import (
	. "n2n-go/pkg/edge"
	"net"
	"testing"
)

// RFC5737 documentation ranges and RFC1918 blocks that no test host is
// plausibly on-link for. Using documentation ranges keeps the test honest:
// 192.168.x is exactly the range the on-link guard is most likely to trip on.
func TestClassifyPunchTargetRejectsOffLinkPrivate(t *testing.T) {
	// 10.2.80.2 was the address E1 actually received for its peer E2 on
	// 2026-10-02 -- RFC1918, but on a different subnet, therefore unroutable.
	if got := ClassifyPunchTarget("10.2.80.2:46718"); got != PunchTargetUnusable {
		t.Fatalf("ClassifyPunchTarget(10.2.80.2:46718) = %d, want unusable", got)
	}
}

func TestClassifyPunchTargetRejectsSelf(t *testing.T) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("cannot enumerate interfaces: %v", err)
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP == nil {
			continue
		}
		v4 := ipnet.IP.To4()
		if v4 == nil || v4.IsLoopback() {
			continue
		}
		// E1's failure was punching 10.137.189.93:37151 -- its own address.
		if got := ClassifyPunchTarget(v4.String() + ":37151"); got != PunchTargetUnusable {
			t.Fatalf("ClassifyPunchTarget(%s) = %d, want unusable for our own address", v4, got)
		}
		return
	}
	t.Skip("host has no non-loopback IPv4 address")
}

func TestClassifyPunchTargetAcceptsPublic(t *testing.T) {
	if got := ClassifyPunchTarget("2.58.196.38:37151"); got != PunchTargetPublic {
		t.Fatalf("ClassifyPunchTarget(2.58.196.38:37151) = %d, want public", got)
	}
}

func TestClassifyPunchTargetAcceptsOnLinkPrivate(t *testing.T) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("cannot enumerate interfaces: %v", err)
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP == nil || ipnet.IP.To4() == nil {
			continue
		}
		if ipnet.IP.IsLoopback() {
			continue
		}
		ones, bits := ipnet.Mask.Size()
		if bits != 32 || ones >= 31 {
			continue
		}
		// Another usable host in our own subnet.
		peer := ipnet.IP.To4().Mask(ipnet.Mask)
		peer[len(peer)-1]++
		if peer.Equal(ipnet.IP.To4()) {
			continue
		}
		ep := peer.String() + ":43484"
		if got := ClassifyPunchTarget(ep); got != PunchTargetOnLink {
			t.Fatalf("ClassifyPunchTarget(%s) = %d, want on-link", ep, got)
		}
		return
	}
	t.Skip("no non-loopback IPv4 subnet suitable for an on-link peer")
}

// The regression, in the shape it actually appeared: the relay handed over the
// receiver's own private address while the registry held the correct public
// mapping. The public address must win, and it must be the one punched.
func TestResolvePunchTargetPrefersRegistryPublicOverRelayPrivate(t *testing.T) {
	// E1's registry knew E2 as 57.129.106.133:46718; the instruction carried
	// 10.137.189.93:37151, which is E1's own private address.
	relay := ""
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP != nil && ipnet.IP.To4() != nil {
				relay = ipnet.IP.String() + ":37151"
				break
			}
		}
	}
	if relay == "" {
		t.Skip("no IPv4 address to stand in for the relay-supplied value")
	}

	got, note := ResolvePunchTarget("", "57.129.106.133:46718", "", relay, "aa:bc:3a:74:37:b1", true)
	if got != "57.129.106.133:46718" {
		t.Fatalf("ResolvePunchTarget chose %q, want the registry public socket (note: %s)", got, note)
	}
}

// No usable candidate must be an empty address, never a private one -- an
// empty result stops the punch round; a wrong address burns the retry budget
// against a black hole and, worse, suppresses the receiver's return traffic.
func TestResolvePunchTargetYieldsNothingRatherThanPrivate(t *testing.T) {
	got, note := ResolvePunchTarget("", "", "", "10.2.80.2:46718", "aa:bc:3a:74:37:b1", true)
	if got != "" {
		t.Fatalf("ResolvePunchTarget chose %q, want empty (note: %s)", got, note)
	}
	if note == "" {
		t.Fatal("empty result should still explain itself in the log note")
	}
}
