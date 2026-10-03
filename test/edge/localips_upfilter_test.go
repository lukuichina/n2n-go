package edge_test

import (
	. "n2n-go/pkg/edge"
	"net"
	"strings"
	"testing"
)

// The regression, as it appeared on a Windows host. ipconfig listed the WiFi
// adapter as "media disconnected" with no IPv4 address shown, yet the address
// it used to hold kept coming back from the enumeration and was advertised to
// peers as 192.168.1.11:<the live P2P port>. Because the port was genuine,
// the entry looked plausible and survived review; the address was simply
// unreachable, so peers burned a punch budget on it.
//
// CollectAssistedIPs already filtered on FlagUp, which is why the assisted
// list was clean while ListLocalIPs -- feeding setup.go's P2PEndpointString(1)
// -- was not.
func TestListLocalIPsOmitsAddressesOfDownInterfaces(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("cannot enumerate interfaces: %v", err)
	}

	// Collect every address belonging to an interface that is not up.
	down := map[string]string{} // ip -> interface name
	for i := range ifaces {
		if ifaces[i].Flags&net.FlagUp != 0 {
			continue
		}
		addrs, aerr := ifaces[i].Addrs()
		if aerr != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP == nil {
				continue
			}
			if v4 := ipnet.IP.To4(); v4 != nil && !v4.IsLinkLocalUnicast() && !v4.IsLoopback() {
				down[v4.String()] = ifaces[i].Name
			}
		}
	}
	if len(down) == 0 {
		t.Skip("host has no down interface carrying an IPv4 address to test against")
	}

	for _, ip := range ListLocalIPs(50) {
		if name, bad := down[ip]; bad {
			t.Fatalf("ListLocalIPs reported %s, which belongs to down interface %q", ip, name)
		}
	}
}

// The filtering must not empty the list on a normal host: an up interface
// with a usable address has to survive.
func TestListLocalIPsStillReportsLiveInterfaces(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("cannot enumerate interfaces: %v", err)
	}
	live := 0
	for i := range ifaces {
		if ifaces[i].Flags&net.FlagUp == 0 {
			continue
		}
		addrs, aerr := ifaces[i].Addrs()
		if aerr != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP == nil {
				continue
			}
			v4 := ipnet.IP.To4()
			if v4 != nil && !v4.IsLinkLocalUnicast() && !v4.IsLoopback() {
				live++
			}
		}
	}
	if live == 0 {
		t.Skip("host has no usable address on an up interface")
	}
	if got := ListLocalIPs(50); len(got) == 0 {
		t.Fatal("ListLocalIPs returned nothing although the host has up interfaces with addresses")
	}
}

// setup.go's ListLocalIPs(1) is the single entry broadcast to peers as the
// P2P endpoint, so it must not be a tunnel-internal or down-link address.
// This pins the ordering property that makes that safe.
func TestListLocalIPsRanksRoutableFirst(t *testing.T) {
	got := ListLocalIPs(50)
	if len(got) < 2 {
		t.Skip("need at least two addresses to assert ordering")
	}
	first := net.ParseIP(got[0])
	if first == nil {
		t.Fatalf("unparsable first entry %q", got[0])
	}
	for _, later := range got[1:] {
		ip := net.ParseIP(later)
		if ip == nil {
			continue
		}
		v1, v2 := first.To4(), ip.To4()
		if v1 == nil || v2 == nil {
			continue
		}
		fTier, lTier := RoutabilityTier(v1), RoutabilityTier(v2)
		if fTier > lTier {
			t.Fatalf("ordering inverted: %s (tier %d) before %s (tier %d)",
				got[0], fTier, later, lTier)
		}
	}
}

// The overlay ranges that appear on both the Windows and Linux test hosts must
// never be handed out as a P2P endpoint -- a peer cannot punch them.
func TestListLocalIPsNeverReportsOverlayRanges(t *testing.T) {
	for _, ip := range ListLocalIPs(50) {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		if v4 := parsed.To4(); v4 != nil && v4.IsLoopback() {
			t.Fatalf("ListLocalIPs reported loopback %s", ip)
		}
		if strings.HasPrefix(ip, "169.254.") {
			t.Fatalf("ListLocalIPs reported link-local %s", ip)
		}
	}
}
