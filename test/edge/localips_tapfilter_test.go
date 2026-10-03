package edge_test

import (
	. "n2n-go/pkg/edge"
	"net"
	"testing"
)

// log4's stale address: a TAP-Windows adapter left over from an earlier n2n
// run with a different subnet, carrying 10.0.10.40, on a host whose real
// uplink was 172.22.2.44. Both are RFC1918, so they land in the same
// reachability tier and enumeration order alone would decide the winner of
// ListLocalIPs(1) -- the single value broadcast to peers as the P2P endpoint.
// FlagUp does not save us: the TAP-Windows driver reports an opened adapter as
// up whether or not any n2n instance is using it.
//
// The name is the weak signal here. It only works on an English-locale host:
// the marker "tap-windows" appears in "TAP-Windows Adapter V9 #3", but on the
// Chinese-locale hosts the same adapter is called "本地连接 3", which matches
// nothing, and its leftover subnet 10.0.10.0/24 is ordinary RFC1918 rather
// than overlay space. Driver identity is what covers that, which is why
// ifaceCIDR carries a tapDriver flag and IsTapInterface takes the index set.
func TestIsTapInterfaceRecognisesWindowsTapNames(t *testing.T) {
	for _, name := range []string{
		"TAP-Windows Adapter V9 #3",
		"tap-windows adapter v9",
		"TAP-Windows Adapter V9",
	} {
		ifc := net.Interface{Name: name, Flags: net.FlagUp | net.FlagRunning}
		if !IsTapInterface(&ifc, nil) {
			t.Errorf("IsTapInterface(%q) = false, want true", name)
		}
	}
}

// The localized name is what both lab hosts actually report, and it matches no
// marker -- so with only name and address space to go on, a leftover tap wins
// the advertised endpoint. This is the case that reached a peer's edge as
// P2PEndpoint=10.0.10.40:60735.
func TestSortLocalIPsLocalizedStaleTapCannotWinEndpointSlot(t *testing.T) {
	got := sortLocalIPsFromCIDRs([]ifaceCIDR{
		{"本地连接 3", true, net.IPv4(10, 0, 10, 40), 4, true},
		{"以太网", true, net.IPv4(172, 22, 2, 44), 20, false},
	}, 1)
	if len(got) != 1 || got[0] != "172.22.2.44" {
		t.Fatalf("advertised endpoint would be %v, want the real uplink 172.22.2.44", got)
	}
}

// The same situation on an English-locale host, where the name does match.
func TestSortLocalIPsStaleTapCannotWinEndpointSlot(t *testing.T) {
	got := sortLocalIPsFromCIDRs([]ifaceCIDR{
		{"TAP-Windows Adapter V9 #3", true, net.IPv4(10, 0, 10, 40), 4, true},
		{"Ethernet", true, net.IPv4(172, 22, 2, 44), 20, false},
	}, 1)
	if len(got) != 1 || got[0] != "172.22.2.44" {
		t.Fatalf("advertised endpoint would be %v, want the real uplink 172.22.2.44", got)
	}
}

// A name that matches no marker and an address outside overlay space is
// indistinguishable from a real NIC without the driver's say-so, so a host
// without driver identity is left with the bad candidate. This documents the
// residual gap rather than asserting a fix: on non-Windows there is no
// TAP-Windows registry to consult, and there the live tap is excluded by
// index instead.
func TestSortLocalIPsUnidentifiedAdapterIsNotSilentlyDropped(t *testing.T) {
	got := sortLocalIPsFromCIDRs([]ifaceCIDR{
		{"本地连接 3", true, net.IPv4(10, 0, 10, 40), 4, false},
		{"以太网", true, net.IPv4(172, 22, 2, 44), 20, false},
	}, 10)
	if len(got) != 2 {
		t.Fatalf("an adapter with no identifying signal must not be dropped on a guess: %v", got)
	}
}

// The exclusion must not touch genuine NICs. A host whose Ethernet is
// "以太网 3" and whose WiFi is "WLAN" has to keep both eligible.
func TestSortLocalIPsKeepsRealNICs(t *testing.T) {
	got := sortLocalIPsFromCIDRs([]ifaceCIDR{
		{"以太网 3", true, net.IPv4(192, 168, 10, 7), 3, false},
		{"WLAN", true, net.IPv4(192, 168, 1, 11), 12, false},
	}, 10)
	if len(got) != 2 {
		t.Fatalf("real NICs were dropped: %v", got)
	}
}

// The live tap carries the n2n overlay address (100.64.0.5 on log4). It is
// tier 2 so it cannot win the single slot, but it must still be excluded: it
// is our own virtual interface, and a peer cannot reach it.
func TestSortLocalIPsExcludesLiveOverlayTap(t *testing.T) {
	got := sortLocalIPsFromCIDRs([]ifaceCIDR{
		{"本地连接", true, net.IPv4(100, 64, 0, 5), 7, true},
		{"Ethernet", true, net.IPv4(172, 22, 2, 44), 20, false},
	}, 10)
	for _, ip := range got {
		if ip == "100.64.0.5" {
			t.Fatalf("the n2n overlay address must not be offered: %v", got)
		}
	}
	if len(got) != 1 || got[0] != "172.22.2.44" {
		t.Fatalf("expected only the uplink, got %v", got)
	}
}

// NetBird's wt0 shares the 100.64.0.0/10 overlay space and is also a tunnel,
// so it must not be offered as a punchable endpoint either.
func TestSortLocalIPsExcludesTunnelInterface(t *testing.T) {
	got := sortLocalIPsFromCIDRs([]ifaceCIDR{
		{"wt0", true, net.IPv4(100, 101, 102, 2), 25, false},
		{"Ethernet", true, net.IPv4(172, 22, 2, 44), 20, false},
	}, 1)
	if len(got) != 1 || got[0] != "172.22.2.44" {
		t.Fatalf("tunnel interface won the endpoint slot: %v", got)
	}
}

// A Hyper-V or WSL virtual switch holds a private address and reports itself
// up, so it is offered to peers like any other address. log3's default switch
// is 172.20.80.1/20.
func TestSortLocalIPsExcludesHyperVSwitch(t *testing.T) {
	got := sortLocalIPsFromCIDRs([]ifaceCIDR{
		{"vEthernet (Default Switch)", true, net.IPv4(172, 20, 80, 1), 50, false},
		{"以太网 3", true, net.IPv4(192, 168, 10, 7), 3, false},
	}, 10)
	for _, ip := range got {
		if ip == "172.20.80.1" {
			t.Fatalf("the Hyper-V switch address must not be offered: %v", got)
		}
	}
	if len(got) != 1 || got[0] != "192.168.10.7" {
		t.Fatalf("expected only the uplink, got %v", got)
	}
}
