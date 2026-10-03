package edge_test

import (
	"net"
	"testing"
)

// The two lab Windows desktops, transcribed from Get-NetIPAddress
// -AddressFamily IPv4 (2026-10-03), joined to the up/down state from
// Get-NetAdapter / ipconfig. Interface names are ifAlias, which is what Go
// reports as net.Interface.Name on Windows.
//
// These tables exist because neither regression can be reproduced on a build
// host: it has no stale TAP, no ZeroTier, no Hyper-V switch. The deciding
// question is which address wins ListLocalIPs(1), and that single value becomes
// the advertised P2P endpoint -- so one wrong row here sends every peer to an
// address that belongs to somebody else's virtual network.
var labWindows = map[string]struct {
	// order is the enumeration order as the host itself prints it, since
	// equal-tier addresses are separated by enumeration order alone.
	order []ifaceCIDR
	// uplink is the address a peer on the same LAN can actually reach.
	uplink string
}{
	// log3 -- 以太网 3 = 192.168.10.7, TAP = 本地连接 = 100.64.0.4.
	"log3": {
		uplink: "192.168.10.7",
		order: []ifaceCIDR{
			{"ZeroTier One [17d709436cd229e9]", true, net.IPv4(192, 168, 192, 2), 30, false},
			{"wt0", true, net.IPv4(100, 101, 102, 1), 74, false},
			{"本地连接", true, net.IPv4(100, 64, 0, 4), 11, true}, // ifIndex 11, the n2n TAP
			{"Tailscale", true, net.IPv4(100, 76, 83, 147), 8, false},
			{"以太网 3", true, net.IPv4(192, 168, 10, 7), 3, false},
			{"vEthernet (Default Switch)", true, net.IPv4(172, 20, 80, 1), 50, false},
		},
	},
	// log4 -- 以太网 = 172.22.2.44 (DHCP), live TAP = 本地连接 = 100.64.0.5,
	// leftover TAP 本地连接 3 = 10.0.10.40, which has already been observed
	// reaching ListLocalIPs despite ipconfig reporting the media disconnected.
	"log4": {
		uplink: "172.22.2.44",
		order: []ifaceCIDR{
			{"Tailscale", true, net.IPv4(100, 89, 25, 155), 6, false},
			{"wt0", true, net.IPv4(100, 101, 102, 2), 25, false},
			{"本地连接", true, net.IPv4(100, 64, 0, 5), 7, true},   // ifIndex 7, the n2n TAP
			{"本地连接 3", true, net.IPv4(10, 0, 10, 40), 4, true}, // ifIndex 4, stale TAP
			{"以太网", true, net.IPv4(172, 22, 2, 44), 20, false},
		},
	},
}

// The advertised endpoint must be the real uplink on both lab hosts. Every
// other address on these tables belongs to a virtual network a peer cannot
// punch: the n2n overlay, NetBird, Tailscale, a leftover TAP, or -- on log3 --
// the Hyper-V default switch.
func TestListLocalIPsPicksRealUplinkOnLabWindows(t *testing.T) {
	for name, tc := range labWindows {
		t.Run(name, func(t *testing.T) {
			got := sortLocalIPsFromCIDRs(tc.order, 1)
			if len(got) != 1 || got[0] != tc.uplink {
				t.Errorf("advertised endpoint = %v, want the real uplink %s", got, tc.uplink)
			}
		})
	}
}

// The full candidate list is what peers receive as AssistedAddrs, so a virtual
// address surviving here means peers spend punch attempts on it.
func TestListLocalIPsOffersOnlyReachableAddressesOnLabWindows(t *testing.T) {
	for name, tc := range labWindows {
		t.Run(name, func(t *testing.T) {
			for _, ip := range sortLocalIPsFromCIDRs(tc.order, 10) {
				if ip != tc.uplink {
					t.Errorf("offered %s, which is not reachable by a peer", ip)
				}
			}
		})
	}
}
