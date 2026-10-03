package edge_test

import (
	. "n2n-go/pkg/edge"
	"net"
	"testing"
)

// A host with a live Ethernet link and a WiFi associated to nothing carries
// addresses on both. Reporting the WiFi's is not a harmless extra entry: the
// peer spends a punch budget on an address that can never answer.
//
// Synthetic interfaces, not the host's own, because the bug only shows up
// where a down interface exists and CI hosts rarely have one.
func TestAssistedAddressesSkipDownInterfaces(t *testing.T) {
	live := net.Interface{
		Index: 1, Name: "eth0", MTU: 1500,
		Flags:        net.FlagUp | net.FlagBroadcast | net.FlagMulticast,
		HardwareAddr: net.HardwareAddr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee},
	}
	// The WiFi: left holding a stale address after the association dropped.
	wifi := net.Interface{
		Index:        2,
		Name:         "wlan0",
		MTU:          1500,
		HardwareAddr: net.HardwareAddr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xff},
	}

	// Neither interface has addresses in this synthetic set, so the only
	// thing the helper could possibly return comes from the down one.
	got := CollectAssistedIPs([]net.Interface{live, wifi}, MaxAssistedAddrs,
		map[string]bool{}, nil)
	if len(got) != 0 {
		t.Errorf("addresses collected from a down interface: %v", got)
	}
}

// The tap is up, so it must still be recognised and excluded by MAC even after
// the FlagUp filter -- otherwise the exclusion silently stops working on a
// host whose only other interface is down.
func TestAssistedStillExcludesTapMACOnOtherwiseQuietHost(t *testing.T) {
	up := net.Interface{
		Index: 3, Name: "n2n_tap0", MTU: 1450,
		Flags:        net.FlagUp | net.FlagBroadcast | net.FlagMulticast,
		HardwareAddr: net.HardwareAddr{0x52, 0xeb, 0x72, 0xed, 0x64, 0x1f},
	}
	down := net.Interface{
		Index: 2, Name: "wlan0", MTU: 1500,
		HardwareAddr: net.HardwareAddr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xff},
	}
	got := CollectAssistedIPs([]net.Interface{up, down}, MaxAssistedAddrs,
		map[string]bool{"100.64.0.4": true}, nil)
	if len(got) != 0 {
		t.Errorf("tap or down-interface address leaked into %v", got)
	}
}
