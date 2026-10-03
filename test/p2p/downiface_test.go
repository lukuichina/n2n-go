package p2p_test

import (
	. "n2n-go/pkg/p2p"
	"net"
	"net/netip"
	"testing"
)

// The other half of the same bug, and the half that actually broke the field
// test.
//
// Filtering the down interface out of what we advertise is not enough. If its
// subnet still counts as "one of ours", then the peer's address on that same
// dead interface collects the same-subnet bonus and gets promoted to
// candidate 0 -- ahead of an address the peer could demonstrably reach.
//
// That is what the logs showed: a disconnected WiFi's address promoted to
// first, pushing a live, ping-verified address behind it.
func TestLocalPrefixesSkipDownInterfaces(t *testing.T) {
	live := net.Interface{
		Index: 1, Name: "eth0", MTU: 1500,
		Flags:        net.FlagUp | net.FlagBroadcast | net.FlagMulticast,
		HardwareAddr: net.HardwareAddr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee},
	}
	down := net.Interface{
		Index:        2,
		Name:         "wlan0",
		MTU:          1500,
		HardwareAddr: net.HardwareAddr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xff},
	}

	if got := CollectLocalPrefixes([]net.Interface{live, down}, "", nil, netip.Prefix{}, false); len(got) != 0 {
		t.Errorf("prefixes derived from a down interface: %v", got)
	}
}
