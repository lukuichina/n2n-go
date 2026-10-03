package edge_test

import (
	. "n2n-go/pkg/edge"
	"net"
	"testing"
)

// The assisted list is the entry point, not a fallback. Its addresses arrive
// inside senderAssistedEndpoints and the peer tries them AHEAD of the peer's
// public address (pkg/p2p/p2p.go, "Sender: using OBSERVED raddr ... ahead of
// predicted candidates" and the same-subnet promotion above it), so a virtual
// address in here is tried first rather than last.
//
// Recorded 2026-10-03 from the relay's own view of log3:
//
//	ea:2f:de:90:a5:72 NAT feature: pubSocket=111.101.5.1:53781
//	  assistedSockets=["192.168.10.7:53781","192.168.192.2:53781","172.20.80.1:53781"]
//
// 192.168.192.2 is ZeroTier and 172.20.80.1 is the Hyper-V default switch.
// Both are up, both are RFC1918, and neither was excluded: the old filter knew
// our own tap by IP/MAC/name and rejected the CGNAT address space, and neither
// rule sees a third-party adapter carrying an ordinary private address. The
// fix is interface identity, which is what ListLocalIPs(1) already used.
//
// Driven from the transcribed lab tables rather than the live host: a build
// machine has no ZeroTier and no Hyper-V switch, so a test against its own
// interface table returns the uplink and passes either way.
func TestAssistedAddressesExcludeVirtualInterfacesOnLabWindows(t *testing.T) {
	for name, tc := range labWindows {
		t.Run(name, func(t *testing.T) {
			excluded := make(map[uint32]bool)
			for _, c := range tc.order {
				if c.tapDriver {
					excluded[uint32(c.index)] = true
				}
			}
			byIndex := make(map[int][]net.Addr, len(tc.order))
			for _, c := range tc.order {
				if c.ip == nil {
					continue
				}
				byIndex[c.index] = []net.Addr{&net.IPNet{IP: c.ip, Mask: net.CIDRMask(prefixLen(c.ip), 32)}}
			}
			restore := swapInterfaceAddrs(t, byIndex)
			defer restore()

			ifaces := make([]net.Interface, 0, len(tc.order))
			for _, c := range tc.order {
				ifc := net.Interface{Index: c.index, Name: c.name}
				if c.up {
					ifc.Flags = net.FlagUp
				}
				ifaces = append(ifaces, ifc)
			}

			got := CollectAssistedIPs(ifaces, MaxAssistedAddrs, map[string]bool{}, excluded)
			if len(got) != 1 || got[0] != tc.uplink {
				t.Errorf("assisted addresses = %v, want only the real uplink %s", got, tc.uplink)
			}
		})
	}
}

// Without the driver index set -- as on a host where the TAP driver identity
// cannot be read -- the name markers still have to carry as much as they can,
// which is not all of it.
//
// log3's virtual adapters name themselves: "ZeroTier One [17d709436cd229e9]"
// and "vEthernet (Default Switch)" match tunInterfaceMarkers in any locale
// observed here, so both are excluded with no registry access at all.
//
// log4's leftover TAP does not. It is called "本地连接 3" and holds
// 10.0.10.40/24 -- no marker in the name, and an address that is ordinary
// RFC1918, so neither the name rules nor the CGNAT address-space rule in
// IsTapInterface can see it. That is the whole reason tapAdapterIfIndexes()
// exists and why it is a required argument on Windows rather than an
// optimisation: without it this host advertises a dead TAP to its peers.
//
// Pinned here so that asymmetry stays visible. If this test ever starts
// passing for log4, the fallback got better and the comment in IsTapInterface
// needs updating; if it starts failing for log3, a marker was lost.
func TestAssistedAddressesWithoutDriverIdentityCoverWhatNamesCan(t *testing.T) {
	want := map[string][]string{
		// ZeroTier and Hyper-V are named; nothing else on log3 leaks.
		"log3": {"192.168.10.7"},
		// Tailscale and NetBird are named. 本地连接 3 has no marker and holds
		// an RFC1918 address, so the leftover TAP is admitted -- and it comes
		// first, because this collector keeps enumeration order and does not
		// rank. The peer tries assisted addresses ahead of the public one, so
		// the dead TAP is not merely present, it is tried first.
		"log4": {"10.0.10.40", "172.22.2.44"},
	}
	for name, tc := range labWindows {
		t.Run(name, func(t *testing.T) {
			byIndex := make(map[int][]net.Addr, len(tc.order))
			ifaces := make([]net.Interface, 0, len(tc.order))
			for _, c := range tc.order {
				ifc := net.Interface{Index: c.index, Name: c.name}
				if c.up {
					ifc.Flags = net.FlagUp
				}
				ifaces = append(ifaces, ifc)
				if c.ip == nil {
					continue
				}
				byIndex[c.index] = []net.Addr{&net.IPNet{IP: c.ip, Mask: net.CIDRMask(prefixLen(c.ip), 32)}}
			}
			restore := swapInterfaceAddrs(t, byIndex)
			defer restore()

			got := CollectAssistedIPs(ifaces, MaxAssistedAddrs, map[string]bool{}, nil)
			if len(got) != len(want[name]) {
				t.Fatalf("assisted addresses = %v, want %v", got, want[name])
			}
			for i, ip := range want[name] {
				if got[i] != ip {
					t.Errorf("assisted addresses = %v, want %v", got, want[name])
					break
				}
			}
		})
	}
}

// A real uplink must survive, or the filter has thrown away the one address a
// peer can actually use.
func TestAssistedAddressesKeepRealUplinkOnLabWindows(t *testing.T) {
	iface := net.Interface{
		Index: 20, Name: "以太网", Flags: net.FlagUp,
	}
	up := net.IPv4(172, 22, 2, 44)
	restore := swapInterfaceAddrs(t, map[int][]net.Addr{
		20: {&net.IPNet{IP: up, Mask: net.CIDRMask(22, 32)}},
	})
	defer restore()

	got := CollectAssistedIPs([]net.Interface{iface}, MaxAssistedAddrs, map[string]bool{}, nil)
	if len(got) != 1 || got[0] != "172.22.2.44" {
		t.Errorf("assisted addresses = %v, want [172.22.2.44]", got)
	}
}

func swapInterfaceAddrs(t *testing.T, byIndex map[int][]net.Addr) func() {
	t.Helper()
	prev := InterfaceAddrs
	InterfaceAddrs = func(ifc *net.Interface) ([]net.Addr, error) {
		if a, ok := byIndex[ifc.Index]; ok {
			return a, nil
		}
		return nil, errNoAddrs
	}
	return func() { InterfaceAddrs = prev }
}

var errNoAddrs = &noAddrsError{}

type noAddrsError struct{}

func (*noAddrsError) Error() string { return "no addresses in the recorded table" }

// prefixLen returns the mask width Go would have stored for an address handed
// to net.IPNet without an explicit mask. net.CIDRMask panics on a non-IPv4
// address, and the recorded table has none, but a nil would be a silent
// divide-by-zero inside the helper.
func prefixLen(ip net.IP) int {
	if ip == nil {
		return 32
	}
	return 32
}
