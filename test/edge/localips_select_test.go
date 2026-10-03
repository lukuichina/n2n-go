package edge_test

import (
	. "n2n-go/pkg/edge"
	"net"
	"sort"
	"testing"
)

// The two tests that matter for the stale-WiFi regression cannot run on a
// typical build host: it has no down interface carrying an IPv4 address, so
// the real-interface test skips and the regression would go unnoticed until
// it reached a Windows desktop.
//
// net.Interface.Addrs is a method that reads the OS, so a synthetic
// net.Interface cannot carry addresses. sortLocalIPsFromCIDRs therefore takes
// the up/down state and addresses explicitly, which is exactly the input
// ListLocalIPs extracts from the real table. Interface identity goes through
// the real IsTapInterface so name-based filtering is covered as well.
//
// index is the interface index and tapDriver says whether the OS attributes
// that interface to a TAP driver -- the one signal neither the name nor the
// address can supply. excludedIfIndexes carries the same set as production,
// with the test supplying it directly because a build host is not Windows.
func sortLocalIPsFromCIDRs(candidates []ifaceCIDR, maxIPs int) []string {
	excluded := make(map[uint32]bool, len(candidates))
	for _, c := range candidates {
		if c.tapDriver {
			excluded[uint32(c.index)] = true
		}
	}
	type ranked struct {
		ip   string
		tier int
		seq  int
	}
	var out []ranked
	seq := 0
	for _, c := range candidates {
		if !c.up {
			continue
		}
		ifc := net.Interface{Index: c.index, Name: c.name, Flags: net.FlagUp}
		if v4 := c.ip.To4(); v4 != nil && TapAddressSpace.Contains(v4) {
			continue // overlay adapter, e.g. the localized "本地连接" tap
		}
		if IsTapInterface(&ifc, excluded) {
			continue
		}
		ipv4 := c.ip.To4()
		if ipv4 == nil || ipv4.IsLoopback() || ipv4.IsLinkLocalUnicast() {
			continue
		}
		out = append(out, ranked{ip: ipv4.String(), tier: RoutabilityTier(ipv4), seq: seq})
		seq++
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].tier < out[j].tier })

	ips := make([]string, 0, len(out))
	for _, r := range out {
		if len(ips) >= maxIPs {
			break
		}
		ips = append(ips, r.ip)
	}
	return ips
}

type ifaceCIDR struct {
	name string
	up   bool
	ip   net.IP
	// index is the interface index, as net.Interface reports it.
	index int
	// tapDriver marks an interface the OS attributes to a TAP driver. On
	// Windows that identity comes from the registry; see tapindex_windows.go.
	tapDriver bool
}

// The regression, in the shape it appeared on the Windows host: Ethernet up
// with 192.168.10.7, WiFi down but still configured with 192.168.1.11.
func TestSortLocalIPsDropsDownButKeepsUp(t *testing.T) {
	got := sortLocalIPsFromCIDRs([]ifaceCIDR{
		{"Ethernet", true, net.IPv4(192, 168, 10, 7), 3, false},
		{"WiFi", false, net.IPv4(192, 168, 1, 11), 12, false},
	}, 10)

	if len(got) != 1 || got[0] != "192.168.10.7" {
		t.Fatalf("expected only the live uplink 192.168.10.7, got %v", got)
	}
	for _, ip := range got {
		if ip == "192.168.1.11" {
			t.Fatal("the down interface's stale address was offered as a punch target")
		}
	}
}

// setup.go's ListLocalIPs(1) is the single entry broadcast to peers as the
// P2P endpoint. On Windows the disconnected WiFi adapter sorts ahead of the
// live uplink by interface index, so this is the case that actually bit.
func TestSortLocalIPsFirstEntryIsNeverStale(t *testing.T) {
	got := sortLocalIPsFromCIDRs([]ifaceCIDR{
		{"WiFi", false, net.IPv4(192, 168, 1, 11), 12, false},
		{"Ethernet", true, net.IPv4(192, 168, 10, 7), 3, false},
	}, 1)
	if len(got) != 1 {
		t.Fatalf("expected one endpoint, got %v", got)
	}
	if got[0] != "192.168.10.7" {
		t.Fatalf("P2PEndpoint would be advertised as %s, but that link is down", got[0])
	}
}

// A tunnel interface that is up but overlay-scoped must sort behind a real
// uplink, so the single-entry pick does not hand peers an unpunchable address.
func TestSortLocalIPsRanksUplinkAboveOverlay(t *testing.T) {
	got := sortLocalIPsFromCIDRs([]ifaceCIDR{
		{"wt0", true, net.IPv4(100, 101, 102, 1), 74, false},
		{"Ethernet", true, net.IPv4(192, 168, 10, 7), 3, false},
	}, 1)
	if len(got) != 1 || got[0] != "192.168.10.7" {
		t.Fatalf("overlay address won the single-endpoint slot: %v", got)
	}
}

// A globally routable address still outranks a private one, preserving the
// ordering that ListLocalIPs documents.
func TestSortLocalIPsRanksPublicAbovePrivate(t *testing.T) {
	got := sortLocalIPsFromCIDRs([]ifaceCIDR{
		{"Ethernet", true, net.IPv4(192, 168, 10, 7), 3, false},
		{"Ethernet2", true, net.IPv4(2, 58, 196, 38), 4, false},
	}, 2)
	if len(got) != 2 || got[0] != "2.58.196.38" {
		t.Fatalf("public address should rank first, got %v", got)
	}
}
