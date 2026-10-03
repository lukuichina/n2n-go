package edge

import (
	"fmt"
	"log"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// cgnat is RFC 6598 shared address space (100.64.0.0/10). Go's net package
// does not classify it as private, yet it is never routable on the public
// internet, so we rank it separately.
var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0).To4(), Mask: net.CIDRMask(10, 32)}

// NAT classification constants — ported from FRP's pkg/nathole/classify.go.
const (
	EasyNAT = "EasyNAT"
	HardNAT = "HardNAT"

	BehaviorNoChange    = "BehaviorNoChange"
	BehaviorIPChanged   = "BehaviorIPChanged"
	BehaviorPortChanged = "BehaviorPortChanged"
	BehaviorBothChanged = "BehaviorBothChanged"
)

// NatFeature describes the NAT traversal characteristics of this Edge.
//
// Ported from FRP's NatFeature struct. The classification is derived by
// comparing multiple STUN responses: if the external IP or port varies
// across probes, the NAT is "Hard" (port-restricted / symmetric); otherwise
// it's "Easy" (full cone / restricted cone).
type NatFeature struct {
	NatType            string
	Behavior           string
	PortsDifference    int
	RegularPortsChange bool
	PublicNetwork      bool
}

// ClassifyNATFeature classifies the NAT type by comparing multiple STUN
// responses. Each response is an "externalAddr" string ("ip:port").
//
// - If both IP and port change across probes → HardNAT (BehaviorBothChanged)
// - If only IP changes → HardNAT (BehaviorIPChanged)
// - If only port changes → HardNAT (BehaviorPortChanged)
// - If neither changes → EasyNAT (BehaviorNoChange)
//
// localIPs are the host's own IPs; if any STUN response IP matches a local IP,
// the network is considered Public (no NAT).
//
// Ported from FRP's ClassifyNATFeature.
func ClassifyNATFeature(addresses []string, localIPs []string) (*NatFeature, error) {
	if len(addresses) == 0 {
		return nil, fmt.Errorf("no addresses for NAT classification")
	}
	if len(addresses) == 1 {
		// One STUN response cannot distinguish a cone NAT from a symmetric
		// one -- there is nothing to compare it against -- but it does settle
		// two things, and refusing to answer threw both away.
		//
		// It used to return an error here, which left NatFeature nil, which
		// made the edge advertise natType="unknown", which made the Worker's
		// isCoordEligible reject the peer outright
		// (handler.js:386 accepts only HardNAT/EasyNAT). A host behind a
		// firewall that lets one of the six STUN servers through was thus
		// silently excluded from hole-punch coordination for the life of the
		// process. Observed 2026-10-02 on E1 (100.64.0.1) and log3
		// (100.64.0.4), both Online and both punching fine by hand.
		//
		// If the mapped IP is one of ours there is no NAT at all, and that is
		// decidable from a single sample -- report it as public. Otherwise we
		// cannot prove cone, so say HardNAT: it still passes isCoordEligible,
		// and being treated as the hard case only costs a longer ladder,
		// whereas "unknown" costs the peer its place in the ladder entirely.
		addr := &NatFeature{Behavior: BehaviorNoChange}
		host, portStr, err := net.SplitHostPort(addresses[0])
		if err != nil {
			return nil, fmt.Errorf("invalid address %q: %w", addresses[0], err)
		}
		// The classification below only reads the host, but the port is
		// validated anyway so this path accepts exactly what the multi-sample
		// path does. A corrupt address is worth reporting even when the
		// answer would not have changed.
		if _, err := strconv.Atoi(portStr); err != nil {
			return nil, fmt.Errorf("invalid port %q in %q: %w", portStr, addresses[0], err)
		}
		if slices.Contains(localIPs, host) {
			addr.PublicNetwork = true
			addr.NatType = EasyNAT
		} else {
			addr.NatType = HardNAT
		}
		return addr, nil
	}
	natFeature := &NatFeature{}
	ipChanged := false
	portChanged := false

	var baseIP, basePort string
	var portMax, portMin int
	for _, addr := range addresses {
		ip, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid address %q: %w", addr, err)
		}
		portNum, err := strconv.Atoi(port)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q in %q: %w", port, addr, err)
		}
		if slices.Contains(localIPs, ip) {
			natFeature.PublicNetwork = true
		}

		if baseIP == "" {
			baseIP = ip
			basePort = port
			portMax = portNum
			portMin = portNum
			continue
		}

		portMax = max(portMax, portNum)
		portMin = min(portMin, portNum)
		if baseIP != ip {
			ipChanged = true
		}
		if basePort != port {
			portChanged = true
		}
	}

	switch {
	case ipChanged && portChanged:
		natFeature.NatType = HardNAT
		natFeature.Behavior = BehaviorBothChanged
	case ipChanged:
		natFeature.NatType = HardNAT
		natFeature.Behavior = BehaviorIPChanged
	case portChanged:
		natFeature.NatType = HardNAT
		natFeature.Behavior = BehaviorPortChanged
	default:
		natFeature.NatType = EasyNAT
		natFeature.Behavior = BehaviorNoChange
	}

	if natFeature.Behavior == BehaviorPortChanged {
		natFeature.PortsDifference = portMax - portMin
		if natFeature.PortsDifference <= 5 && natFeature.PortsDifference >= 1 {
			natFeature.RegularPortsChange = true
		}
	}

	return natFeature, nil
}

// ClassifyFeatureCount counts EasyNAT vs HardNAT features and how many
// HardNAT features have regular port changes. Useful for the relay server
// to decide which side should initiate hole-punching.
//
// Ported from FRP's ClassifyFeatureCount.
func ClassifyFeatureCount(features []*NatFeature) (easyCount, hardCount, regularPortChangeCount int) {
	for _, feature := range features {
		if feature == nil {
			continue
		}
		if feature.NatType == EasyNAT {
			easyCount++
			continue
		}
		hardCount++
		if feature.RegularPortsChange {
			regularPortChangeCount++
		}
	}
	return
}

// ListLocalIPs returns all non-loopback, non-link-local IPv4 addresses
// of the host, up to maxIPs. Used to detect whether a STUN response
// address matches a local address (public network detection).
//
// Ported from FRP's ListLocalIPsForNatHole.
//
// Ordering matters. net.InterfaceAddrs() returns addresses in interface
// index order, and callers such as EdgeClient.P2PEndpointString() take the
// FIRST entry to stand in for a wildcard-bound P2P socket. On a host with
// a tunnel interface (WireGuard/Tailscale/cloud agent) that interface is
// often enumerated before the real uplink, so the unfiltered first entry
// was a tunnel-internal address such as 100.101.102.21 -- unreachable
// from the peer, which made every hole punch fail while the node looked
// perfectly healthy.
//
// We therefore sort by decreasing likelihood of being reachable from a
// remote peer: globally routable addresses first, then ordinary private
// ranges, and finally link-local/tunnel space. Within a tier the original
// enumeration order is preserved so the result stays deterministic.
// A down interface's address is actively misleading, not merely useless: a
// peer spends a punch budget on it and can never get an answer, because
// nothing can be delivered to an interface that is not up.
//
// CollectAssistedIPs already filters on net.FlagUp, but this function did
// not, and it feeds two places that matter:
//
//   - setup.go's ListLocalIPs(1), whose single entry stands in for a
//     wildcard-bound P2P socket and is broadcast to peers as the endpoint.
//   - ClassifyNATFeature, which decides whether a STUN-reflexive address is
//     one of our own -- a wrong entry there makes a genuinely open NAT look
//     like a symmetric one, or the reverse.
//
// Observed on a Windows host whose WiFi had been associated to a
// 192.168.1.0/24 network and then disconnected: ipconfig listed the adapter
// as "media disconnected" and showed no address, yet 192.168.1.11 kept
// appearing in the address list and was advertised to peers as
// 192.168.1.11:<live P2P port> -- a port the host was genuinely listening on,
// which is what made the entry look plausible enough to survive review.
//
// net.InterfaceAddrs cannot be used for this: it returns no interface
// metadata, so there is no way to tell an address that is configured on a
// down link from one on a live link.
func ListLocalIPs(maxIPs int) []string {
	return ListLocalIPsExcluding(maxIPs, 0)
}

// ListLocalIPsExcluding is ListLocalIPs with the interface n2n itself is
// running on additionally excluded by index.
//
// The overlay address space already covers the tap when --net is left at its
// default, but the subnet is configurable, and a tap carrying a routable
// address on a non-default --net is exactly the kind of address a peer must
// never be sent to. Passing the index removes the dependence on the subnet.
//
// ownIfIndex may be 0 when the tap has not been opened yet or its index is
// unknown, in which case this behaves exactly as ListLocalIPs.
func ListLocalIPsExcluding(maxIPs int, ownIfIndex uint32) []string {
	if maxIPs <= 0 {
		maxIPs = 10
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		// Fall back to the unfiltered list rather than reporting nothing:
		// a stale address is a lesser evil than an empty one, and the
		// ordering below still puts a real uplink first in the common case.
		log.Printf("[P2P] cannot enumerate interfaces for local IPs: %v", err)
		return listLocalIPsUnfiltered(maxIPs)
	}
	excluded := tapAdapterIfIndexes()
	if ownIfIndex != 0 {
		if excluded == nil {
			excluded = make(map[uint32]bool, 1)
		}
		excluded[ownIfIndex] = true
	}
	return sortAndTrimLocalIPs(ifaces, maxIPs, excluded)
}

// sortAndTrimLocalIPs applies the up-interface filter, the TAP filter, the
// address sanity checks and the reachability ordering. Split out from
// ListLocalIPs so the selection logic can be tested against a synthetic
// interface table -- a normal build host has no down interface with a stale
// address, so a test against the real one would skip and miss the regression.
//
// excludedIfIndexes carries interface identity that no other signal can
// supply: the indexes the OS attributes to a TAP driver, plus the index of the
// interface n2n itself opened.
func sortAndTrimLocalIPs(ifaces []net.Interface, maxIPs int, excludedIfIndexes map[uint32]bool) []string {
	type ranked struct {
		ip   string
		tier int
		seq  int
	}
	var out []ranked
	seq := 0
	for i := range ifaces {
		if ifaces[i].Flags&net.FlagUp == 0 {
			continue
		}
		if IsTapInterface(&ifaces[i], excludedIfIndexes) {
			continue
		}
		addrs, aerr := ifaces[i].Addrs()
		if aerr != nil {
			continue
		}
		for _, address := range addrs {
			ipnet, ok := address.(*net.IPNet)
			if !ok || ipnet.IP == nil || ipnet.IP.IsLoopback() {
				continue
			}
			ipv4 := ipnet.IP.To4()
			if ipv4 == nil || ipv4.IsLinkLocalUnicast() {
				continue
			}
			out = append(out, ranked{ip: ipv4.String(), tier: RoutabilityTier(ipv4), seq: seq})
			seq++
		}
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

// tapInterfaceMarkers are the substrings Windows uses to name a TAP-Windows
// virtual adapter. There is no portable way to ask the OS "is this a tap";
// matching the name is what CollectAssistedIPs's callers already do via
// excludeIface, and it is the only signal available before the tap has been
// opened (and thus before its MAC is known).
var tapInterfaceMarkers = []string{
	"tap-windows",
	"tap-windows adapter",
	"tap-windows v9",
	"openvpn",
}

// TapAddressSpace is the CGNAT range (100.64.0.0/10) that n2n-go's own
// overlay draws from, and which NetBird and Tailscale also use. An address in
// this space is never reachable by a peer over the public internet, so it is
// not a punch target regardless of which interface carries it.
var TapAddressSpace = cgnat

// IsTapInterface reports whether ifc is a TAP or VPN/tunnel virtual adapter,
// judged by name where the name says so and by address space otherwise.
//
// A TAP must never be advertised as a P2P endpoint, and FlagUp cannot keep it
// out: the TAP-Windows driver reports the adapter as up once it has been
// opened, regardless of whether any n2n instance is using it. On a host that
// has run several n2n instances -- or has one leftover TAP from an earlier run
// with a different subnet -- the stale adapter is both up and carrying an
// RFC1918 address, which puts it in the same reachability tier as a real
// uplink. Since ListLocalIPs(1)'s single entry becomes the advertised
// endpoint, an enumerated-first stale TAP wins the slot and the peer is sent
// to an address that belongs to an unrelated virtual network.
//
// Observed on log4: 10.0.10.40 on a leftover tap, while the real uplink was
// 172.22.2.44 and the live tap was 100.64.0.5. The two are the same tier, so
// only interface identity can tell them apart -- and the name and address
// space below do not: "本地连接 3" carries no marker, and 10.0.10.40 is
// ordinary RFC1918. That address was measured arriving at a peer's edge as
// the advertised P2P endpoint, so the gap was not theoretical. The index set
// passed in is what closes it; the name and address-space rules stay as the
// fallback for hosts where the driver identity cannot be read.
//
// Name matching alone is not sufficient. On a Chinese-locale Windows the tap
// appears as "本地连接" with no marker in the name at all -- the ipconfig of
// the host shows the live n2n overlay there as 100.64.0.5. So the address
// space is checked as well, which covers every overlay adapter regardless of
// how it is named or which locale is installed.
//
// The rule is deliberately conservative: it can only exclude additional
// interfaces, never admit a bad one.
func IsTapInterface(ifc *net.Interface, excludedIfIndexes map[uint32]bool) bool {
	// Driver identity first, where it is available. This is the only check
	// that survives a localized adapter name and an adapter the driver
	// insists is up: on the lab hosts the leftover tap is called "本地连接 3"
	// and holds 10.0.10.40/24, so no name marker matches it and no address
	// space does either, while the registry records its driver as the same
	// tap0901 as the tap n2n is actually using.
	if excludedIfIndexes != nil && excludedIfIndexes[uint32(ifc.Index)] {
		return true
	}
	name := strings.ToLower(ifc.Name)
	for _, marker := range tapInterfaceMarkers {
		if strings.Contains(name, marker) {
			return true
		}
	}
	for _, marker := range tunnelInterfaceMarkers {
		if strings.Contains(name, marker) {
			return true
		}
	}
	// No usable marker in the name: fall back to the address space. This is
	// what catches the localized "本地连接" naming.
	addrs, err := ifc.Addrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP == nil {
			continue
		}
		if v4 := ipnet.IP.To4(); v4 != nil && TapAddressSpace.Contains(v4) {
			return true
		}
	}
	return false
}

// tunnelInterfaceMarkers name the userland VPN/VCS tunnel adapters that show
// up on the sample hosts alongside the TAP.
//
// "vethernet" covers the Hyper-V and WSL virtual switch adapters that carry a
// private address -- log3's default switch holds 172.20.80.1/20 and is up, so
// it is offered to peers as a punch target despite being reachable only from
// the host itself. Like the tunnel markers these are interfaces whose address
// belongs to an overlay, not to the network peers are on.
var tunnelInterfaceMarkers = []string{
	"wt0", "tailscale", "zerotier", "vethernet",
}

// listLocalIPsUnfiltered is the previous implementation, kept only as the
// fallback for the case where the interface table cannot be read at all.
func listLocalIPsUnfiltered(maxIPs int) []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	type ranked struct {
		ip   string
		tier int
		seq  int
	}
	var out []ranked
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			ipv4 := ipnet.IP.To4()
			if ipv4 != nil && !ipv4.IsLinkLocalUnicast() {
				out = append(out, ranked{ip: ipv4.String(), tier: RoutabilityTier(ipv4), seq: len(out)})
			}
		}
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

// RoutabilityTier ranks an address by how likely a remote peer is to reach
// it directly. Lower is better.
//
//	tier 0 -- globally routable: a real public address, the only kind that
//	           can be punched from the internet.
//	tier 1 -- RFC1918 private: reachable only from inside the same network.
//	tier 2 -- CGNAT (100.64/10) and other non-RFC1918 reserved space, which
//	           includes most tunnel overlay addresses.
//	tier 3 -- link-local and everything else.
func RoutabilityTier(ip net.IP) int {
	switch {
	case ip.IsGlobalUnicast() && !ip.IsPrivate():
		// 100.64.0.0/10 is a global-unicast range but is carrier-grade NAT
		// space, never routable on the public internet. It is also the range
		// overlay networks commonly draw from, so it must not outrank a real
		// public address.
		if cgnat.Contains(ip) {
			return 2
		}
		return 0
	case ip.IsPrivate():
		return 1
	default:
		return 3
	}
}
