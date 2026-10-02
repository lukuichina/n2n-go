package edge

import (
	"fmt"
	"net"
	"slices"
	"sort"
	"strconv"
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
func ListLocalIPs(maxIPs int) []string {
	if maxIPs <= 0 {
		maxIPs = 10
	}
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
				out = append(out, ranked{ip: ipv4.String(), tier: routabilityTier(ipv4), seq: len(out)})
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

// routabilityTier ranks an address by how likely a remote peer is to reach
// it directly. Lower is better.
//
//	tier 0 -- globally routable: a real public address, the only kind that
//	           can be punched from the internet.
//	tier 1 -- RFC1918 private: reachable only from inside the same network.
//	tier 2 -- CGNAT (100.64/10) and other non-RFC1918 reserved space, which
//	           includes most tunnel overlay addresses.
//	tier 3 -- link-local and everything else.
func routabilityTier(ip net.IP) int {
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
