package edge

import (
	"fmt"
	"net"
	"slices"
	"strconv"
)

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
	if len(addresses) <= 1 {
		return nil, fmt.Errorf("not enough addresses for NAT classification")
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
func ListLocalIPs(maxIPs int) []string {
	if maxIPs <= 0 {
		maxIPs = 10
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var ips []string
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			ipv4 := ipnet.IP.To4()
			if ipv4 != nil && !ipv4.IsLinkLocalUnicast() {
				ips = append(ips, ipv4.String())
				if len(ips) >= maxIPs {
					break
				}
			}
		}
	}
	return ips
}