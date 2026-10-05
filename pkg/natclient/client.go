package natclient

import (
	"fmt"
	"n2n-go/pkg/log"
	"n2n-go/pkg/p2p"
	"net"
	"sort"
	"strings"
	"time"
)

// NATClient defines the common interface for NAT traversal clients
type NATClient interface {
	// AddPortMapping requests a port mapping on the gateway.
	AddPortMapping(protocol string, externalPort, internalPort uint16, description string, leaseDuration uint32) error
	// DeletePortMapping removes a previously added port mapping.
	DeletePortMapping(protocol string, externalPort uint16) error
	// CleanupAllMappings removes all port mappings created by this specific client instance.
	CleanupAllMappings()
	// GetExternalIP returns the external IP address discovered by the client.
	GetExternalIP() string
	// GetLocalIP returns the local IP address used by the client for mappings.
	GetLocalIP() string
	// GetType returns a string identifying the type of NAT client (e.g., "UPnP-IGDv1", "NAT-PMP/PCP").
	GetType() string
}

// SetupNAT attempts NAT traversal using UPnP first, then NAT-PMP/PCP.
// It takes the UDP connection to determine the internal port and an identifier for the description.
// Returns a NATClient interface instance on success, or nil if both methods fail.
func SetupNAT(conn *net.UDPConn, edgeID string, dialAddr string) NATClient {
	if conn == nil || conn.LocalAddr() == nil {
		log.Printf("NAT Setup: Invalid UDP connection provided.")
		return nil
	}
	localUDPAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		log.Printf("NAT Setup: Could not get UDP address from connection: %v", conn.LocalAddr())
		return nil
	}

	localIP, err := getLocalIP(dialAddr)
	if err != nil {
		log.Printf("NAT Setup: Unable to get suitable LocalIP, no further NAT Setup")
		return nil
	}
	ipv4 := net.ParseIP(localIP)
	if IsPublicRoutable(ipv4) {
		log.Printf("NAT Setup: found public/routable local ip: %s no further nat setup is required", localIP)
		return nil
	}

	udpPort := uint16(localUDPAddr.Port)
	protocol := "udp" // Assuming UDP for n2n-go

	var natClient NATClient
	var setupErr error

	// --- Try UPnP First ---
	log.Printf("NAT Setup: Attempting UPnP/IGD discovery...")
	upnpClient, err := newUPnPClient(dialAddr) // Internal constructor
	if err == nil {
		log.Printf("NAT Setup: UPnP/IGD client created successfully (%s).", upnpClient.GetType())
		log.Printf("NAT Setup: UPnP Local IP: %s, External IP: %s", upnpClient.GetLocalIP(), upnpClient.GetExternalIP())

		description := fmt.Sprintf("n2n-go/%s/%s", edgeID, upnpClient.GetType())
		leaseDuration := uint32(0) // 0 often means permanent/long lease in UPnP

		log.Printf("NAT Setup: UPnP Requesting mapping: %s ext:%d -> int:%d (%s) lease:%d",
			protocol, udpPort, udpPort, description, leaseDuration)

		errMap := upnpClient.AddPortMapping(protocol, udpPort, udpPort, description, leaseDuration)
		if errMap != nil {
			log.Printf("NAT Setup: UPnP AddPortMapping failed: %v. Trying NAT-PMP/PCP...", errMap)
			// Don't clean up UPnP client yet, just record the error
			setupErr = fmt.Errorf("UPnP mapping failed: %w", errMap)
		} else {
			log.Printf("NAT Setup: UPnP port mapping added successfully.")
			natClient = upnpClient // Success!
		}
	} else {
		log.Printf("NAT Setup: UPnP/IGD initialization failed: %v. Trying NAT-PMP/PCP...", err)
		setupErr = fmt.Errorf("UPnP init failed: %w", err) // Record the error
	}

	// --- Try NAT-PMP/PCP if UPnP failed ---
	if natClient == nil {
		log.Printf("NAT Setup: Attempting NAT-PMP/PCP discovery...")
		pmpClient, err := newNATPMPClient(dialAddr) // Internal constructor
		if err == nil {
			log.Printf("NAT Setup: NAT-PMP/PCP client created successfully (%s).", pmpClient.GetType())
			log.Printf("NAT Setup: NAT-PMP/PCP Local IP: %s, External IP: %s", pmpClient.GetLocalIP(), pmpClient.GetExternalIP())

			description := fmt.Sprintf("n2n-go/%s/%s", edgeID, pmpClient.GetType())
			// Use a long-ish default lifetime for NAT-PMP/PCP when 0 is desired.
			// Routers might cap this. 0 specifically means delete in PMP/PCP mapping request.
			leaseDuration := uint32(3600 * 24) // Request 24 hours

			log.Printf("NAT Setup: NAT-PMP/PCP Requesting mapping: %s ext:%d -> int:%d (%s) lease:%ds",
				protocol, udpPort, udpPort, description, leaseDuration)

			errMap := pmpClient.AddPortMapping(protocol, udpPort, udpPort, description, leaseDuration)
			if errMap != nil {
				log.Printf("NAT Setup: NAT-PMP/PCP AddPortMapping failed: %v", errMap)
				// Both methods have failed now. Append error info.
				if setupErr != nil {
					setupErr = fmt.Errorf("%v; NAT-PMP/PCP mapping failed: %w", setupErr, errMap)
				} else {
					setupErr = fmt.Errorf("NAT-PMP/PCP mapping failed: %w", errMap)
				}
				natClient = nil // Ensure it's nil
			} else {
				log.Printf("NAT Setup: NAT-PMP/PCP port mapping added successfully.")
				natClient = pmpClient // Success!
			}
		} else {
			log.Printf("NAT Setup: NAT-PMP/PCP initialization failed: %v", err)
			// Both methods have failed now. Append error info.
			if setupErr != nil {
				setupErr = fmt.Errorf("%v; NAT-PMP/PCP init failed: %w", setupErr, err)
			} else {
				setupErr = fmt.Errorf("NAT-PMP/PCP init failed: %w", err)
			}
			natClient = nil // Ensure it's nil
		}
	}

	// --- Final Result ---
	if natClient != nil {
		log.Printf("NAT Setup: Successfully configured NAT traversal using %s.", natClient.GetType())
		log.Printf("NAT Setup: External address expected: %s:%d (%s)", natClient.GetExternalIP(), udpPort, protocol)
		return natClient
	}

	log.Printf("NAT Setup: Failed to configure NAT traversal using UPnP or NAT-PMP/PCP. Last error: %v", setupErr)
	return nil
}

// Cleanup ensures any mappings created by the client are removed.
// Safe to call even if client is nil.
func Cleanup(client NATClient) {
	if client != nil {
		log.Printf("NAT Cleanup: Cleaning up mappings for %s client...", client.GetType())
		client.CleanupAllMappings()
		log.Printf("NAT Cleanup: Finished for %s.", client.GetType())
	}
}

// getLocalIP returns a non-loopback, non-linklocal IPv4 address for the host.
// This is shared by both UPnP and NAT-PMP implementations.
func getLocalIP(dialAddr string) (string, error) {
	if dialAddr == "" {
		ifaces, err := net.Interfaces()
		if err != nil {
			return "", fmt.Errorf("failed to get interface addresses: %w", err)
		}
		// Knowing the gateway turns "pick an address" into "pick the
		// address that faces the gateway", which is the only question UPnP and
		// NAT-PMP actually care about. Best-effort: a failure here just means
		// we rank without it, which is no worse than the old behaviour.
		var gw net.IP
		if g, gerr := discoverGatewayIP(); gerr == nil {
			gw = g
		}
		if ranked := RankLocalIPv4(ifaces, gw); len(ranked) > 0 {
			return ranked[0], nil
		}
	}
	dialto := "8.8.8.8:53"
	if dialAddr != "" {
		dialto = dialAddr
	}
	// Last resort: Try dialing out (might not work in all sandboxes/environments)
	conn, err := net.DialTimeout("udp", dialto, 2*time.Second) // Connect to public DNS
	if err == nil {
		defer conn.Close()
		if localAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			ipv4 := localAddr.IP.To4()
			if ipv4 != nil && !ipv4.IsLoopback() && !ipv4.IsLinkLocalUnicast() {
				//log.Printf("getLocalIP: Found IP via Dial: %s", ipv4.String())
				return ipv4.String(), nil
			}
		}
	}
	log.Printf("getLocalIP: Dial method failed or yielded unsuitable IP: %v", err)

	return "", fmt.Errorf("no suitable local IPv4 address found")
}

// Helper to standardize protocol input
func standardizeProtocol(protocol string) string {
	upper := strings.ToUpper(protocol)
	if upper == "UDP" {
		return "UDP"
	}
	return "TCP" // Default to TCP if not UDP
}

// IsPublicRoutable reports whether ip is reachable from the public internet, and
// is the single test this package should use for that question.
//
// It replaces `!ip.IsPrivate()`, which is wrong in the direction that matters
// here: Go's IsPrivate covers RFC1918 only, so every address in 100.64.0.0/10
// -- carrier-grade NAT space, and the pool overlay tunnels are carved from --
// counts as "not private" and therefore as public. On a host with NetBird that
// made the tunnel address look like a public IP and short-circuited the UPnP
// setup. This is the third copy of the CGNAT test in the tree, after
// pkg/edge/natclassify.go and pkg/p2p/affinity.go; all three agree because they
// share pkg/p2p's definition.
func IsPublicRoutable(ip net.IP) bool {
	if ip == nil {
		return false
	}
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	if v4.IsPrivate() || p2p.IsCGNATOverlayAddr(v4) {
		return false
	}
	return v4.IsGlobalUnicast() && !v4.IsLinkLocalUnicast() && !v4.IsLoopback()
}

// RankLocalIPv4 returns this host's usable IPv4 addresses, best first.
//
// It replaces the enumeration getLocalIP() used to do, which had two defects.
//
// The first was already known: net.InterfaceAddrs() returns addresses from
// every interface regardless of state, so an overlay tunnel's 100.64.0.0/10
// address could be reported as the host's "public/routable local ip" (observed
// 2026-09-30: 100.101.102.21, 100.76.83.147). Ranking public above private
// above overlay fixed that ordering but did nothing for the second defect.
//
// The second is that "first RFC1918 address wins" is not a preference at all,
// it is whatever the OS enumerated first. On log3 (Windows, 2026-10-05) that
// picked 192.168.1.11 on WLAN -- an adapter in AddressState Tentative, i.e. not
// actually connected -- over 192.168.10.7 on 以太网 3, which was the adapter
// carrying all of the host's real traffic. Both are private, so the existing
// ranking could not tell them apart and the caller got the wrong one. It is
// visible in the log as UPnP and NAT-PMP both reporting "Local IP:
// 192.168.1.11" on a machine whose working address was 192.168.10.7.
//
// Two things are therefore checked per address, and both are facts rather than
// guesses:
//
//   - the interface has to be up. A down interface cannot reach the gateway,
//     and Windows leaves a disabled adapter's addresses enumerable;
//   - the gateway decides. An address on the same subnet as the gateway is the
//     one that can actually talk to it, so it outranks an equally-private
//     address on some other subnet. This is the signal that actually
//     distinguishes 192.168.10.7 from 192.168.1.11, since both are RFC1918
//     and both are on interfaces that may report as up.
//
// gateway may be nil, in which case only the interface-up and
// public/private/overlay ordering applies.
//
// Ties keep enumeration order, so a host with one interface per class is
// unaffected.
func RankLocalIPv4(ifaces []net.Interface, gateway net.IP) []string {
	return rankLocalIPv4(ifaces, gateway, func(i *net.Interface) ([]net.Addr, error) {
		return i.Addrs()
	})
}

// ifaceAddrs is the seam that makes RankLocalIPv4 testable. net.Interface.Addrs
// reads the OS, so a ranking function that took interfaces directly could only
// ever be exercised against whatever machine the test happened to run on -- and
// the bug it fixes is precisely that this machine's adapter order is not the
// one that matters.
func rankLocalIPv4(
	ifaces []net.Interface,
	gateway net.IP,
	addrsOf func(*net.Interface) ([]net.Addr, error),
) []string {
	type candidate struct {
		ip    string
		score int
	}
	var cands []candidate
	for idx := range ifaces {
		ifc := &ifaces[idx]
		// FlagUp is the only portable statement available about interface
		// readiness. Go's net package does not surface Windows'
		// AddressState, so a Tentative adapter cannot be named directly --
		// but a disabled one is not FlagUp, and the gateway test covers the
		// rest.
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := addrsOf(ifc)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ipv4 := ipnet.IP.To4()
			if ipv4 == nil || ipv4.IsLoopback() || ipv4.IsLinkLocalUnicast() {
				continue
			}
			// Class dominates, and the gateway only breaks ties inside a
			// class. A public address outranking every private one is the
			// older guarantee (a host with a real public IP must report that
			// IP), so the gateway bonus must not be able to lift a private
			// address past it -- hence the class weight of 1000 against a
			// bonus of 1, not the other way round.
			score := 0
			switch {
			case IsPublicRoutable(ipv4):
				score = 3000
			case p2p.IsCGNATOverlayAddr(ipv4):
				score = 1000
			default:
				score = 2000
			}
			// On the gateway's subnet: this is the address the rest of the
			// NAT conversation happens over.
			if gateway != nil && gateway.To4() != nil {
				if _, prefix, err := net.ParseCIDR(ipnet.String()); err == nil {
					if prefix.Contains(gateway) {
						score += 1
					}
				}
			}
			cands = append(cands, candidate{ip: ipv4.String(), score: score})
		}
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].score > cands[j].score })
	out := make([]string, 0, len(cands))
	for _, c := range cands {
		out = append(out, c.ip)
	}
	return out
}
