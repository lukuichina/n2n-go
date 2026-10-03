package natclient

import (
	"fmt"
	"n2n-go/pkg/log"
	"n2n-go/pkg/p2p"
	"net"
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
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			return "", fmt.Errorf("failed to get interface addresses: %w", err)
		}
		// Rank the candidates and take the best one. Returning whichever
		// address happened to come first was the bug: on a host running an
		// overlay tunnel -- NetBird, WireGuard, all drawing from 100.64.0.0/10
		// -- the tunnel's address won and was then reported as "found
		// public/routable local ip" (observed 2026-09-30: 100.101.102.21 and
		// 100.76.83.147). A public address outranks every private and overlay
		// one, so a host that has both now keeps the right answer.
		var fallbackIP string
		var public, private, overlay string
		for _, address := range addrs {
			ipnet, ok := address.(*net.IPNet)
			if !ok {
				continue
			}
			ipv4 := ipnet.IP.To4()
			switch {
			case ipv4 == nil, ipv4.IsLoopback(), ipv4.IsLinkLocalUnicast():
				continue
			case IsPublicRoutable(ipv4):
				if public == "" {
					public = ipv4.String()
				}
			case p2p.IsCGNATOverlayAddr(ipv4):
				if overlay == "" {
					overlay = ipv4.String()
				}
			default:
				if private == "" {
					private = ipv4.String()
				}
			}
		}
		if public != "" {
			return public, nil
		}
		if private != "" {
			fallbackIP = private
		} else {
			fallbackIP = overlay
		}
		// If we only found private IPs, return the first one
		if fallbackIP != "" {
			return fallbackIP, nil
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
