package edge

import (
	"fmt"
	"net"
	"strings"
	"time"

	"n2n-go/pkg/log"
	"github.com/pion/stun/v2"
)

// STUNClient performs STUN binding requests to discover the public-facing
// UDP address as seen by an external STUN server. The discovered address is
// used to populate the pub_socket field in RegisterRequest so the relay
// server can display a routable address for P2P hole-punching coordination.
//
// The caller must pass the same *net.UDPConn that is used for P2P traffic,
// so the NAT-mapped public address corresponds to the same socket that
// will later receive hole-punch packets from peers.
type STUNClient struct {
	servers []string
	conn    *net.UDPConn
}

// NewSTUNClient creates a STUN client that uses the given P2P UDP connection
// for STUN probing. The P2P socket must be the same one that handleP2P
// reads from, so the STUN-discovered public endpoint matches the actual
// P2P socket's NAT mapping.
func NewSTUNClient(conn *net.UDPConn, servers []string) *STUNClient {
	return &STUNClient{
		servers: servers,
		conn:    conn,
	}
}

// Discover sends a STUN Binding Request to each configured server and
// returns the first successful external address (IP:port). Returns nil
// if all servers fail or no routable address is discovered.
func (s *STUNClient) Discover() (*net.UDPAddr, error) {
	result, err := s.DiscoverWithClassification()
	if err != nil {
		return nil, err
	}
	return result.Addr, nil
}

// STUNResult holds the result of a STUN discovery, including NAT classification.
type STUNResult struct {
	Addr       *net.UDPAddr
	AllAddrs   []string
	NatFeature *NatFeature
}

// DiscoverWithClassification performs STUN discovery against all configured
// servers and classifies the NAT type by comparing the responses.
//
// STUN requests are sent from the P2P UDP socket itself (s.conn) using
// WriteToUDP/ReadFromUDP, NOT from a separate DialUDP socket. This is
// critical: the STUN server sees the P2P socket's public endpoint (IP:port),
// which is the address peers must send hole-punch packets to. Using a
// separate socket would discover a different NAT mapping and produce an
// incorrect pubSocket.
//
// This runs before handleP2P starts (called from InitialSetup → InitialRegister
// → pubSocketString, before Run → handleP2P), so there is no read contention
// on the P2P socket.
//
// The approach is ported from FRP's pkg/nathole:
//  1. Send STUN Binding Requests to each configured server
//  2. Collect all external addresses
//  3. ClassifyNATFeature compares the addresses to determine EasyNAT/HardNAT
//     and the port-change behavior
func (s *STUNClient) DiscoverWithClassification() (*STUNResult, error) {
	if s.conn == nil {
		return nil, fmt.Errorf("STUN: nil connection")
	}
	if len(s.servers) == 0 {
		return nil, fmt.Errorf("STUN: no servers configured")
	}

	var allAddrs []string
	var firstAddr *net.UDPAddr
	var lastErr error

	for _, server := range s.servers {
		server = strings.TrimSpace(server)
		if server == "" {
			continue
		}
		if !strings.Contains(server, ":") {
			server = server + ":19302"
		}

		// Resolve the STUN server address
		serverAddr, err := net.ResolveUDPAddr("udp4", server)
		if err != nil {
			lastErr = fmt.Errorf("STUN: resolve %s: %w", server, err)
			continue
		}

		// Build the Binding Request message. Use a unique transaction ID
		// so we can match the response among potentially multiple STUN servers.
		msg, err := stun.Build(stun.TransactionID, stun.BindingRequest)
		if err != nil {
			lastErr = fmt.Errorf("STUN: build request for %s: %w", server, err)
			continue
		}

		// Send the STUN request from the P2P socket itself so the NAT creates
		// a mapping for the P2P socket's local port. The STUN server will
		// see this socket's public endpoint.
		_, err = s.conn.WriteToUDP(msg.Raw, serverAddr)
		if err != nil {
			lastErr = fmt.Errorf("STUN: write to %s: %w", server, err)
			continue
		}

		// Read the STUN response from the P2P socket. Use a deadline to
		// avoid blocking forever if the server doesn't respond.
		// We may receive responses from other STUN servers (from previous
		// iterations), so we match by transaction ID.
		buf := make([]byte, 2048)
		s.conn.SetReadDeadline(time.Now().Add(5 * time.Second))

		var discovered *net.UDPAddr
		found := false
		for !found {
			n, _, err := s.conn.ReadFromUDP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					lastErr = fmt.Errorf("STUN: %s: timeout", server)
					break
				}
				lastErr = fmt.Errorf("STUN: %s: read: %w", server, err)
				break
			}

			// Parse the STUN response
			var respMsg stun.Message
			if err := stun.Decode(buf[:n], &respMsg); err != nil {
				// Not a STUN message or malformed — skip it
				continue
			}

			// Check transaction ID matches
			if respMsg.TransactionID != msg.TransactionID {
				continue
			}

			// Try XOR-MAPPED-ADDRESS first (RFC 5389), then MAPPED-ADDRESS (RFC 3489)
			var xorAddr stun.XORMappedAddress
			if err := xorAddr.GetFrom(&respMsg); err == nil && xorAddr.IP != nil {
				discovered = &net.UDPAddr{
					IP:   xorAddr.IP,
					Port: xorAddr.Port,
				}
				found = true
			} else {
				var mappedAddr stun.MappedAddress
				if err := mappedAddr.GetFrom(&respMsg); err == nil && mappedAddr.IP != nil {
					discovered = &net.UDPAddr{
						IP:   mappedAddr.IP,
						Port: mappedAddr.Port,
					}
					found = true
				}
			}

			if !found {
				lastErr = fmt.Errorf("STUN: %s: no XOR-MAPPED-ADDRESS or MAPPED-ADDRESS in response", server)
			}
		}

		// Clear the read deadline so handleP2P can use blocking reads later
		s.conn.SetReadDeadline(time.Time{})

		if discovered != nil && discovered.IP != nil && !discovered.IP.IsLoopback() {
			if firstAddr == nil {
				firstAddr = discovered
			}
			allAddrs = append(allAddrs, discovered.String())
		}
	}

	if firstAddr == nil {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, fmt.Errorf("STUN: all servers failed")
	}

	// Classify NAT type by comparing all discovered addresses
	localIPs := ListLocalIPs(10)
	natFeature, err := ClassifyNATFeature(allAddrs, localIPs)
	if err != nil {
		// Not enough addresses for classification; still return what we have
		log.Printf("NAT classification skipped: %v", err)
	}

	return &STUNResult{
		Addr:       firstAddr,
		AllAddrs:   allAddrs,
		NatFeature: natFeature,
	}, nil
}
