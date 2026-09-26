package edge

import (
	"fmt"
	"n2n-go/pkg/log"
	"n2n-go/pkg/p2p"
	"n2n-go/pkg/protocol"
	"n2n-go/pkg/protocol/netstruct"
	"n2n-go/pkg/protocol/spec"
	"net"
	"sync/atomic"
	"time"
)

func (e *EdgeClient) UDPAddrWithStrategy(dst net.HardwareAddr, strategy p2p.UDPWriteStrategy) (*net.UDPAddr, bool, error) {
	var udpSocket *net.UDPAddr
	isP2P := false

	switch strategy {
	case p2p.UDPEnforceSupernode:
		udpSocket = e.SupernodeAddr
	case p2p.UDPBestEffort, p2p.UDPEnforceP2P:
		if dst == nil {
			if strategy == p2p.UDPEnforceP2P {
				return nil, false, fmt.Errorf("cannot write packet with UDPEnforceP2P flag and a nil destMACAddr")
			}
			udpSocket = e.SupernodeAddr
			break
		}
		p, err := e.Peers.GetPeer(dst.String())
		if err != nil {
			log.Printf("[P2P-DEBUG] peer lookup failed for %s: %v, using supernode", dst.String(), err)
			if strategy == p2p.UDPEnforceP2P {
				return nil, false, fmt.Errorf("cannot write packet with UDPEnforceP2P (peer not found) %v", err)
			}
			udpSocket = e.SupernodeAddr
			break
		}
		// Only use direct P2P for UDPBestEffort when the hole punch is
		// confirmed (P2PFullDuplex). P2PAvailable only means the peer
		// *might* be reachable — e.g. Edge1 behind cloud NAT with no UDP
		// port forwarding will silently lose direct UDP packets.
		// For UDPEnforceP2P, we trust the caller's explicit request.
		//
		// CRITICAL: prefer P2PRaddr (the NAT-mapped source address observed
		// by the peer when receiving our punch packets — FRP-style raddr)
		// over PubSocket (STUN-discovered). Under Symmetric NAT, these
		// differ because the NAT assigns a different port per destination.
		// Using PubSocket sends data to the wrong port and packets are
		// silently dropped. P2PRaddr is the verified-reachable address.
		//
		// The routing log is emitted once at the end of this block, *after*
		// the decision is made — logging before it would report the previous
		// packet's target and hide exactly the transitions that matter
		// (Unavailable -> FullDuplex). LogRouteDecision collapses it to one
		// line per real change plus a periodic re-log, instead of one line
		// per packet: the liveness ping/pong alone produced ~8 lines per 3s
		// per peer.
		decide := func() {
			if strategy == p2p.UDPBestEffort && p.P2PStatus == p2p.P2PFullDuplex {
				// Verify P2P is actually usable by checking if we received
				// the peer's raddr (NAT-mapped source observed by the peer
				// when receiving our punch packets). Without a verified
				// raddr, the hole-punch may be a false positive — e.g. Edge1
				// behind a cloud NAT with no UDP port forwarding will report
				// FullDuplex based on tiny punch packets getting through, but
				// larger Data/ICMP packets are silently dropped on direct UDP.
				if raddr := p.P2PRaddr; raddr != "" {
					if resolvedRaddr, err := net.ResolveUDPAddr("udp", raddr); err == nil && resolvedRaddr != nil {
						udpSocket = resolvedRaddr
						isP2P = true
						return
					}
				}
				// No verified raddr — P2P hole-punch may be a false positive;
				// fall back to WSS relay for reliable delivery.
				log.Printf("[P2P-DEBUG] peer %s: FullDuplex but no verified raddr, falling back to WSS relay", dst.String())
				udpSocket = e.SupernodeAddr
				return
			}
			if strategy == p2p.UDPBestEffort {
				udpSocket = e.SupernodeAddr
				return
			}
			// UDPEnforceP2P: the caller explicitly wants the direct path
			// (the path-verification probe, and the punch itself).
			//
			// Prefer the verified raddr here exactly as the UDPBestEffort
			// FullDuplex branch does above. Falling straight through to
			// p.UDPAddr() (the STUN/PubSocket address) sends the packet to
			// the wrong port under Symmetric NAT, where the gateway assigns
			// a different port per destination — the probe was silently
			// dropped every time even though the punch (which targets the
			// observed source address) worked fine.
			if raddr := p.P2PRaddr; raddr != "" {
				if resolvedRaddr, err := net.ResolveUDPAddr("udp", raddr); err == nil && resolvedRaddr != nil {
					udpSocket = resolvedRaddr
					isP2P = true
					return
				}
			}
			// No verified raddr yet - fall back to PubSocket
			udpSocket = p.UDPAddr()
		}
		decide()
		p.LogRouteDecision(fmt.Sprintf("%v", strategy), udpSocket, isP2P)
	}
	return udpSocket, isP2P, nil
}

func (e *EdgeClient) EdgeHeader(pt spec.PacketType, dst net.HardwareAddr) *protocol.ProtoVHeader {
	seq := uint16(atomic.AddUint32(&e.seq, 1) & 0xFFFF)
	h := &protocol.ProtoVHeader{
		Version:     protocol.VersionV,
		TTL:         64,
		PacketType:  pt,
		Flags:       0,
		Sequence:    seq,
		CommunityID: protocol.HashCommunity(e.Community),
		Timestamp:   uint32(time.Now().Unix()),
	}
	copy(h.SourceID[:], e.MACAddr[:6])
	if dst != nil {
		copy(h.DestID[:], dst[:6])
	}
	return h
}

func (e *EdgeClient) WritePacket(pt spec.PacketType, dst net.HardwareAddr, payload []byte, strategy p2p.UDPWriteStrategy) error {
	udpSocket, isP2P, err := e.UDPAddrWithStrategy(dst, strategy)
	if err != nil {
		return err
	}

	header := e.EdgeHeader(pt, dst)
	e.PacketsSent.Add(1)

	packet := protocol.PackProtoVDatagram(header, payload)

	// P2P direct send takes priority over WSS
	if isP2P && e.P2PConn != nil {
		_, err = e.P2PConn.WriteToUDP(packet, udpSocket)
		if err != nil {
			return fmt.Errorf("failed to send P2P UDP packet: %w", err)
		}
		return nil
	}

	// Use WSS transport if available
	if e.WSSTransport != nil {
		_, err = e.WSSTransport.Write(packet, nil)
		if err != nil {
			return fmt.Errorf("failed to send WSS packet: %w", err)
		}
		return nil
	}

	// Use UDP
	if e.Conn == nil {
		return fmt.Errorf("no transport available: WSS disconnected and UDP not initialized")
	}
	_, err = e.Conn.WriteToUDP(packet, udpSocket)
	if err != nil {
		return fmt.Errorf("failed to send UDP packet: %w", err)
	}
	return nil
}

func (e *EdgeClient) SendStruct(s netstruct.PacketTyped, dst net.HardwareAddr, strategy p2p.UDPWriteStrategy) error {
	udpSocket, isP2P, err := e.UDPAddrWithStrategy(dst, strategy)
	if err != nil {
		return err
	}

	header := e.EdgeHeader(s.PacketType(), dst)

	payload, err := protocol.Encode(s)
	if err != nil {
		return err
	}

	packet := protocol.PackProtoVDatagram(header, payload)

	// P2P direct send takes priority over WSS
	if isP2P && e.P2PConn != nil {
		_, err = e.P2PConn.WriteToUDP(packet, udpSocket)
		if err != nil {
			return fmt.Errorf("failed to send P2P UDP packet: %w", err)
		}
		return nil
	}

	// Use WSS transport if available
	if e.WSSTransport != nil {
		_, err = e.WSSTransport.Write(packet, nil)
		if err != nil {
			return fmt.Errorf("failed to send WSS packet: %w", err)
		}
		return nil
	}

	// Use UDP
	if e.Conn == nil {
		return fmt.Errorf("no transport available: WSS disconnected and UDP not initialized")
	}
	_, err = e.Conn.WriteToUDP(packet, udpSocket)
	if err != nil {
		return fmt.Errorf("failed to send UDP packet: %w", err)
	}
	return nil
}

func (e *EdgeClient) SendVFuze(dst net.HardwareAddr, n int, payload []byte, strategy p2p.UDPWriteStrategy) error {
	udpSocket, isP2P, err := e.UDPAddrWithStrategy(dst, strategy)
	if err != nil {
		return err
	}

	vfuzh := protocol.VFuzeHeaderBytes(dst)
	totalLen := protocol.ProtoVFuzeSize + len(payload)
	packet := make([]byte, totalLen)
	copy(packet[0:7], vfuzh[0:7])
	copy(packet[7:], payload)
	e.PacketsSent.Add(1)

	// P2P direct send takes priority over WSS
	if isP2P && e.P2PConn != nil {
		_, err = e.P2PConn.WriteToUDP(packet[:totalLen], udpSocket)
		if err != nil {
			return fmt.Errorf("failed to send P2P VFuze packet: %w", err)
		}
		return nil
	}

	// Use WSS transport if available
	if e.WSSTransport != nil {
		_, err = e.WSSTransport.Write(packet, nil)
		if err != nil {
			return fmt.Errorf("failed to send WSS packet: %w", err)
		}
		return nil
	}

	// Use UDP
	if e.Conn == nil {
		return fmt.Errorf("no transport available: WSS disconnected and UDP not initialized")
	}
	_, err = e.Conn.WriteToUDP(packet[:totalLen], udpSocket)
	if err != nil {
		return err
	}
	return nil
}
