package supernode

import (
	"fmt"
	"n2n-go/pkg/log"
	"n2n-go/pkg/protocol"
	"n2n-go/pkg/protocol/netstruct"
	"n2n-go/pkg/protocol/spec"
	"net"
	"time"
)

func (s *Supernode) ForwardUnicast(r *protocol.RawMessage) error {
	cm, err := s.GetCommunity(r)
	if err != nil {
		return err
	}
	targetEdge, found := cm.GetEdge(r.DestMACAddr())
	if !found {
		return fmt.Errorf("%w: %s", ErrUnicastForwardFail, r.EdgeMACAddr())
	}

	if err := s.forwardPacket(r.RawPacket(), targetEdge); err != nil {
		s.stats.PacketsDropped.Add(1)
		return fmt.Errorf("Supernode: Failed to forward packet to edge %s: %v", targetEdge.MACAddr, err)
	}
	s.debugLog("Forwarded packet to edge %s", targetEdge.MACAddr)
	s.stats.PacketsForwarded.Add(1)
	return nil

}

func (s *Supernode) ForwardWithFallBack(r *protocol.RawMessage) error {
	cm, err := s.GetCommunity(r)
	if err != nil {
		return err
	}
	targetEdge, found := cm.GetEdge(r.DestMACAddr())
	if found {
		if err := s.forwardPacket(r.RawPacket(), targetEdge); err != nil {
			s.stats.PacketsDropped.Add(1)
			log.Printf("Supernode: Failed to forward packet to edge %s: %v", targetEdge.MACAddr, err)
		} else {
			s.debugLog("Forwarded packet to edge %s", targetEdge.MACAddr)
			s.stats.PacketsForwarded.Add(1)
			return nil
		}
	}
	s.debugLog("Unable to selectively forward packet orNo destination MAC provided. Broadcasting to community %s", cm.Name())
	s.broadcast(r.RawPacket(), cm, r.EdgeMACAddr())
	return nil
}

// forwardPacket sends a packet to a specific edge
func (s *Supernode) forwardPacket(packet []byte, target *Edge) error {
	var err error
	if packet[0] == protocol.VersionV {
		packet, err = protocol.FlagPacketFromSupernode(packet)
		if err != nil {
			return err
		}
	}

	// Check if target is using WSS
	if target.WSSConnID != "" {
		s.wssConnectionsMu.RLock()
		wssTransport, found := s.wssConnections[target.WSSConnID]
		s.wssConnectionsMu.RUnlock()
		if !found {
			return fmt.Errorf("WSS connection not found: %s", target.WSSConnID)
		}
		s.debugLog("Forwarding WSS packet to edge %s (conn: %s)", target.MACAddr, target.WSSConnID)
		_, err = wssTransport.Write(packet, nil)
		return err
	}

	// Use UDP
	addr := target.UDPAddr()
	s.debugLog("Forwarding packet to edge %s at %v", target.MACAddr, addr)
	_, err = s.Conn.WriteToUDP(packet, addr)
	return err
}

// broadcast sends a packet to all edges in the same community except the sender
func (s *Supernode) broadcast(packet []byte, cm *Community, senderID string) {
	targets := cm.GetAllEdges()

	// Now send to all targets without holding the lock
	sentCount := 0
	for _, target := range targets {
		if target.MACAddr == senderID {
			continue
		} // Check if we need to convert the packet for this target
		if err := s.forwardPacket(packet, target); err != nil {
			log.Printf("Supernode: Failed to broadcast packet to edge %s: %v", target.MACAddr, err)
			s.stats.PacketsDropped.Add(1)
		} else {
			s.debugLog("Broadcasted packet from %s to edge %s", senderID, target.MACAddr)
			sentCount++
		}
	}

	if sentCount > 0 {
		s.stats.PacketsForwarded.Add(uint64(sentCount))
	}
}

func (s *Supernode) WritePacket(pt spec.PacketType, community string, dst net.HardwareAddr, payload []byte, addr net.Addr) error {

	header := s.SNHeader(pt, community, dst)

	// Check if this is a WSS connection
	if addr != nil {
		// Try to find edge by address
		s.edgeMu.RLock()
		var targetEdge *Edge
		for _, edge := range s.edgesByMAC {
			if edge.WSSConnID != "" && s.wssConnections[edge.WSSConnID] != nil {
				// For WSS, we need to match by some identifier
				// For now, we'll use the address string
				if edge.WSSConnID == addr.String() {
					targetEdge = edge
					break
				}
			}
		}
		s.edgeMu.RUnlock()

		if targetEdge != nil {
			packet := protocol.PackProtoVDatagram(header, payload)
			return s.forwardPacket(packet, targetEdge)
		}
	}

	// Only send UDP if we have a UDP address
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		_, err := s.Conn.WriteToUDP(protocol.PackProtoVDatagram(header, payload), udpAddr)
		if err != nil {
			return fmt.Errorf(" failed to send packet: %w", err)
		}
	} else if addr != nil {
		return fmt.Errorf("cannot send UDP packet to non-UDP address: %T", addr)
	}
	return nil
}

func (s *Supernode) SNHeader(pt spec.PacketType, community string, dst net.HardwareAddr) *protocol.ProtoVHeader {
	h := &protocol.ProtoVHeader{
		Version:     protocol.VersionV,
		TTL:         64,
		PacketType:  pt,
		Flags:       protocol.FlagFromSuperNode,
		Sequence:    0,
		CommunityID: protocol.HashCommunity(community),
		Timestamp:   uint32(time.Now().Unix()),
	}
	copy(h.SourceID[:], s.MacADDR()[:6])
	if dst != nil {
		copy(h.DestID[:], dst[:6])
	}
	return h
}

func (s *Supernode) SNStructHeader(p netstruct.PacketTyped, community string, dst net.HardwareAddr) *protocol.ProtoVHeader {
	return s.SNHeader(p.PacketType(), community, dst)
}

func (s *Supernode) SendStruct(p netstruct.PacketTyped, community string, src, dst net.HardwareAddr, addr net.Addr) error {

	header := s.SNStructHeader(p, community, dst)
	payload, err := protocol.Encode(p)
	if err != nil {
		return err
	}

	// Check if this is a WSS connection
	if addr != nil {
		s.edgeMu.RLock()
		var targetEdge *Edge
		for _, edge := range s.edgesByMAC {
			if edge.WSSConnID != "" && s.wssConnections[edge.WSSConnID] != nil {
				if edge.WSSConnID == addr.String() {
					targetEdge = edge
					break
				}
			}
		}
		s.edgeMu.RUnlock()

		if targetEdge != nil {
			packet := protocol.PackProtoVDatagram(header, payload)
			return s.forwardPacket(packet, targetEdge)
		}

		// Check if this is a wssAddr (for unregistered edges like SNPublicSecret requests)
		if waddr, ok := addr.(*wssAddr); ok {
			s.wssConnectionsMu.RLock()
			wssTransport, found := s.wssConnections[waddr.connID]
			s.wssConnectionsMu.RUnlock()
			if found {
				_, err = wssTransport.Write(protocol.PackProtoVDatagram(header, payload), nil)
				if err != nil {
					return fmt.Errorf("failed to send WSS packet: %w", err)
				}
				return nil
			}
		}
	}

	// For UDP, we need *net.UDPAddr
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		_, err = s.Conn.WriteToUDP(protocol.PackProtoVDatagram(header, payload), udpAddr)
		if err != nil {
			return fmt.Errorf(" failed to send packet: %w", err)
		}
	} else if addr != nil {
		return fmt.Errorf("cannot send UDP packet to non-UDP address: %T", addr)
	} else {
		// addr is nil, this might be an error or a broadcast
		return fmt.Errorf("cannot send UDP packet to nil address")
	}
	return nil
}

func (s *Supernode) BroadcastStruct(p netstruct.PacketTyped, cm *Community, src, dst net.HardwareAddr, senderMac string) error {
	// Get buffer for full packet

	header := s.SNStructHeader(p, cm.Name(), dst)
	payload, err := protocol.Encode(p)
	if err != nil {
		return err
	}
	packet := protocol.PackProtoVDatagram(header, payload)

	s.broadcast(packet, cm, senderMac)
	return nil
}
