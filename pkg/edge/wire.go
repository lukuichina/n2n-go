package edge

import (
	"fmt"
	"n2n-go/pkg/p2p"
	"n2n-go/pkg/protocol"
	"n2n-go/pkg/protocol/netstruct"
	"n2n-go/pkg/protocol/spec"
	"net"
	"sync/atomic"
	"time"
)

func (e *EdgeClient) UDPAddrWithStrategy(dst net.HardwareAddr, strategy p2p.UDPWriteStrategy) (*net.UDPAddr, error) {
	// If using WSS, always route through supernode
	if e.WSSTransport != nil {
		return e.SupernodeAddr, nil
	}

	var udpSocket *net.UDPAddr
	switch strategy {
	case p2p.UDPEnforceSupernode:
		udpSocket = e.SupernodeAddr
	case p2p.UDPBestEffort, p2p.UDPEnforceP2P:
		if dst == nil {
			if strategy == p2p.UDPEnforceP2P {
				return nil, fmt.Errorf("cannot write packet with UDPEnforceP2P flag and a nil destMACAddr")
			}
			udpSocket = e.SupernodeAddr
			break
		}
		p, err := e.Peers.GetPeer(dst.String())
		if err != nil {
			if strategy == p2p.UDPEnforceP2P {
				return nil, fmt.Errorf("cannot write packet with UDPEnforceP2P (peer not found) %v", err)
			}
			udpSocket = e.SupernodeAddr
			break
		}
		if p.P2PStatus != p2p.P2PAvailable && strategy == p2p.UDPBestEffort {
			udpSocket = e.SupernodeAddr
			break
		}
		udpSocket = p.UDPAddr()
	}
	return udpSocket, nil
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
	udpSocket, err := e.UDPAddrWithStrategy(dst, strategy)
	if err != nil {
		return err
	}

	header := e.EdgeHeader(pt, dst)
	e.PacketsSent.Add(1)

	packet := protocol.PackProtoVDatagram(header, payload)

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
	udpSocket, err := e.UDPAddrWithStrategy(dst, strategy)
	if err != nil {
		return err
	}

	header := e.EdgeHeader(s.PacketType(), dst)

	payload, err := protocol.Encode(s)
	if err != nil {
		return err
	}

	packet := protocol.PackProtoVDatagram(header, payload)

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
	udpSocket, err := e.UDPAddrWithStrategy(dst, strategy)
	if err != nil {
		return err
	}

	vfuzh := protocol.VFuzeHeaderBytes(dst)
	totalLen := protocol.ProtoVFuzeSize + len(payload)
	packet := make([]byte, totalLen)
	copy(packet[0:7], vfuzh[0:7])
	copy(packet[7:], payload)
	e.PacketsSent.Add(1)

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
