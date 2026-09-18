package edge

import (
	"fmt"
	"n2n-go/pkg/log"
	"n2n-go/pkg/transport"
	"n2n-go/pkg/p2p"
	"n2n-go/pkg/protocol"
	"n2n-go/pkg/protocol/netstruct"
	"n2n-go/pkg/protocol/spec"
	"n2n-go/pkg/tuntap"
	"net"
	"strings"
	"time"
)

func (e *EdgeClient) UpdatePeersP2PStates() {
	peers := e.Peers.GetP2PUnknownPeers()
	for _, p := range peers {
		err := e.PingPeer(p, 3, 300*time.Second, p2p.P2PPending)
		if err != nil {
			log.Printf("handleP2PUpdates: error in UpdatePeersP2PStates for peer with MACAddress %s: %v", net.HardwareAddr(p.Infos.MacAddr).String(), err)
		}
	}
	peers = e.Peers.GetP2PendingPeers()
	for _, p := range peers {
		err := e.PingPeer(p, 3, 300*time.Second, p2p.P2PPending)
		if err != nil {
			log.Printf("handleP2PUpdates: error in UpdatePeersP2PStates for peer with MACAddress %s: %v", net.HardwareAddr(p.Infos.MacAddr).String(), err)
		}
	}
	peers = e.Peers.GetP2PAvailablePeers()
	for _, p := range peers {
		err := e.PingPeer(p, 3, 300*time.Millisecond, p2p.P2PAvailable)
		if err != nil {
			log.Printf("handleP2PUpdates: error in UpdatePeersP2PStates for peer with MACAddress %s: %v", net.HardwareAddr(p.Infos.MacAddr).String(), err)
		}
	}
}

func (e *EdgeClient) PingPeer(p *p2p.Peer, n int, interval time.Duration, status p2p.P2PCapacity) error {
	checkid := fmt.Sprintf("%s.%s.%s.%s.%d", e.ID, e.MACAddr.String(), net.HardwareAddr(p.Infos.MacAddr).String(), p.Infos.PubSocket, 0)
	pingMsg := &netstruct.PeerToPing{
		IsPong:  false,
		CheckId: checkid,
	}
	if p.UpdateP2PStatus(status, checkid) {
		e.Peers.SetPendingChanges()
	}
	for range n {
		e.SendStruct(pingMsg, net.HardwareAddr(p.Infos.MacAddr), p2p.UDPEnforceP2P)
	}
	return e.SendStruct(pingMsg, net.HardwareAddr(p.Infos.MacAddr), p2p.UDPEnforceP2P)
}

// handleHeartbeat sends heartbeat messages periodically
func (e *EdgeClient) handleP2PUpdates() {
	e.wg.Add(1)
	defer e.wg.Done()

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("handleP2PUpdates: recovered from panic: %v", r)
					}
				}()
				e.UpdatePeersP2PStates()
			}()
		case <-e.ctx.Done():
			return
		}
	}
}

func (e *EdgeClient) handleP2PInfos() {
	e.wg.Add(1)
	defer e.wg.Done()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := e.sendP2PInfos(); err != nil {
				log.Printf("sendP2PInfos error: %v", err)
			}
		case <-e.ctx.Done():
			return
		}
	}
}

// handleHeartbeat sends heartbeat messages periodically
func (e *EdgeClient) handleHeartbeat() {
	e.wg.Add(1)
	defer e.wg.Done()

	ticker := time.NewTicker(e.heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := e.sendHeartbeat(); err != nil {
				log.Printf("Heartbeat error: %v", err)
			}
		case <-e.ctx.Done():
			return
		}
	}
}

// handleTAP reads packets from the TAP interface and (potentially) sends them to the supernode.
// What's read from TAP right now are EthernetFrames and thus transformed into DATA packets
// Then sent through UDP, to either Supernode or P2PDirect connection if available and relevant.
// Alternative to Data Packet, if vFuze is enabled, it can be transfered early as Vfuze data packet.
func (e *EdgeClient) handleTAP() {
	e.wg.Add(1)
	defer e.wg.Done()

	// Preallocate the buffer once - no need to reallocate for each packet
	packetBuf := e.packetBufPool.Get()
	defer e.packetBufPool.Put(packetBuf)

	// Create separate areas for header and payload
	headerSize := protocol.ProtoVHeaderSize
	frameBuf := packetBuf[headerSize:]

	for {
		select {
		case <-e.ctx.Done():
			return
		default:
			// Continue processing
		}

		// Read directly into payload area to avoid a copy
		n, err := e.TAP.Read(frameBuf)
		if err != nil {
			if strings.Contains(err.Error(), "file already closed") {
				return
			}
			log.Printf("TAP read error: %v (handle=%v)", err, e.TAP.Iface.GetHandle())
			continue
		}

		if n < 14 {
			log.Printf("Packet too short to contain Ethernet header (%d bytes)", n)
			continue
		}

		ethertype, err := tuntap.GetEthertype(frameBuf)
		if err != nil {
			log.Printf("Cannot parse link layer frame for Ethertype, skipping: %v", err)
			continue
		}
		if ethertype == tuntap.IPv6 {
			//log.Printf("(warn) skipping TAP frame with IPv6 Ethertype: %v", ethertype)
			continue
		}

		// Log ARP frames (both request/broadcast and reply/unicast)
		if ethertype == tuntap.EthertypeARP {
			dstMAC := tuntap.FastDestination(frameBuf)
			srcMAC := tuntap.FastSource(frameBuf)
			if tuntap.IsBroadcast(dstMAC) {
				log.Printf("TAP read ARP request (broadcast) from %s, frame len=%d", srcMAC, n)
			} else {
				log.Printf("TAP read ARP reply (unicast) from %s to %s, frame len=%d", srcMAC, dstMAC, n)
			}
		}

		payload, err := e.ProcessOutgoingPayload(frameBuf[:n])
		if err != nil {
			log.Printf("Failed to process Outgoing payload %v", err)
			continue
		}

		strategy := p2p.UDPEnforceSupernode

		destMAC := tuntap.FastDestination(frameBuf)
		// if destMAC is not unicat
		// 1. We change the strategy to BestEffort so we may try P2P Direct connection
		// 2. We switch to vFuze packets if enabled by config
		if !tuntap.IsBroadcast(destMAC) {
			strategy = p2p.UDPBestEffort
			if e.enableVFuze {
				err = e.SendVFuze(destMAC, n, payload, strategy)
				if err != nil {
					if strings.Contains(err.Error(), "use of closed network connection") {
						return
					}
					log.Printf("Error sending packet with enableVFuze from TAP: %v", err)
				}
				continue
			}
		}

		err = e.WritePacket(spec.TypeData, destMAC, payload, strategy)
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			log.Printf("Error sending packet to supernode: %v", err)
		}
	}
}

// handleUDP reads packets from the UDP connection and writes the payload to the TAP interface.
func (e *EdgeClient) handleUDP() {
	// If using WSS, handle WSS packets instead
	if e.WSSTransport != nil {
		e.handleWSS()
		return
	}
	e.wg.Add(1)
	defer e.wg.Done()

	// Preallocate buffer for receiving packets
	packetBuf := e.packetBufPool.Get()
	defer e.packetBufPool.Put(packetBuf)

	for {
		select {
		case <-e.ctx.Done():
			return
		default:
			// Continue processing
		}
		n, addr, err := e.Conn.ReadFromUDP(packetBuf)
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			log.Printf("UDP read error: %v", err)
			continue
		}

		e.PacketsRecv.Add(1)

		if packetBuf[0] == protocol.VersionVFuze {
			err = e.handleVFuzePacket(packetBuf, n, addr)
			if err != nil {
				if strings.Contains(err.Error(), "file already closed") {
					return
				}
				log.Printf("handleVFuzePacket Error: %v", err)
			}
			continue
		}

		if n < protocol.ProtoVHeaderSize {
			log.Printf("Received packet too short from %v: %q", addr, string(packetBuf[:n]))
			continue
		}

		rawMsg, err := protocol.NewRawMessage(packetBuf[:n], addr)
		if err != nil {
			log.Printf("error while parsing UDP Packet: %v", err)
			continue
		}

		err = e.messageHandlers.Handle(rawMsg)
		if err != nil {
			if strings.Contains(err.Error(), "file already closed") {
				return
			}
			log.Printf("Error from messageHandler: %v", err)
		}
	}
}

func (e *EdgeClient) handleWSS() {
	e.wg.Add(1)
	defer e.wg.Done()

	log.Printf("Starting WSS packet handler")

	// Preallocate buffer for receiving packets
	packetBuf := e.packetBufPool.Get()
	defer e.packetBufPool.Put(packetBuf)

	reconnectDelay := 3 * time.Second

	for {
		select {
		case <-e.ctx.Done():
			return
		default:
			// Continue processing
		}
		
		// If not connected, try to (re)connect
		if e.WSSTransport == nil {
			if e.wssConfig == nil {
				return
			}
			log.Printf("WSS disconnected, attempting to connect in %v...", reconnectDelay)
			time.Sleep(reconnectDelay)
			
			newTransport, err := transport.NewWSSTransport(e.wssConfig)
			if err != nil {
				log.Printf("Failed to connect WSS: %v", err)
				reconnectDelay *= 2
				if reconnectDelay > 60*time.Second {
					reconnectDelay = 60 * time.Second
				}
				continue
			}
			
			e.WSSTransport = newTransport
			reconnectDelay = 3 * time.Second // Reset backoff
			log.Printf("WSS connected to %s", e.wssConfig.URL)
			
			// Re-register with supernode after (re)connection
			e.registered = false
			e.isWaitingForSNRetryRegisterResponse = true
			log.Printf("Fetching supernode public key for (re)registration...")
			if err := e.RequestSNPublicKey(); err != nil {
				log.Printf("Failed to request supernode public key: %v", err)
			}
			continue
		}

		n, addr, err := e.WSSTransport.Read(packetBuf)
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			log.Printf("WSS read error: %v", err)
			
			// Close and discard old transport to avoid repeated reads on failed connection
			oldTransport := e.WSSTransport
			e.WSSTransport = nil
			if oldTransport != nil {
				oldTransport.Close()
			}
			
			// Will reconnect on next iteration
			continue
		}

		e.PacketsRecv.Add(1)

		if packetBuf[0] == protocol.VersionVFuze {
			udpAddr, _ := addr.(*net.UDPAddr)
			err = e.handleVFuzePacket(packetBuf, n, udpAddr)
			if err != nil {
				if strings.Contains(err.Error(), "file already closed") {
					return
				}
				log.Printf("handleVFuzePacket Error: %v", err)
			}
			continue
		}

		if n < protocol.ProtoVHeaderSize {
			log.Printf("Received WSS packet too short from %v: %q", addr, string(packetBuf[:n]))
			continue
		}

		udpAddr, _ := addr.(*net.UDPAddr)
		rawMsg, err := protocol.NewRawMessage(packetBuf[:n], udpAddr)
		if err != nil {
			log.Printf("error while parsing WSS Packet: %v", err)
			continue
		}

		err = e.messageHandlers.Handle(rawMsg)
		if err != nil {
			if strings.Contains(err.Error(), "file already closed") {
				return
			}
			log.Printf("Error from WSS messageHandler: %v", err)
		}
	}
}
