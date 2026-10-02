package edge

import (
	"errors"
	"fmt"
	"n2n-go/pkg/crypto"
	"n2n-go/pkg/log"
	"n2n-go/pkg/p2p"
	"n2n-go/pkg/protocol"
	"n2n-go/pkg/protocol/netstruct"
	"n2n-go/pkg/protocol/spec"
	"net"
)

var ErrNACKRegister = errors.New("Edge: supernode refused register request. Aborting")

func (e *EdgeClient) handleHeartbeatMessage(r *protocol.RawMessage) error {
	// Heartbeat from relay (WS mode) - no response needed, just acknowledge
	return nil
}

func (e *EdgeClient) handleSNPublicSecretMessage(r *protocol.RawMessage) error {
	rresp, err := protocol.ToMessage[*netstruct.SnPublicSecret](r)
	if err != nil {
		return err
	}

	pubkey, err := crypto.PublicKeyFromPEMData(rresp.Msg.PemData)
	if err != nil {
		return err
	}
	e.SNPubKey = pubkey
	log.Printf("Updated Supernode public key !")
	e.isWaitingForSNPubKeyUpdate = false
	if e.isWaitingForSNRetryRegisterResponse {

		err = e.RequestRegister()
		if err != nil {
			return err
		}

	}
	return nil
}

func (e *EdgeClient) handleRegisterResponseMessage(r *protocol.RawMessage) error {
	rresp, err := protocol.ToMessage[*netstruct.RegisterResponse](r)
	if err != nil {
		return err
	}
	if !rresp.Msg.IsRegisterOk {
		return ErrNACKRegister
	}

	log.Printf("Successfull Supernode Reregister")
	e.registered = true
	e.isWaitingForSNRetryRegisterResponse = false
	e.Peers.IsWaitingCommunityDatas = false
	log.Printf("sending Recovery Peer List Request")
	err = e.sendPeerListRequest()
	if err != nil {
		log.Printf("(warn) failed sending Recovery Peer List Request: %v", err)
	}
	return nil
}

// handleVFuzePacket processes incoming VFuze packets
func (e *EdgeClient) handleVFuzePacket(packetBuf []byte, n int, addr *net.UDPAddr) error {
	if !e.enableVFuze {
		log.Printf("received VFuze data packet from %v but VFuze support is disabled", addr)
		return nil
	}

	dst, err := protocol.VFuzePacketDestMACAddr(packetBuf)
	if err != nil {
		log.Printf("ignoring VFuze packet with non extractable destMac: %v", err)
		return nil
	}

	if e.MACAddr.String() != dst.String() {
		log.Printf("ignoring VFuze packet with destMAC (%s) not matching our (%s)", dst.String(), e.MACAddr.String())
		return nil
	}

	// A relayed packet has no UDP source, so the socket checks below cannot
	// run. Skip them rather than dereferencing nil; the destMAC check above
	// still applies, and this matches the ProtoV path, which also delivers
	// relayed packets with a nil source address.
	if !disablePeerSocketCheckingInVFuze && addr != nil {
		// if not from supernode, we check that we now this peer
		if !e.IsSupernodeUDPAddr(addr) {
			if !e.IsKnownPeerSocket(addr) {
				log.Printf("ignoring VFuze packet from not in known peers: %s", addr.String())
				return nil
			}
		}
	}

	// Store raddr (NAT-mapped source address) when we receive VFuze data.
	// Under Symmetric NAT, the source port changes with each destination,
	// so we continuously update the best-known reachable address.
	//
	// addr is nil for packets relayed by the Worker: handleWSS does
	// addr.(*net.UDPAddr) on conn.RemoteAddr(), which is not a *net.UDPAddr,
	// so the assertion yields a nil *net.UDPAddr that was passed straight
	// through. Dereferencing it crashed the whole edge process. The payload
	// is still valid and must be delivered — only the raddr bookkeeping needs
	// a real source, and a relayed packet simply has none to learn.
	if addr != nil {
		// Every SetP2PRaddr must be paired with IndexPeerRaddr. The registry
		// resolves inbound packets by socket address, and the raddr is
		// precisely the address a NAT rewrote the source to -- so an raddr
		// that is set but not indexed is one this peer will never be found
		// by again.
		//
		// Observed 2026-10-02 on log4 (172.22.2.44 behind a router at
		// 172.22.1.17): its raddr for log3 settled on 172.22.1.17:49653
		// through this very block, and the index never learned that address.
		// 451 well-formed direct frames then arrived from exactly that source
		// and not one promoted the peer, because handleP2P's GetPeerBySocket
		// missed and the IP fallback could not match a NAT device to any
		// peer either. The pair sat at Available and the punch path kept
		// logging "punch seen but no data frame verified yet" forever.
		//
		// log3, with no NAT in front of it, was unaffected -- its peers'
		// advertised addresses already resolve -- which is why the symptom
		// looked selective rather than universal.
		if peer, err := e.Peers.GetPeerBySocket(addr); err == nil {
			peer.SetP2PRaddr(addr.String())
			e.Peers.IndexPeerRaddr(peer, addr.String())
		} else if peer, err := e.Peers.GetPeerBySocketIP(addr.IP); err == nil {
			peer.SetP2PRaddr(addr.String())
			e.Peers.IndexPeerRaddr(peer, addr.String())
		}
	}

	return e.handleDataPayload(packetBuf[protocol.ProtoVFuzeSize:n])
}

func (e *EdgeClient) handleDataPayload(payload []byte) error {
	// AES-GCM 最小有效密文长度 = nonceSize(12) + authTag(16) = 28 字节。
	// 短于此长度的包不可能是 AES-GCM 加密过的，跳过 transform pipeline 直接透传。
	// 这处理了同一社区内加密设置不一致（部分 Edge 用 -k、部分不用）或
	// 上游（Worker/Supernode）转发的非加密短包场景。
	const minGCMSize = 28 // nonce(12) + tag(16)
	var err error
	if len(payload) < minGCMSize {
		log.Printf("handleDataPayload: payload len=%d < %d (AES-GCM minimum), skipping decryption, passing through", len(payload), minGCMSize)
	} else {
		payload, err = e.ProcessIncomingPayload(payload)
		if err != nil {
			return fmt.Errorf("error while processing Incoming data packets, droping (err: %w)", err)
		}
	}
	// Pad to minimum Ethernet frame size (60 bytes) for IFF_NO_PI TAP devices.
	// Linux kernel rejects frames < ETH_Z when IFF_NO_PI is set.
	if len(payload) < 60 {
		padded := make([]byte, 60)
		copy(padded, payload)
		payload = padded
	}
	if e.TAP == nil {
		// The TAP device can disappear underneath a running edge (it was
		// deleted, or never came up). Writing through a nil device panics
		// and takes the whole edge process down, turning a recoverable
		// data-path problem into a hard outage. Report it instead.
		return fmt.Errorf("TAP device is nil, dropping %d-byte payload", len(payload))
	}
	// A blocking write here is expected on Windows, where the TAP handle is an
	// overlapped handle with a shared event pool: the write waits for the other
	// side of the device to drain, and the handleTAP goroutine on the far side
	// sees the matching second-long stall in its own read. It is the normal cost
	// of the device, not a defect, so it is not worth a log line.
	_, err = e.TAP.Write(payload)
	if err != nil {
		return fmt.Errorf("TAP write error: %w", err)
	}
	return nil
}

func (e *EdgeClient) handleDataMessage(r *protocol.RawMessage) error {
	log.Printf("handleDataMessage: type=%d srcMAC=%s dstMAC=%s payloadLen=%d",
		r.Header.PacketType,
		r.Header.GetSrcMACAddr(),
		r.Header.GetDstMACAddr(),
		len(r.Payload))

	// Store raddr when receiving data messages — the source address is
	// the NAT-mapped address through which the peer can be reached.
	// This continuously updates the best-known reachable address under
	// Symmetric NAT where the port changes per destination.
	if udpAddr, ok := r.FromAddr.(*net.UDPAddr); ok && udpAddr != nil {
		// Same invariant as above: set and index together, or the new raddr
		// is unreachable by lookup.
		if peer, err := e.Peers.GetPeerBySocket(udpAddr); err == nil {
			peer.SetP2PRaddr(udpAddr.String())
			e.Peers.IndexPeerRaddr(peer, udpAddr.String())
		}
	}

	return e.handleDataPayload(r.Payload)
}

func (e *EdgeClient) handlePeerInfoMessage(r *protocol.RawMessage) error {
	peerMsg, err := protocol.ToMessage[*p2p.PeerInfoList](r) //r.ToPeerInfoMessage()
	if err != nil {
		return err
	}
	peerInfos := peerMsg.Msg
	err = e.Peers.HandlePeerInfoList(peerInfos, false, true)
	if err != nil {
		log.Printf("error in HandlePeerInfoList: %v", err)
		return err
	}
	// Mark pending changes so sendP2PInfos will broadcast our own P2P
	// state (pubSocket from STUN, NAT type) to the Worker. Without this,
	// the Worker never learns our NAT info and cannot coordinate hole
	// punching — only the peer that received P2PStateInfo gets eligible.
	e.Peers.SetPendingChanges()
	// Extract and dispatch relay-coordinated NAT hole instructions.
	// The Worker embeds an instruction in each peer's PeerInfo entry, but
	// only the entry matching our own MAC is addressed to us. Processing
	// other peers' instructions would cause the role-detection logic to
	// assign us the wrong role (self-punching).
	ourMAC := e.MACAddr.String()
	for _, pi := range peerInfos.GetPeerInfos() {
		instr := pi.GetNatHoleInstruction()
		if instr == nil {
			continue
		}
		peerMAC := net.HardwareAddr(pi.GetMacAddr()).String()
		if peerMAC != ourMAC {
			continue
		}
		if err := e.handleNatHoleInstruction(peerMAC, instr); err != nil {
			log.Printf("[Edge] handleNatHoleInstruction error: %v", err)
		}
	}
	return nil
}

func (s *EdgeClient) handleLeasesInfosMessage(r *protocol.RawMessage) error {
	leaseMsg, err := protocol.ToMessage[*netstruct.LeasesInfos](r)
	if err != nil {
		return err
	}
	if leaseMsg.Msg.IsRequest {
		return fmt.Errorf("edge do not handle request LeasesInfosMessage")
	}
	s.EAPI.LastLeasesInfos = leaseMsg.Msg
	s.EAPI.IsWaitingForLeasesInfos = false
	return nil
}

func (e *EdgeClient) handleRetryRegisterRequest(r *protocol.RawMessage) error {
	if r.Header.PacketType != spec.TypeRetryRegisterRequest {
		return fmt.Errorf(" routing failure: not a TypeRetryRegisterRequest")
	}

	if e.isWaitingForSNRetryRegisterResponse {
		return nil
	}

	log.Printf("Received RetryRegisteRequest from recovering supernode. Trying gracefull Re-regisration...")

	err := e.RequestSNPublicKey()
	if err != nil {
		return err
	}
	e.isWaitingForSNPubKeyUpdate = true
	e.isWaitingForSNRetryRegisterResponse = true

	return nil
}

func (e *EdgeClient) handleP2PFullStateMessage(r *protocol.RawMessage) error {
	fstateMsg, err := protocol.ToMessage[*p2p.P2PFullState](r) //r.ToP2PFullStateMessage()
	if err != nil {
		return err
	}
	if fstateMsg.Msg.IsRequest {
		return fmt.Errorf("edge shall not received Request type P2PFullStateMessage")
	}
	return e.Peers.UpdateP2PCommunityDatas(fstateMsg.Msg.Reachables, fstateMsg.Msg.Unreachables)
}

func (e *EdgeClient) handlePingMessage(r *protocol.RawMessage) error {
	pingMsg, err := protocol.ToMessage[*netstruct.PeerToPing](r)
	if err != nil {
		return err
	}
	// If it is PING message, answer with pong and CheckId payload
	if !pingMsg.Msg.IsPong {
		// swap dst/src
		dst, err := net.ParseMAC(pingMsg.EdgeMACAddr())
		if err != nil {
			return fmt.Errorf("cannot parse dst EdgeMACAddr for swaping")
		}
		if pingMsg.DestMACAddr() != e.MACAddr.String() {
			return fmt.Errorf("ping recipient differs from this edge MACAddress")
		}
		pongMsg := &netstruct.PeerToPing{
			IsPong:  true,
			CheckId: pingMsg.Msg.CheckId,
		}
		e.SendStruct(pongMsg, dst, p2p.UDPBestEffort)
	} else {
		// if it is a PONG message, check OUR last pings and update P2PStates accordingly
		p, err := e.Peers.GetPeer(pingMsg.EdgeMACAddr())
		if err != nil {
			// Peer may have been removed (e.g. via TypeUnregister) after
			// the ping was sent; silently ignore stale pongs.
			log.Printf("(warn) received pong for MACAddress %s not in our peers list (stale)", pingMsg.EdgeMACAddr())
			return nil
		}
		if p.P2PCheckID == pingMsg.Msg.CheckId {
			if p.UpdateP2PStatus(p2p.P2PAvailable, pingMsg.Msg.CheckId) {
				e.Peers.SetPendingChanges()
			}
		} else {
			err = fmt.Errorf("received a pong for MACAddress %s but checkID differs (want %s, received %s)", pingMsg.EdgeMACAddr(), p.P2PCheckID, pingMsg.Msg.CheckId)
			if p.UpdateP2PStatus(p2p.P2PUnknown, "") {
				e.Peers.SetPendingChanges()
			}
		}
		if p.P2PStatus == p2p.P2PAvailable {
			if !pingMsg.Header.IsFromSupernode() {
				if changed, _ := p.SetFullDuplex(true); changed {
					e.Peers.SetPendingChanges()
				}
			} else {
				if changed, _ := p.SetFullDuplex(false); changed {
					e.Peers.SetPendingChanges()
				}
			}
		}
	}
	return nil
}
