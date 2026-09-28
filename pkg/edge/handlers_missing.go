package edge

import (
	"fmt"
	"n2n-go/pkg/log"
	"n2n-go/pkg/p2p"
	"n2n-go/pkg/protocol"
	"n2n-go/pkg/protocol/netstruct"
	"net"
	"strconv"
	"strings"
)

// handleUnregisterRequestMessage handles TypeUnregisterRequest (2).
// Removes the peer from the local registry.
func (e *EdgeClient) handleUnregisterRequestMessage(r *protocol.RawMessage) error {
	unreg, err := protocol.ToMessage[*netstruct.UnregisterRequest](r)
	if err != nil {
		return err
	}
	macAddr := unreg.EdgeMACAddr()
	if macAddr == e.MACAddr.String() {
		return nil // ignore self-unregister
	}
	if err := e.Peers.RemovePeer(macAddr); err != nil {
		log.Printf("(warn) failed removing peer %s on unregister: %v", macAddr, err)
		return nil
	}
	log.Printf("removed peer %s via UnregisterRequest", macAddr)
	return nil
}

// handleAckMessage handles TypeAck (5) - no operation required.
func (e *EdgeClient) handleAckMessage(r *protocol.RawMessage) error {
	return nil
}

// handlePeerListRequestMessage handles TypePeerListRequest (6).
// Edge does not serve peer lists; silently ignore.
func (e *EdgeClient) handlePeerListRequestMessage(r *protocol.RawMessage) error {
	return nil
}

// handleP2PStateInfoMessage handles TypeP2PStateInfo (9).
// Merges P2P reachable info from the sender into the local registry.
func (e *EdgeClient) handleP2PStateInfoMessage(r *protocol.RawMessage) error {
	p2pMsg, err := protocol.ToMessage[*p2p.PeerP2PInfos](r)
	if err != nil {
		return err
	}
	srcMAC := p2pMsg.EdgeMACAddr()

	// Update the sender's own P2P info if present
	if p2pMsg.Msg.From != nil {
		if p, err := e.Peers.GetPeer(srcMAC); err == nil {
			// Learn P2P endpoint from the sender
			if p2pMsg.Msg.From.P2PEndpoint != "" {
				p.SetP2PEndpoint(p2pMsg.Msg.From.P2PEndpoint)
			}
			// We received P2P info from this peer; mark as reachable
			if p.UpdateP2PStatus(p2p.P2PAvailable, "") {
				e.Peers.SetPendingChanges()
			}
		}
	}

	// Update P2P status and endpoints for peers listed in the message
	for _, info := range p2pMsg.Msg.To {
		mac := net.HardwareAddr(info.MacAddr).String()
		if p, err := e.Peers.GetPeer(mac); err == nil {
			// Learn P2P endpoint from the reachable peer
			if info.P2PEndpoint != "" {
				p.SetP2PEndpoint(info.P2PEndpoint)
			}
			// Peer reported as reachable
			if p.UpdateP2PStatus(p2p.P2PAvailable, "") {
				e.Peers.SetPendingChanges()
			}
		}
	}
	return nil
}

// handleOnlineCheckMessage handles TypeOnlineCheck (12).
// Replies with an Ack to confirm liveness.
func (e *EdgeClient) handleOnlineCheckMessage(r *protocol.RawMessage) error {
	oc, err := protocol.ToMessage[*netstruct.OnlineCheck](r)
	if err != nil {
		return err
	}
	if oc.Msg.IsReply {
		return nil // already a reply, don't echo back
	}
	// Reply with Ack
	ack := &netstruct.Ack{}
	return e.SendStruct(ack, net.HardwareAddr(r.Header.GetSrcMACAddr()), p2p.UDPBestEffort)
}

// handleICECandidateMessage handles TypeICECandidate (14).
// Forwards the ICE candidate to the target peer.
func (e *EdgeClient) handleICECandidateMessage(r *protocol.RawMessage) error {
	ice, err := protocol.ToMessage[*netstruct.ICECandidate](r)
	if err != nil {
		return err
	}
	targetMAC := ice.Msg.TargetMac
	if targetMAC == "" {
		// Fall back to header dst MAC
		targetMAC = r.DestMACAddr()
	}
	if targetMAC == "" {
		return fmt.Errorf("ICECandidate missing target MAC")
	}
	dst, err := net.ParseMAC(targetMAC)
	if err != nil {
		return fmt.Errorf("cannot parse target MAC %s: %w", targetMAC, err)
	}
	return e.SendStruct(ice.Msg, dst, p2p.UDPBestEffort)
}

// handleTURNCredentialsMessage handles TypeTURNCredentials (15).
// Receives and records TURN credentials.
func (e *EdgeClient) handleTURNCredentialsMessage(r *protocol.RawMessage) error {
	turn, err := protocol.ToMessage[*netstruct.TURNCredentials](r)
	if err != nil {
		return err
	}
	log.Printf("received TURN credentials: username=%s ttl=%d uris=%v",
		turn.Msg.Username, turn.Msg.Ttl, turn.Msg.Uris)
	return nil
}

// handleNatHoleInstruction handles a relay-coordinated NAT hole-punching
// instruction. entryMAC is the MAC of the PeerInfoList entry that carried it,
// which is what identifies the intended recipient.
// The instruction is embedded in a PeerInfo message; we extract it and dispatch
// the punch execution to the P2P subsystem.
func (e *EdgeClient) handleNatHoleInstruction(entryMAC string, instr *p2p.NatHoleInstruction) error {
	if instr == nil {
		return nil
	}

	role := instr.GetRole()
	senderNatType := instr.GetSenderNatType()
	senderBehavior := instr.GetSenderBehavior()
	portsDiff := instr.GetPortsDifference()
	regularChange := instr.GetRegularPortsChange()
	portsFrom := instr.GetPortsRangeFrom()
	portsTo := instr.GetPortsRangeTo()
	ttl := instr.GetTtl()
	mode := instr.GetMode()
	behaviorIndex := instr.GetBehaviorIndex()
	sendDelayMs := instr.GetSendDelayMs()
	senderMAC := macBytesToStr(instr.GetSenderMac())
	senderP2PEndpoint := instr.GetSenderP2PEndpoint()
	senderPubSocket := instr.GetSenderPubSocket()

	// The sender's LAN addresses, which this side will try BEFORE the
	// STUN-reflexive senderPubSocket when it is itself the sender. Printed
	// for both roles because the relay hands the same instruction to both,
	// and "present but ignored" otherwise looks like a missing field.
	senderAssisted := instr.GetSenderAssistedEndpoints()
	assistedStr := "<none>"
	if len(senderAssisted) > 0 {
		assistedStr = strings.Join(senderAssisted, ",")
	}

	log.Printf("[Edge] NatHoleInstruction: role=%d senderNatType=%s senderBehavior=%s portsDiff=%d regularChange=%v portsRange=%d-%d ttl=%d senderMAC=%s senderP2P=%s senderPubSocket=%s senderAssisted=[%s] ladder=mode%d/index%d sendDelay=%dms",
		role, senderNatType, senderBehavior, portsDiff, regularChange, portsFrom, portsTo, ttl, senderMAC, senderP2PEndpoint, senderPubSocket, assistedStr, mode, behaviorIndex, sendDelayMs)

	// Determine whether we are the sender or receiver.
	// Use the instruction's role field directly, not a MAC comparison,
	// because the Worker broadcasts the full PeerInfoList to all peers,
	// so another peer's instruction may also reach us. The MAC comparison
	// would incorrectly classify us as the sender when processing a
	// receiver instruction that happens to have senderMac == ourMAC.
	// Verify this instruction is actually addressed to us.
	//
	// The instruction arrives inside one PeerInfoList entry, and
	// handlePeerInfoMessage already dispatches only the entry whose MAC is
	// ours — that entry is the only reliable "this is yours" signal. It is
	// re-asserted here, at the point of use, so the guarantee does not depend
	// on every future caller remembering to filter.
	//
	// The instruction's own fields CANNOT identify the receiver. For a
	// receiver instruction the Worker fills BOTH senderMac and targetMac with
	// the SENDER's MAC (handler.js:184-186): the receiver punches at the
	// sender, so targetMac is the peer whose punch it waits for, and
	// waitForPunchSuccess keys off exactly that. An earlier version of this
	// function tried to identify the receiver by matching targetMac against
	// our MAC, which discarded every legitimate receiver instruction and left
	// the receiver with no punch to run at all.
	ourMAC := e.MACAddr.String()
	if ourMAC == "" {
		return fmt.Errorf("handleNatHoleInstruction: edge has no MAC address")
	}
	if entryMAC != ourMAC {
		log.Printf("[Edge] NatHoleInstruction: entry belongs to %s, not us (%s) — skipping", entryMAC, ourMAC)
		return nil
	}

	var ourRole p2p.NatHoleRole
	if role == p2p.NatHoleRole_DetectRoleSender && senderMAC == ourMAC {
		ourRole = p2p.NatHoleRole_DetectRoleSender
	} else if role == p2p.NatHoleRole_DetectRoleReceiver {
		ourRole = p2p.NatHoleRole_DetectRoleReceiver
	} else {
		log.Printf("[Edge] NatHoleInstruction: role mismatch (instr role=%d, senderMAC=%s, ourMAC=%s) — skipping",
			role, senderMAC, ourMAC)
		return nil
	}

	// The target is always the OTHER peer. The instruction's target_mac
	// field tells us who to punch. For the sender, target = receiver.
	// For the receiver, target = sender (whose P2P endpoint is in the instruction).
	targetMAC := macBytesToStr(instr.GetTargetMac())
	var targetP2PEndpoint string
	var targetPubSocket string

	if ourRole == p2p.NatHoleRole_DetectRoleSender {
		// We are the sender; the target is the receiver.
		// Look up the receiver's P2P endpoint from the registry.
		// Try P2PAvailable peers first (preferred — peer has confirmed P2P connectivity).
		peers := e.Peers.GetP2PAvailablePeers()
		for _, p := range peers {
			if macBytesToStr(p.Infos.MacAddr) == targetMAC {
				targetP2PEndpoint = p.P2PEndpoint
				targetPubSocket = p.Infos.PubSocket
				break
			}
		}
		// Fallback: look up by MAC directly from registry. The Worker
		// broadcasts the full PeerInfoList (with the target's P2P info)
		// before P2P availability is confirmed, causing a race where the
		// target is in the registry but its P2PStatus is still P2PUnknown.
		if targetP2PEndpoint == "" {
			if p, err := e.Peers.GetPeer(targetMAC); err == nil {
				targetP2PEndpoint = p.P2PEndpoint
				targetPubSocket = p.Infos.PubSocket
				log.Printf("NatHoleInstruction: found target %s in registry (P2PStatus=%s) via fallback GetPeer", targetMAC, p.P2PStatus.String())
			}
		}
		if targetP2PEndpoint == "" {
			log.Printf("[Edge] NatHoleInstruction: sender cannot find target %s in P2P registry", targetMAC)
			return nil
		}
	} else {
		// We are the receiver; the target is the sender.
		// The sender's P2P endpoint and pub socket are in the instruction.
		targetP2PEndpoint = senderP2PEndpoint
		targetPubSocket = senderPubSocket
	}

	if targetP2PEndpoint == "" {
		log.Printf("[Edge] NatHoleInstruction: cannot resolve target P2P endpoint for role=%d", ourRole)
		return nil
	}

	// Dispatch the punch execution to the P2P subsystem.
	// The P2P subsystem will open a UDP socket, send/receive punch packets,
	// and call SetFullDuplex when successful.
	e.Peers.SetNatHoleInstruction(macStrToBytes(ourMAC), &p2p.NatHoleInstruction{
		Role:               ourRole,
		TargetMac:          macStrToBytes(targetMAC),
		SenderMac:          macStrToBytes(ourMAC),
		SenderP2PEndpoint:  targetP2PEndpoint,
		SenderPubSocket:    targetPubSocket,
		SenderNatType:      senderNatType,
		SenderBehavior:     senderBehavior,
		PortsDifference:    portsDiff,
		RegularPortsChange: regularChange,
		PortsRangeFrom:     portsFrom,
		PortsRangeTo:       portsTo,
		Ttl:                ttl,
		Mode:               mode,
		BehaviorIndex:      behaviorIndex,
		SendDelayMs:        sendDelayMs,
	})

	return nil
}

func macStrToBytes(mac string) []byte {
	parts := strings.Split(mac, ":")
	b := make([]byte, len(parts))
	for i, p := range parts {
		v, _ := strconv.ParseUint(p, 16, 8)
		b[i] = byte(v)
	}
	return b
}

func macBytesToStr(mac []byte) string {
	return net.HardwareAddr(mac).String()
}
