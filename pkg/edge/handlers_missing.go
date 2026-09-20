package edge

import (
	"fmt"
	"n2n-go/pkg/log"
	"n2n-go/pkg/p2p"
	"n2n-go/pkg/protocol"
	"n2n-go/pkg/protocol/netstruct"
	"net"
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
			// We received P2P info from this peer; mark as reachable
			if p.UpdateP2PStatus(p2p.P2PAvailable, "") {
				e.Peers.SetPendingChanges()
			}
		}
	}

	// Update P2P status for peers listed in the message
	for _, info := range p2pMsg.Msg.To {
		mac := net.HardwareAddr(info.MacAddr).String()
		if p, err := e.Peers.GetPeer(mac); err == nil {
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