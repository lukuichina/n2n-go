package edge

import (
	"fmt"
	"n2n-go/pkg/log"
	"n2n-go/pkg/p2p"
	"n2n-go/pkg/protocol"
	"n2n-go/pkg/protocol/netstruct"
	"n2n-go/pkg/protocol/spec"
	"n2n-go/pkg/transport"
	"n2n-go/pkg/tuntap"
	"net"
	"strings"
	"time"
)

func (e *EdgeClient) UpdatePeersP2PStates() {
	peers := e.Peers.GetP2PUnknownPeers()
	for _, p := range peers {
		// Skip self — prevents self-ping PONG from setting FullDuplex=true on own peer
		if net.HardwareAddr(p.Infos.MacAddr).String() == e.MACAddr.String() {
			continue
		}
		err := e.PingPeer(p, 3, 300*time.Second, p2p.P2PPending)
		if err != nil {
			log.Printf("handleP2PUpdates: error in UpdatePeersP2PStates for peer with MACAddress %s: %v", net.HardwareAddr(p.Infos.MacAddr).String(), err)
		}
	}
	peers = e.Peers.GetP2PendingPeers()
	for _, p := range peers {
		if net.HardwareAddr(p.Infos.MacAddr).String() == e.MACAddr.String() {
			continue
		}
		err := e.PingPeer(p, 3, 300*time.Second, p2p.P2PPending)
		if err != nil {
			log.Printf("handleP2PUpdates: error in UpdatePeersP2PStates for peer with MACAddress %s: %v", net.HardwareAddr(p.Infos.MacAddr).String(), err)
		}
	}
	peers = e.Peers.GetP2PAvailablePeers()
	for _, p := range peers {
		if net.HardwareAddr(p.Infos.MacAddr).String() == e.MACAddr.String() {
			continue
		}
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
		e.SendStruct(pingMsg, net.HardwareAddr(p.Infos.MacAddr), p2p.UDPBestEffort)
	}
	return e.SendStruct(pingMsg, net.HardwareAddr(p.Infos.MacAddr), p2p.UDPBestEffort)
}

// peerListResyncInterval is how often a community with no known peers asks
// the supernode for the peer list again.
//
// Without this the edge only ever asks twice: once at startup ("preliminary"
// in client.go) and once after a successful re-register (handlers.go). If
// either of those snapshots is truncated — e.g. it was taken before the other
// edge finished registering, or the supernode skipped the notification
// because the other WebSocket had not come up yet — the peer is simply
// never learned about, and every packet to it fails forever with
// "peer lookup failed for <mac>". The supernode side treats a peer list as a
// full snapshot and drops every peer missing from it, so a single missed
// notification is enough to leave one side permanently isolated.
//
// Asking on a timer is cheap (one small message per interval) and makes the
// peer table self-healing instead of depending on the supernode to announce
// everyone to everyone exactly once, at exactly the right moment.
const peerListResyncInterval = 30 * time.Second

// handleHeartbeat sends heartbeat messages periodically
func (e *EdgeClient) handleP2PUpdates() {
	e.wg.Add(1)
	defer e.wg.Done()

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	// Separate, slower ticker for the peer-list resync so it survives across
	// the 3s loop without being reset by it.
	resyncTicker := time.NewTicker(peerListResyncInterval)
	defer resyncTicker.Stop()

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
				// Execute relay-coordinated NAT hole punching if an instruction is pending.
				e.executeNatHolePunchLoop()
			}()
		case <-resyncTicker.C:
			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("handleP2PUpdates: peer list resync recovered from panic: %v", r)
					}
				}()
				// Only reach out while we know of nobody else. A populated
				// table means the supernode told us about the community, and
				// spamming requests would be pure overhead.
				if e.Peers.NumPeers() == 0 {
					if err := e.sendPeerListRequest(); err != nil {
						log.Printf("handleP2PUpdates: periodic peer list request failed: %v", err)
					}
				}
			}()
		case <-e.ctx.Done():
			return
		}
	}
}

// executeNatHolePunchLoop checks for pending NAT hole instructions
// and executes them against the P2P UDP connection.
func (e *EdgeClient) executeNatHolePunchLoop() {
	if e.P2PConn == nil {
		return
	}
	if !e.Peers.HasNatHoleInstruction() {
		return
	}
	// STUN is deliberately NOT refreshed here.
	//
	// The STUN client reads from e.P2PConn, the very socket handleP2P is
	// blocked on, and its read loop discards anything that does not decode
	// as a STUN message:
	//
	//     n, _, err := s.conn.ReadFromUDP(buf)   // steals the punch packet
	//     if err := stun.Decode(buf[:n], &respMsg); err != nil {
	//         continue                            // dropped, never re-injected
	//     }
	//
	// So a refresh here swallows the peer's incoming hole-punch packets for
	// the whole discovery window (3 servers x 5s timeout ~= 15s), while we
	// punch every ~3s. The punch could essentially never be observed.
	//
	// FRP avoids this by design: nathole.Prepare() does its single STUN
	// transaction before the punch loop starts, leaving the punch loop as
	// the socket's only reader. We mirror that: STUN runs at registration
	// time (InitialSetup -> pubSocketString) and is then left alone, so
	// handleP2P owns the socket.
	//
	// The NAT mapping stays valid because the punch packets themselves are
	// sent from this same socket, keeping its outbound binding alive.
	//
	// Send NAT hole punch packets via direct UDP.
	// In environments where inter-VM UDP is not routable (e.g., behind
	// Cloudflare Tunnel), the Worker's handlePing forwarding (fixed
	// separately) handles P2P discovery via WebSocket instead.
	//
	// Run it off the caller's goroutine. The punch now ends with a long wait
	// (FRP's ReadTimeoutMs), and this function is invoked from the 3s
	// state-update ticker; blocking here would stall UpdatePeersP2PStates
	// for the whole wait. The in-flight guard keeps a slow round from
	// stacking up a second and third concurrent punch against the same
	// instruction.
	if e.natHolePunching.CompareAndSwap(false, true) {
		go func() {
			defer e.natHolePunching.Store(false)
			// Bound the attribution window to this instruction: while it
			// runs, a punch from an address we cannot match may still be
			// this named peer behind a rewriting router.
			e.setExpectedPunchPeerMAC(e.Peers.ExpectedPunchPeerMAC())
			defer e.setExpectedPunchPeerMAC("")
			e.Peers.ExecuteNatHolePunch(e.P2PConn)
			// FRP writes real data immediately after the punch rather than
			// waiting for the next user packet. With no user data queued
			// here, the verification probe plays that role.
			//
			// Deliberately NOT gated on the punch's return value: that value
			// is true only when the peer is already FullDuplex, and promotion
			// is itself gated on receiving a data frame that only this probe
			// sends. Gating the probe on it left the two conditions
			// permanently unsatisfiable — punch traffic flowed fine (hundreds
			// of packets exchanged) while FullDuplex was never reached.
			for _, p := range e.Peers.GetPunchedNotFullDuplexPeers() {
				e.sendPathVerificationProbe(p)
			}
		}()
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

// handleP2PKeepAlive keeps the NAT mapping for every FullDuplex peer open,
// and demotes peers that stop answering so the failure actually propagates.
//
// Why this is needed: a UDP NAT mapping dies when nothing is sent through it.
// Once ours expired, the peer could no longer reach us — its ARP replies went
// out over P2P and were dropped by the gateway, our ARP entry went INCOMPLETE,
// and the tunnel was unusable while still reporting FullDuplex.
//
// FRP's equivalent has two halves, and both are mirrored here:
//
//  1. yamux keepalive, 10s (client/visitor/xtcp.go:351). A ping is sent and
//     the pong is awaited; a missing pong calls exitErr(ErrKeepAliveTimeout)
//     and tears the session down (yamux session.go keepalive()/Ping()).
//     Here the ping is a real PeerToPing, and the "pong" is any inbound frame
//     from that peer, recorded by NoteDataPacket in handleP2P.
//
//  2. keepTunnelOpenWorker, every MinRetryInterval=90s
//     (client/visitor/xtcp.go:114). A failed probe re-runs makeNatHole().
//     Here a timed-out peer is demoted off FullDuplex and its NAT hole
//     instruction is re-armed, so executeNatHolePunchLoop retries it.
//
// The two differ from FRP in one way worth noting: FRP can afford a 90s
// health interval because KCP retransmits underneath and holds the mapping
// open (pkg/util/net/kcp.go:96, NewConn3(1, udpAddr, nil, 10, 3, pConn)).
// We have no lower layer, so the probe interval is the only thing keeping the
// mapping alive and must stay well under the gateway's idle timeout.
func (e *EdgeClient) handleP2PKeepAlive() {
	e.wg.Add(1)
	defer e.wg.Done()

	interval := e.keepAliveInterval
	if interval <= 0 {
		return
	}
	timeout := e.keepAliveTimeout
	if timeout <= interval {
		// A timeout at or below the interval would tear the tunnel down on
		// the first lost probe, which is far too twitchy for a path that
		// still has a working NAT mapping.
		timeout = 3 * interval
		log.Printf("[P2P] keepalive timeout %v <= interval %v, raising to %v", e.keepAliveTimeout, interval, timeout)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("[P2P] keepalive recovered from panic: %v", r)
					}
				}()
				e.p2pKeepAliveTick(timeout)
			}()
		case <-e.ctx.Done():
			return
		}
	}
}

// p2pKeepAliveTick sends one probe to each FullDuplex peer and demotes the
// ones that have been silent for longer than timeout.
func (e *EdgeClient) p2pKeepAliveTick(timeout time.Duration) {
	self := e.MACAddr.String()
	now := time.Now()

	// Send first, then judge: a peer that just came up would otherwise be
	// demoted by a stale LastDataSeenAt before its first reply landed.
	for _, p := range e.Peers.GetFullDuplexPeers() {
		macStr := net.HardwareAddr(p.Infos.MacAddr).String()
		if macStr == self {
			continue
		}
		// UDPBestEffort routes over P2P while the peer is FullDuplex, so
		// this both keeps our mapping open and gives the peer a reason to
		// answer, which keeps theirs open.
		//
		// Deliberately NOT PingPeer(): that also calls UpdateP2PStatus, and
		// UpdateP2PStatus's "pendingTTL < 1" branch force-sets
		// P2PUnavailable, which would knock a perfectly healthy peer off
		// FullDuplex on the first tick whose pendingTTL had drained. The
		// keepalive must not mutate the state it is measuring.
		e.sendKeepAlivePing(p)
		e.sendPathVerificationProbe(p)
	}

	// Peers that were punched but never promoted need the same probe on a
	// timer. The post-punch probe fires once, immediately after
	// ExecuteNatHolePunch returns — but at that moment the peer's socket
	// has only just been opened by the punch, so the probe is routinely
	// dropped and nothing retries it. Without this loop those peers sit
	// un-promoted forever even though punches are flowing (observed: 522
	// punch packets received, zero data frames). Retrying every keepalive
	// interval converges as soon as the path is genuinely open.
	for _, p := range e.Peers.GetPunchedNotFullDuplexPeers() {
		macStr := net.HardwareAddr(p.Infos.MacAddr).String()
		if macStr == self {
			continue
		}
		e.sendPathVerificationProbe(p)
	}

	for _, p := range e.Peers.GetFullDuplexPeers() {
		macStr := net.HardwareAddr(p.Infos.MacAddr).String()
		if macStr == self {
			continue
		}
		last := p.LastDataSeenAt()
		if last.IsZero() || now.Sub(last) < timeout {
			continue
		}
		log.Printf("[P2P] keepalive timeout: no frame from %s for %v, demoting FullDuplex -> relay",
			macStr, now.Sub(last).Truncate(time.Second))
		if changed, _ := p.SetFullDuplex(false); changed {
			// Re-arm the punch so the next tick retries instead of leaving
			// the peer stuck on the relay forever.
			e.Peers.ReArmNatHoleInstruction(p.Infos.MacAddr)
			e.Peers.SetPendingChanges()
		}
	}
}

// sendKeepAlivePing sends one liveness ping to a peer without touching its
// P2P state.
//
// It is the data-path analogue of yamux's keepalive ping (FRP
// client/visitor/xtcp.go:351 -> yamux session.go:363). The pong is not
// matched by checkID here: any inbound frame from the peer is accepted as
// proof of life, which handleP2P records via NoteDataPacket. That is looser
// than yamux, which awaits a specific pong, but it matches what we can
// observe without tracking every outstanding checkID, and it is still
// strictly stronger than a punch — a punch is generated by our own outbound
// traffic and proves nothing about the inbound path.
func (e *EdgeClient) sendKeepAlivePing(p *p2p.Peer) {
	checkid := fmt.Sprintf("ka.%s.%s.%d", e.ID, net.HardwareAddr(p.Infos.MacAddr).String(), time.Now().UnixNano())
	pingMsg := &netstruct.PeerToPing{
		IsPong:  false,
		CheckId: checkid,
	}
	if err := e.SendStruct(pingMsg, net.HardwareAddr(p.Infos.MacAddr), p2p.UDPBestEffort); err != nil {
		log.Printf("[P2P] keepalive ping to %s failed: %v", net.HardwareAddr(p.Infos.MacAddr).String(), err)
	}
}

// sendPathVerificationProbe actively proves the direct data path works, for
// peers that have been punched but not yet promoted to FullDuplex.
//
// Why this is necessary: promotion to FullDuplex is gated on having seen a
// real data frame, but data is only ever routed over P2P when the peer is
// ALREADY FullDuplex (wire.go UDPAddrWithStrategy: UDPBestEffort takes the
// direct path only on P2PFullDuplex). Gating promotion on data therefore
// deadlocks — nothing sends P2P data until promotion, and nothing is promoted
// until P2P data arrives. Punches kept "succeeding" while no promotion ever
// happened.
//
// FRP does not have this problem because after punching it immediately writes
// real user data through the tunnel, which both proves the path and promotes
// the session. There is no user data to write at punch time here (the TAP has
// nothing queued), so this sends the smallest real ProtoV frame that will do:
// a ping, forced over P2P with UDPEnforceP2P, which bypasses the
// status check. The peer's pong comes back over P2P, is recorded by
// handleP2P via NoteDataPacket, and promotes both sides — on each side
// independently, since each only promotes on frames it actually received.
func (e *EdgeClient) sendPathVerificationProbe(p *p2p.Peer) {
	if p.P2PStatus == p2p.P2PFullDuplex && p.IsFullDuplex {
		return // already promoted; the keepalive ping is enough
	}
	if p.GetP2PRaddr() == "" && p.UDPAddr() == nil {
		return // no known address to probe
	}
	checkid := fmt.Sprintf("vp.%s.%s.%d", e.ID, net.HardwareAddr(p.Infos.MacAddr).String(), time.Now().UnixNano())
	pingMsg := &netstruct.PeerToPing{
		IsPong:  false,
		CheckId: checkid,
	}
	if err := e.SendStruct(pingMsg, net.HardwareAddr(p.Infos.MacAddr), p2p.UDPEnforceP2P); err != nil {
		log.Printf("[P2P] path verification probe to %s failed: %v", net.HardwareAddr(p.Infos.MacAddr).String(), err)
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
			// Avoid tight busy-loop on persistent read errors (e.g.
			// "not pollable" when the TAP device is in a bad state).
			// Back off before retrying so the process does not peg CPU at 100%.
			log.Printf("TAP read error: %v (handle=%v) — backing off", err, e.TAP.Iface.GetHandle())
			time.Sleep(200 * time.Millisecond)
			continue
		}

		if n == 0 {
			// Poll timeout with no data — loop around to check ctx.Done()
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

// handlePunchDatagram processes an inbound hole-punch datagram — a punch or an
// ACK — that arrived on one of this edge's UDP sockets.
//
// It is the single implementation behind both handleP2P (WSS mode, dedicated
// P2P socket) and handleUDP (plain UDP mode). Those two paths used to carry
// near-duplicate copies of this logic, which is how the ACK echo loop below went
// unnoticed: the classification was "first four bytes are the punch magic", so
// an ACK was indistinguishable from a punch and BOTH edges answered every ACK
// with another ACK. Each datagram produced exactly one reply, making a
// self-sustaining loop at 1/RTT (~90 pkt/s at the measured 23.7ms E1<->E2 RTT)
// that only died when UDP happened to drop a datagram — the loop has no
// independent driver. E2 logged 7 four-byte punches against 558 eight-byte ACKs.
//
// Two rules keep it one-directional:
//
//  1. Answer a punch, never an ACK. The ACK already carries the confirmation
//     its sender is waiting for, so re-answering it is pure amplification.
//  2. Rate-limit both the reply and the state we publish about the peer, so a
//     misbehaving or older peer cannot turn punch traffic into a packet storm
//     or into a stream of PeerP2PInfos updates to the supernode.
func (e *EdgeClient) handlePunchDatagram(n int, addr *net.UDPAddr, buf []byte) {
	now := time.Now()
	isAck := p2p.IsPunchAck(buf, n)

	// The peer is looked up before answering, because the per-peer rate limit
	// lives on the peer. Under a NAT the observed source port is the only
	// address the peer can actually be reached at, so it is also the only
	// useful fallback when the published pubSocket has gone stale.
	p, err := e.Peers.GetPeerBySocket(addr)
	if err != nil {
		// Fallback: match by IP only (Symmetric NAT may hand the peer a
		// different port per destination, so the socket match can miss).
		p, err = e.Peers.GetPeerBySocketIP(addr.IP)
	}
	if err != nil {
		// Unknown peer: still answer a genuine punch — it is how a peer that
		// just came back with a new NAT port proves it is reachable — but
		// never answer an ACK, do not fabricate state for an unknown peer, and
		// rate-limit the reply so the four public magic bytes cannot be used
		// to drive a reflection amplifier.
		if !p2p.ShouldAnswerPunch(buf, n) {
			log.Printf("[P2P] Ignoring punch ACK from unknown peer at %v", addr)
			return
		}
		// Before giving up, check whether we are mid-instruction with a peer
		// the supernode named. A router that forwards the punch and rewrites
		// the source address produces a source neither side ever advertised,
		// so both lookups above miss -- and the path then dies even though
		// the packets are demonstrably arriving. Attributing it to the peer
		// the instruction already names records a fact about a peer known to
		// exist; it is not the fabrication the branch above is guarding
		// against, and the window closes with the instruction.
		if mac := e.loadExpectedPunchPeerMAC(); mac != "" {
			if named, nerr := e.Peers.GetPeer(mac); nerr == nil && named != nil {
				log.Printf("[P2P] Punch packet from %v attributed to instruction peer %s (source address was rewritten in transit)", addr, mac)
				if named.AllowPunchAck(now) {
					e.sendPunchAck(addr)
				}
				named.NotePunchPacket()
				named.SetP2PRaddr(addr.String())
				e.Peers.IndexPeerRaddr(named, addr.String())
				return
			}
		}
		if e.allowUnknownPunchAck(addr.String(), now) {
			log.Printf("[P2P] Punch packet from unknown peer at %v — answering once", addr)
			e.sendPunchAck(addr)
		}
		return
	}

	mac := net.HardwareAddr(p.Infos.MacAddr).String()

	if isAck {
		// An ACK is evidence that the peer's socket is reachable, and that is
		// worth recording — it is what unblocks waitForPunchSuccess. It is
		// never worth answering.
		p.NotePunchPacket()
	} else {
		if p.AllowPunchAck(now) {
			log.Printf("[P2P] Punch packet received from %v (peer %s)", addr, mac)
			e.sendPunchAck(addr)
		}
		p.NotePunchPacket()
	}

	// The observed source address is the peer's real raddr, exactly like FRP's
	// raddr. Under Symmetric NAT it differs from the STUN-derived pubSocket
	// (the NAT assigns a different port per destination), and UDPAddrWithStrategy
	// must target it. This is also what lets a restarted peer — whose NAT port
	// has changed — be re-learned without a supernode round trip.
	p.SetP2PRaddr(addr.String())
	e.Peers.IndexPeerRaddr(p, addr.String())

	if !p.AllowPunchPublish(now) {
		// State is already current for this peer; skip the supernode-facing
		// work. NotePunchPacket/SetP2PRaddr above are cheap and idempotent,
		// so liveness tracking stays accurate at full packet rate.
		return
	}

	if changed, ferr := p.SetFullDuplex(true); changed {
		// SetFullDuplex refuses to promote on punch evidence alone, so
		// reaching here means some data path has already been verified for
		// this peer. The wording matters: an operator reading "punch
		// evidence" here would reasonably conclude the hole is enough, which
		// is precisely the assumption that caused the outage.
		log.Printf("[P2P] FullDuplex established with %s (punch from %v, data path already verified)", mac, addr)
		e.Peers.SetPendingChanges()
	} else if ferr != nil {
		log.Printf("[P2P] punch from %s could not set FullDuplex: %v", mac, ferr)
	}

	// A punch packet proves the hole is open, not that the tunnel carries
	// data. Under this NAT pair the two routinely diverge: a restarted peer
	// re-punches cleanly, the relay records a success, and the path still
	// never comes up because P2PRaddr is the only thing that can fill it and
	// nothing is flowing yet. On 2026-09-29 that cost a five-minute outage
	// after each edge restart.
	//
	// So report the round as still in progress and let the data-frame path
	// below be the only thing that claims success. The relay suppresses a
	// pair the moment it sees Succeeded, so claiming it on punch evidence
	// alone is what strands the pair.
	if p.IsFullDuplex && p.HasVerifiedDataPath() {
		e.Peers.RecordNatHolePunchResult(
			mac,
			p2p.NatHolePunchState_PunchStateSucceeded, 1,
			fmt.Sprintf("punch %s observed from %s", map[bool]string{true: "ACK", false: "packet"}[isAck], addr),
			e.Peers.CurrentNatHoleBehaviorIndex(mac))
	} else {
		e.Peers.RecordNatHolePunchResult(
			mac,
			p2p.NatHolePunchState_PunchStateInProgress, 1,
			fmt.Sprintf("punch %s observed from %s, data path not yet verified",
				map[bool]string{true: "ACK", false: "packet"}[isAck], addr),
			e.Peers.CurrentNatHoleBehaviorIndex(mac))
	}
	// Tell the relay the round advanced, otherwise it keeps pushing fresh
	// instructions at an already-established tunnel.
	e.Peers.SetPendingChanges()
}

// setExpectedPunchPeerMAC / loadExpectedPunchPeerMAC guard the attribution
// window, which is written on the punch goroutine and read on the packet
// reader goroutine.
func (e *EdgeClient) setExpectedPunchPeerMAC(mac string) {
	e.expectedPunchPeerMACMu.Lock()
	e.expectedPunchPeerMAC = mac
	e.expectedPunchPeerMACMu.Unlock()
}

func (e *EdgeClient) loadExpectedPunchPeerMAC() string {
	e.expectedPunchPeerMACMu.RLock()
	mac := e.expectedPunchPeerMAC
	e.expectedPunchPeerMACMu.RUnlock()
	return mac
}

// allowUnknownPunchAck rate-limits ACK replies to sources that match no known
// peer, keyed by source address. The map is pruned whenever it grows past a
// small bound, so a spoofed flood cannot make it grow without limit.
func (e *EdgeClient) allowUnknownPunchAck(addr string, now time.Time) bool {
	const maxTracked = 64
	e.unknownPunchAckMu.Lock()
	defer e.unknownPunchAckMu.Unlock()
	if e.unknownPunchAck == nil {
		e.unknownPunchAck = make(map[string]time.Time)
	}
	if last, ok := e.unknownPunchAck[addr]; ok && now.Sub(last) < time.Second {
		return false
	}
	e.unknownPunchAck[addr] = now
	if len(e.unknownPunchAck) > maxTracked {
		for k, t := range e.unknownPunchAck {
			if now.Sub(t) > 10*time.Second {
				delete(e.unknownPunchAck, k)
			}
		}
	}
	return true
}

// sendPunchAck answers a punch on the socket the punch arrived on, replying to
// the observed source address rather than the STUN-discovered pubSocket — the
// FRP waitDetectMessage behaviour. Replying to the source address is what
// works when the cloud NAT has no UDP port forwarding: the NAT's conntrack
// already permits return traffic for the peer's outbound flow.
func (e *EdgeClient) sendPunchAck(addr *net.UDPAddr) {
	punchAck := p2p.PunchAckBytes()
	if e.P2PConn != nil && e.P2PConn != e.Conn {
		if _, err := e.P2PConn.WriteToUDP(punchAck, addr); err != nil {
			log.Printf("[P2P] Failed to send punch ACK to %v: %v", addr, err)
		} else {
			log.Printf("[P2P] Sent punch ACK to source %v", addr)
		}
		return
	}
	if e.Conn != nil {
		if _, err := e.Conn.WriteToUDP(punchAck, addr); err != nil {
			log.Printf("[P2P] Failed to send punch ACK to %v: %v", addr, err)
		} else {
			log.Printf("[P2P] Sent punch ACK to source %v", addr)
		}
		return
	}
	if e.WSSTransport != nil {
		if _, err := e.WSSTransport.Write(punchAck, addr); err != nil {
			log.Printf("[P2P] Failed to send punch ACK via WSS to %v: %v", addr, err)
		} else {
			log.Printf("[P2P] Sent punch ACK via WSS to %v", addr)
		}
	}
}

// handleP2P reads packets from the dedicated P2P UDP socket (used in WSS mode where
// the supernode connection is over WebSocket and a separate UDP socket is needed for
// peer-to-peer hole-punching). In UDP mode, handleUDP already reads from the shared socket.
func (e *EdgeClient) handleP2P() {
	if e.P2PConn == nil || e.P2PConn == e.Conn {
		return
	}
	e.wg.Add(1)
	defer e.wg.Done()

	log.Printf("Starting P2P UDP packet handler on %s", e.P2PAddr)

	packetBuf := e.packetBufPool.Get()
	defer e.packetBufPool.Put(packetBuf)

	for {
		select {
		case <-e.ctx.Done():
			return
		default:
		}
		n, addr, err := e.P2PConn.ReadFromUDP(packetBuf)
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			log.Printf("P2P UDP read error: %v", err)
			continue
		}

		e.PacketsRecv.Add(1)
		// Punch traffic is logged (throttled) inside handlePunchDatagram; logging
		// every datagram here is what buried the real events during the ACK echo loop.
		if !p2p.IsPunch(packetBuf, n) {
			log.Printf("[P2P-DEBUG] raw recv %d bytes from %v, first byte=0x%02x", n, addr, packetBuf[0])
		}
		if p2p.IsPunch(packetBuf, n) {
			// Punch/ACK traffic is handled in one shared place so handleP2P and
			// handleUDP cannot drift apart again.
			e.handlePunchDatagram(n, addr, packetBuf)
			continue
		}
		if packetBuf[0] == protocol.VersionVFuze {
			udpAddr := addr
			err = e.handleVFuzePacket(packetBuf, n, udpAddr)
			if err != nil {
				if strings.Contains(err.Error(), "file already closed") {
					return
				}
				log.Printf("P2P handleVFuzePacket Error: %v", err)
			}
			continue
		}

		if n < protocol.ProtoVHeaderSize {
			log.Printf("P2P: received packet too short from %v: %q", addr, string(packetBuf[:n]))
			continue
		}

		rawMsg, err := protocol.NewRawMessage(packetBuf[:n], addr)
		if err != nil {
			log.Printf("P2P: error while parsing UDP Packet: %v", err)
			continue
		}

		// A well-formed ProtoV frame arriving on the P2P socket is the only
		// proof we accept that the direct data path actually carries traffic.
		// Record it and let it (not a punch) promote the peer to FullDuplex.
		if rawMsg.Header != nil {
			if p, perr := e.Peers.GetPeerBySocket(addr); perr == nil {
				// Learn the peer's raddr from the same observation that proves
				// the direct path works.
				//
				// addr here comes from P2PConn.ReadFromUDP, so it is the real
				// NAT-mapped source the peer punched from -- the same fact
				// routines.go:620 records on the punch path, and the only place
				// it can be learned at all: the WSS path's addr is the relay's
				// own address (routines.go:1041 passes conn.RemoteAddr()
				// through), so handleDataMessage's GetPeerBySocket there never
				// matches a peer and never writes raddr.
				//
				// Without this the pair deadlocks. FullDuplex is reached here,
				// but wire.go:69 refuses the direct path until GetP2PRaddr() is
				// non-empty, so every packet falls back to the relay, so the
				// peer never receives a direct frame from us, so neither side
				// can fill the other's raddr. Observed 2026-09-30 with E1/E2:
				// E2 sat at P2PStatus=FullDuplex with P2PRaddr empty and logged
				// "FullDuplex but no verified raddr, falling back to WSS relay"
				// per packet, indefinitely, while its data still arrived over
				// the relay.
				//
				// This does not weaken the gate. It still requires
				// GetPeerBySocket to succeed, and SetFullDuplex below still
				// requires a real data frame -- raddr and FullDuplex remain two
				// readings of one observation rather than two independent ones.
				p.SetP2PRaddr(addr.String())
				e.Peers.IndexPeerRaddr(p, addr.String())
				p.NoteDataPacket()
				if changed, _ := p.SetFullDuplex(true); changed {
					mac := net.HardwareAddr(p.Infos.MacAddr).String()
					log.Printf("[P2P] FullDuplex established with %s (verified by real data frame from %v)",
						mac, addr)
					// Report the success to the relay. This is the
					// authoritative path: SetFullDuplex only promotes once a
					// real data frame has been verified, so reaching here
					// means the tunnel is genuinely up.
					//
					// Without this the relay never learns the round
					// succeeded. It only ever sees the InProgress/Failed
					// reports written by ExecuteNatHolePunch, so it keeps
					// re-issuing NatHoleInstruction for a pair that is
					// already connected -- observed as instructions every
					// 5 minutes (the 300s backoff cap) long after FullDuplex.
					//
					// The punch-packet path above reports too, but the two
					// never both fire: each keys off the same SetFullDuplex
					// transition, and `changed` is true only on the first.
					// Reporting from both would credit the behaviour ladder
					// twice for one round.
					e.Peers.RecordNatHolePunchResult(
						mac,
						p2p.NatHolePunchState_PunchStateSucceeded, 1,
						fmt.Sprintf("verified by real data frame from %s", addr),
						e.Peers.CurrentNatHoleBehaviorIndex(mac))
				}
			}
		}

		err = e.messageHandlers.Handle(rawMsg)
		if err != nil {
			if strings.Contains(err.Error(), "file already closed") {
				return
			}
			log.Printf("P2P: Error from messageHandler: %v", err)
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
		// Punch traffic is logged (throttled) inside handlePunchDatagram; logging
		// every datagram here is what buried the real events during the ACK echo loop.
		if !p2p.IsPunch(packetBuf, n) {
			log.Printf("[P2P-DEBUG] raw recv %d bytes from %v, first byte=0x%02x", n, addr, packetBuf[0])
		}
		if p2p.IsPunch(packetBuf, n) {
			// Punch/ACK traffic is handled in one shared place so handleP2P and
			// handleUDP cannot drift apart again.
			e.handlePunchDatagram(n, addr, packetBuf)
			continue
		}
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

		// Set a read deadline to detect half-open/disconnected WebSocket
		// connections (e.g. when the supernode/Worker hot-reloads and
		// drops the connection without sending a close frame).
		e.WSSTransport.SetReadDeadline(time.Now().Add(120 * time.Second))

		n, addr, err := e.WSSTransport.Read(packetBuf)
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Printf("WSS read deadline exceeded (20s) — connection likely dead, reconnecting...")
			} else {
				log.Printf("WSS read error: %v", err)
			}
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
		log.Printf("[P2P-DEBUG] raw recv %d bytes from %v, first byte=0x%02x", n, addr, packetBuf[0])

		// FRP-style fix: ONLY process punch packets that arrive via direct P2P UDP
		// (handleP2P), because WSSTransport.Read returns the Worker's address
		// (conn.RemoteAddr()), NOT the sender's NAT-mapped raddr. The Worker
		// (Cloudflare Worker) does NOT forward raw punch packets (0xFF...) —
		// it only forwards ProtoV (0x05) and VFuze (0x51) messages, so punch
		// packets arriving here would have the wrong addr anyway.
		// The handleP2P loop (which uses P2PConn.ReadFromUDP) correctly
		// receives punch packets with the true raddr and handles them.

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
		log.Printf("WSS: parsed protoV msg type=%d srcMAC=%s dstMAC=%s payloadLen=%d",
			rawMsg.Header.PacketType,
			rawMsg.Header.GetSrcMACAddr(),
			rawMsg.Header.GetDstMACAddr(),
			len(rawMsg.Payload))

		err = e.messageHandlers.Handle(rawMsg)
		if err != nil {
			if strings.Contains(err.Error(), "file already closed") {
				return
			}
			log.Printf("Error from WSS messageHandler: %v", err)
		}
	}
}
