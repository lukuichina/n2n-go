package p2p

import (
	"fmt"
	"n2n-go/pkg/log"
	"net"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
)

type UDPWriteStrategy uint8

const (
	UDPEnforceSupernode UDPWriteStrategy = 0 //enforce relaying packet through supernode (e.g. for SUPER directed control messages)
	UDPBestEffort       UDPWriteStrategy = 1 //will send to Peer Socket if Peerlist Checked P2PAvailable
	UDPEnforceP2P       UDPWriteStrategy = 2 //will enforce PeerSocket whatever the state (e.g. for P2PAvailability check routine)
)

type P2PCapacity uint8

const (
	P2PUnknown     P2PCapacity = 0
	P2PPending     P2PCapacity = 1
	P2PAvailable   P2PCapacity = 2
	P2PFullDuplex  P2PCapacity = 3
	P2PUnavailable P2PCapacity = 4
)

func (pt P2PCapacity) String() string {
	switch pt {
	case P2PUnknown:
		return "Unknown"
	case P2PPending:
		return "Pending"
	case P2PAvailable:
		return "Available"
	case P2PUnavailable:
		return "Unavailable"
	case P2PFullDuplex:
		return "FullDuplex"
	default:
		return "Unknown"
	}
}

type P2PCommunityDatas struct {
	Reachables   map[string]*PeerP2PInfos
	UnReachables map[string]*PeerCachedInfo
}

type Peer struct {
	Infos           PeerInfo
	P2PStatus       P2PCapacity
	IsFullDuplex    bool
	P2PCheckID      string
	pendingTTL      int
	UpdatedAt       time.Time
	P2PEndpoint     string
	P2PCapabilities []string
	// NatHoleExecuted marks whether this peer has already executed the
	// relay-coordinated NAT hole-punching instruction.
	NatHoleExecuted bool
	// P2PRaddr stores the NAT-mapped source address observed by this edge
	// when receiving punch/ACK packets from the peer. This is the "raddr"
	// equivalent in FRP — the actual address through which the peer can
	// be reached (accounting for Symmetric NAT port remapping), which may
	// differ from the STUN-discovered pubSocket.
	P2PRaddr string

	// punchSeenAt is when we last received a punch/ACK packet from this
	// peer, and dataSeenAt when we last received a real ProtoV data frame
	// from it over the P2P socket. They are kept separately because a
	// 4-byte punch is NOT evidence that the data path works: it is small,
	// it is sent repeatedly, and sending it refreshes the NAT mapping that
	// lets it through. A dead data path therefore still "succeeds" at
	// punching, which is exactly how this peer ended up stuck reporting
	// FullDuplex over a tunnel where nothing but punches could pass.
	//
	// FRP draws the same line: its yamux keepalive (10s) sends a ping and
	// waits for the pong, and a missing pong tears the session down
	// (yamux session.go keepalive()/Ping()). Only that round trip counts as
	// proof of life.
	punchSeenAt time.Time
	dataSeenAt  time.Time

	// punchAckMu guards lastAckSentAt and lastPunchPublishedAt, which bound
	// how often we answer a punch and how often inbound punch traffic may
	// refresh the state we publish about this peer. See punch.go: without
	// them a punch burst turns into an ACK echo loop and supernode churn.
	punchAckMu           sync.Mutex
	lastAckSentAt        time.Time
	lastPunchPublishedAt time.Time

	// promoteDenyLogged/promoteDenyAt rate-limit the "not promoting" log,
	// which otherwise fires once per inbound punch packet.
	promoteDenyMu       sync.Mutex
	promoteDeniedLogged bool
	promoteDenyAt       time.Time

	// routeDbgMu guards routeDbgKey/routeDbgAt, used to collapse the
	// per-packet routing log in edge/wire.go down to one line per actual
	// change of routing decision.
	routeDbgMu  sync.Mutex
	routeDbgKey string
	routeDbgAt  time.Time
}

// routeDbgReLogInterval is how often an unchanged routing decision is still
// re-logged, so a long-lived tunnel doesn't go completely silent.
const routeDbgReLogInterval = 5 * time.Minute

// promoteDenyReLogInterval is how often a still-unpromoted peer is re-logged
// by the SetFullDuplex promotion gate.
const promoteDenyReLogInterval = 30 * time.Second

// LogRouteDecision emits one [P2P-DEBUG] line describing how packets to this
// peer are currently being routed.
//
// UDPAddrWithStrategy runs for EVERY packet sent to a peer, so logging
// unconditionally produced ~8 lines per 3s per peer from nothing but the
// liveness ping/pong pair (PingPeer sends n+1 pings, each answered by a pong),
// which buried the real state transitions in noise. Log only when the
// decision actually changes, plus a periodic re-log so a long-running
// decision stays visible.
func (p *Peer) LogRouteDecision(strategy string, udpSocket *net.UDPAddr, isP2P bool) {
	target := "<supernode>"
	if udpSocket != nil {
		target = udpSocket.String()
	}
	path := "relay"
	if isP2P {
		path = "p2p"
	}
	key := fmt.Sprintf("%s|%s|%s|%s", p.P2PStatus.String(), p.P2PRaddr, p.UDPAddr(), path)

	p.routeDbgMu.Lock()
	changed := key != p.routeDbgKey
	due := time.Since(p.routeDbgAt) >= routeDbgReLogInterval
	if changed || due {
		p.routeDbgKey = key
		p.routeDbgAt = time.Now()
	}
	p.routeDbgMu.Unlock()

	if changed || due {
		log.Printf("[P2P-DEBUG] route to %s: P2PStatus=%s P2PRaddr=%s pubSocket=%s strat=%s via %s (%s)",
			net.HardwareAddr(p.Infos.MacAddr).String(), p.P2PStatus, p.P2PRaddr, p.UDPAddr(), strategy, path, target)
	}
}

// SetP2PEndpoint updates the peer's P2P endpoint address (e.g. "host:port").
func (p *Peer) SetP2PEndpoint(endpoint string) {
	p.P2PEndpoint = endpoint
}

// SetP2PCapabilities updates the peer's P2P capability list.
func (p *Peer) SetP2PCapabilities(caps []string) {
	p.P2PCapabilities = caps
}

// SetP2PRaddr stores the NAT-mapped source address observed when receiving
// packets from this peer. This is the actual reachable address under
// Symmetric NAT (where the STUN-discovered port may differ).
func (p *Peer) SetP2PRaddr(addr string) {
	p.P2PRaddr = addr
}

// NotePunchPacket records that a punch/ACK arrived from this peer.
//
// It deliberately does NOT promote the peer to FullDuplex. See the comment on
// punchSeenAt/dataSeenAt: a punch alone is not proof the data path works.
func (p *Peer) NotePunchPacket() {
	p.punchSeenAt = time.Now()
}

// NoteDataPacket records that a real ProtoV frame arrived from this peer over
// the P2P UDP socket. This is the only evidence that promotes FullDuplex.
func (p *Peer) NoteDataPacket() {
	p.dataSeenAt = time.Now()
}

// LastDataSeenAt returns when a real data frame was last received from this
// peer over P2P (zero time if never).
func (p *Peer) LastDataSeenAt() time.Time {
	return p.dataSeenAt
}

// HasVerifiedDataPath reports whether a real data frame has ever been
// received from this peer over the P2P socket. Used as the promotion gate.
func (p *Peer) HasVerifiedDataPath() bool {
	return !p.dataSeenAt.IsZero()
}

func (p *Peer) resetPendingTTL() {
	p.pendingTTL = 30
}

type PeerRegistry struct {
	CommunityName string
	// SelfTapName is this host's own n2n tap interface (config TapName,
	// e.g. "n2n_tap0").
	//
	// It is needed because the tap carries an address inside the overlay
	// network, and *the peer has one in the same subnet*. Two consequences,
	// both of which are self-reference bugs if ignored:
	//
	//  1. Advertising it would tell the peer to punch an address that
	//     resolves back to the overlay, not to a direct path.
	//  2. Scoring it as "same subnet" would rank it as highly as the real
	//     LAN -- both are /24 -- so the sort would actively promote it
	//     ahead of the address that can actually connect.
	//
	// Filtering by interface identity rather than by a hardcoded CIDR is
	// deliberate: the overlay network is derived from the community hash
	// over a configurable base+mask (see supernode.NetworkAllocator), so
	// the range is 100.64.0.0/10 in some deployments and 10.171.51.0/24 in
	// others. A constant would go quietly stale.
	SelfTapName     string
	peerMu          sync.RWMutex
	Me              *Peer
	Peers           map[string]*Peer //keyed by MACAddr.String()
	peerBySocket    map[string]*Peer // keyed by net.UDPAddr.String()
	peerByP2PSocket map[string]*Peer // keyed by P2PEndpoint string
	p2pDatasMu      sync.RWMutex
	P2PCommunityDatas
	IsWaitingCommunityDatas bool
	hasPendingChanges       bool
	// NatHole instructions pending execution (keyed by our MAC).
	natHoleInstrs map[string]*NatHoleInstruction
	// Retry counts for NAT hole instructions (keyed by our MAC).
	// Allows multiple punch attempts before giving up.
	natHoleRetryCounts map[string]int
	// lastNatHoleInstrs keeps the most recent instruction per PEER MAC after
	// it has been executed and deleted from natHoleInstrs.
	//
	// ExecuteNatHolePunch deletes the instruction once a round succeeds, which
	// is right for that round but left the self-healing loop with nothing to
	// re-run: a keepalive timeout calls ReArmNatHoleInstruction, which only
	// resets a counter on an instruction that no longer exists, and
	// executeNatHolePunchLoop early-returns on HasNatHoleInstruction(). A
	// tunnel that dropped after a successful punch was therefore never
	// re-punched by the edge, while the relay went on suppressing the pair on
	// its one-off "succeeded" report. FRP closes the same loop by re-running
	// makeNatHole() from keepTunnelOpenWorker (client/visitor/xtcp.go:114);
	// remembering the instruction is what lets this edge do the same.
	lastNatHoleInstrs map[string]*NatHoleInstruction
	// natHoleInstrKey is the key SetNatHoleInstruction stored under (our own
	// MAC). ReArmNatHoleInstruction is called with the PEER's MAC, so it
	// cannot derive this itself.
	natHoleInstrKey string
	// Latest hole-punch outcome per peer MAC, reported to the relay in
	// GetPeerP2PInfos so it can stop re-broadcasting for pairs that are
	// already up and re-arm pairs that just failed. Without this feedback
	// the relay is blind and either loops forever or gives up too early.
	natHolePunchResults map[string]*NatHolePunchResult
}

// NumPeers returns how many peers are currently in the registry.
//
// Used by the edge's periodic resync to decide whether the peer list is
// worth re-requesting from the supernode.
func (reg *PeerRegistry) NumPeers() int {
	reg.peerMu.RLock()
	defer reg.peerMu.RUnlock()
	return len(reg.Peers)
}

func (reg *PeerRegistry) UpdateP2PCommunityDatas(reachables map[string]*PeerP2PInfos, unreachables map[string]*PeerCachedInfo) error {
	if reachables == nil {
		return fmt.Errorf("received nil reachables in P2PFullStateMessage")
	}
	reg.p2pDatasMu.Lock()
	defer reg.p2pDatasMu.Unlock()

	reg.Reachables = reachables
	if unreachables != nil {
		reg.UnReachables = unreachables
	} else {
		reg.UnReachables = make(map[string]*PeerCachedInfo)
	}
	reg.IsWaitingCommunityDatas = false

	// Learn P2P endpoints from the reachability map.
	// reachables is keyed by source MAC address; each value's To[] lists
	// the peers that the source considers reachable, along with their P2PEndpoint.
	for macAddr, p2pInfos := range reachables {
		// Learn from the sender's own P2P endpoint
		if p2pInfos.From != nil && p2pInfos.From.P2PEndpoint != "" {
			if p, err := reg.GetPeer(macAddr); err == nil {
				p.SetP2PEndpoint(p2pInfos.From.P2PEndpoint)
			}
		}
		// Learn P2P endpoints for each reachable peer
		for _, info := range p2pInfos.To {
			if info == nil {
				continue
			}
			targetMAC := net.HardwareAddr(info.MacAddr).String()
			if info.P2PEndpoint != "" {
				if p, err := reg.GetPeer(targetMAC); err == nil {
					p.SetP2PEndpoint(info.P2PEndpoint)
				}
			}
		}
	}

	return nil
}

func (reg *PeerRegistry) GenPeersDot() string {
	reg.p2pDatasMu.RLock()
	defer reg.p2pDatasMu.RUnlock()
	if reg.Reachables != nil {
		cp2p, err := NewCommunityP2PVizDatas(reg.CommunityName, reg.Reachables)
		if err != nil {
			return ""
		}
		return cp2p.GenerateP2PGraphviz()
	}
	return ""
}

func (reg *PeerRegistry) GenOfflinesDot() string {
	reg.p2pDatasMu.RLock()
	defer reg.p2pDatasMu.RUnlock()
	if reg.P2PCommunityDatas.UnReachables != nil {
		return P2VizGenOfflinesDot(reg.P2PCommunityDatas.UnReachables)
	}
	return ""
}

func (reg *PeerRegistry) GenLegendDot() string {
	return legend
}

func (reg *PeerRegistry) GenPeersHTML() string {
	legraph := fmt.Sprintf("`%s`", reg.GenLegendDot())
	result := fmt.Sprintf(peerHTML2, legraph)
	return result
}

func NewPeerRegistry(communityName string) *PeerRegistry {
	return &PeerRegistry{
		CommunityName:       communityName,
		Peers:               make(map[string]*Peer),
		peerBySocket:        make(map[string]*Peer),
		peerByP2PSocket:     make(map[string]*Peer),
		natHoleInstrs:       make(map[string]*NatHoleInstruction),
		natHoleRetryCounts:  make(map[string]int),
		lastNatHoleInstrs:   make(map[string]*NatHoleInstruction),
		natHolePunchResults: make(map[string]*NatHolePunchResult),
	}
}

func (reg *PeerRegistry) GetPeerP2PInfos() *PeerP2PInfos {
	if reg.Me == nil {
		return &PeerP2PInfos{}
	}
	var to []*PeerInfo
	for _, v := range reg.Peers {
		// Publish the OBSERVED source address for each peer. This is the
		// address the peer's packets actually arrive from — the only one
		// guaranteed to traverse the peer's NAT. The Worker forwards it to
		// the other side so it can punch to a verified-reachable address
		// instead of the STUN snapshot (which may be stale or bound to a
		// different NAT mapping).
		infos := v.Infos
		if v.P2PRaddr != "" {
			infos.ObservedRaddr = v.P2PRaddr
		}
		// Attach our latest punch outcome for this peer so the relay learns
		// whether to keep pushing instructions (in-progress/failed) or stop
		// entirely (succeeded). Reports are per-peer and carry the MAC they
		// refer to, so the relay never has to guess whose round this was.
		reg.peerMu.RLock()
		res := reg.natHolePunchResults[macAddrStr(v.Infos.MacAddr)]
		reg.peerMu.RUnlock()
		if res != nil {
			infos.PunchResult = res
			infos.PunchResultPeerMac = macAddrStr(v.Infos.MacAddr)
		}
		to = append(to, &infos)
	}
	return &PeerP2PInfos{
		From: &reg.Me.Infos,
		To:   to,
	}
}

func (reg *PeerRegistry) HasPendingChanges() bool {
	return reg.hasPendingChanges
}

func (reg *PeerRegistry) SetPendingChanges() {
	reg.hasPendingChanges = true
}

func (reg *PeerRegistry) ClearPendingChanges() {
	reg.hasPendingChanges = false
}

// SetMe creates or updates the local peer's (reg.Me) PeerInfo.
// This is called when the Edge knows its own identity (MAC, VIP, pubSocket,
// NAT type) — typically after STUN discovery and registration with the
// supernode. By setting reg.Me locally (instead of waiting for the
// supernode to echo it back as Origin), the Edge can immediately send
// P2PStateInfo (pubSocket, NAT type) to the supernode, enabling the
// supernode to generate NatHoleInstructions for peer coordination.
func (reg *PeerRegistry) SetMe(infos PeerInfo) {
	reg.peerMu.Lock()
	defer reg.peerMu.Unlock()
	reg.Me = &Peer{
		Infos:     infos,
		UpdatedAt: time.Now(),
		P2PStatus: P2PUnavailable,
	}
}

func (reg *PeerRegistry) GetPeer(MACAddr string) (*Peer, error) {
	reg.peerMu.RLock()
	defer reg.peerMu.RUnlock()

	peer, exists := reg.Peers[MACAddr]
	if !exists {
		return nil, fmt.Errorf("peer with MAC address %s not found", MACAddr)
	}
	return peer, nil
}

// lookupSockets returns every address a peer may legitimately be reached
// at, and therefore every address its inbound packets may legitimately
// appear to come from.
//
// The LAN addresses must be in this set, not just the STUN-reflexive
// pubSocket: we actively ask the peer to punch at them (FRP parity,
// m.AssistedAddrs), so once it does, its packets arrive sourced from one
// of them. Matching only pubSocket would then classify a perfectly good
// packet as coming from an "unknown peer", and handlePunchDatagram would
// drop it -- the symptom being a punch that provably completes on the wire
// yet never registers as a success.
//
// Keys are normalised through net.ResolveUDPAddr so that "1.2.3.4:5678"
// and any spelling of the same endpoint collapse to one entry.
func (p *Peer) lookupSockets() []string {
	if p == nil {
		return nil
	}
	raw := make([]string, 0, 1+len(p.Infos.GetAssistedSockets()))
	if a := p.UDPAddr(); a != nil {
		raw = append(raw, a.String())
	}
	raw = append(raw, p.Infos.GetAssistedSockets()...)

	seen := make(map[string]bool, len(raw))
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		if r == "" {
			continue
		}
		key := r
		if ua, err := net.ResolveUDPAddr("udp", r); err == nil && ua != nil {
			key = ua.String()
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	return out
}

// SelfMAC returns this host's own n2n MAC as a string, which is also the MAC
// n2n assigns to our tap. Empty until the MAC is known.
//
// This is the one tap identifier guaranteed to be available while building
// the registration request: the interface name does not match the OS name on
// Windows, and the virtual IP only arrives in the registration response.
func (reg *PeerRegistry) SelfMAC() string {
	if reg == nil || reg.Me == nil {
		return ""
	}
	return net.HardwareAddr(reg.Me.Infos.MacAddr).String()
}

// SelfTapIP returns this host's own n2n virtual IP, i.e. the address carried
// on our tap. Empty until we have registered. See PeerRegistry.SelfTapName for
// why both identifiers exist: the name is a convenience, this is the
// authoritative one.
func (reg *PeerRegistry) SelfTapIP() string {
	if reg == nil || reg.Me == nil {
		return ""
	}
	return reg.Me.Infos.GetVirtualIp()
}

func (reg *PeerRegistry) GetPeerBySocket(addr *net.UDPAddr) (*Peer, error) {
	if addr == nil {
		return nil, fmt.Errorf("cannot GetPeerBySocket with nil net.UDPAddr")
	}
	reg.peerMu.RLock()
	defer reg.peerMu.RUnlock()

	peer, exists := reg.peerBySocket[addr.String()]
	if !exists {
		return nil, fmt.Errorf("peer with Socket %s not found", addr.String())
	}
	return peer, nil
}

// GetPeerBySocketIP looks up a peer by matching only the IP address
// (ignoring port). This is a fallback for symmetric NAT where the
// NAT-assigned port differs from the STUN-discovered pubSocket port,
// so an exact socket match fails but the IP still identifies the peer.
func (reg *PeerRegistry) GetPeerBySocketIP(ip net.IP) (*Peer, error) {
	if ip == nil {
		return nil, fmt.Errorf("cannot GetPeerBySocketIP with nil IP")
	}
	reg.peerMu.RLock()
	defer reg.peerMu.RUnlock()

	for _, peer := range reg.Peers {
		pubSocketAddr := peer.UDPAddr()
		if pubSocketAddr != nil && pubSocketAddr.IP != nil && pubSocketAddr.IP.Equal(ip) {
			return peer, nil
		}
	}
	return nil, fmt.Errorf("peer with IP %s not found", ip.String())
}

// RecordNatHolePunchResult stores the outcome of a hole-punch attempt for a
// peer so it can be reported to the relay via GetPeerP2PInfos. The relay uses
// this to stop re-broadcasting for pairs that are already connected and to
// immediately re-arm pairs whose latest round failed.
// behaviorIndex is the relay behaviour-ladder rung this outcome belongs to,
// so the relay can credit or blame the right one. 0 is a valid rung, so it is
// always meaningful; callers that have no instruction in hand pass 0.
func (reg *PeerRegistry) RecordNatHolePunchResult(peerMAC string, state NatHolePunchState, attempts uint32, detail string, behaviorIndex uint32) {
	if peerMAC == "" {
		return
	}
	reg.peerMu.Lock()
	defer reg.peerMu.Unlock()
	if reg.natHolePunchResults == nil {
		reg.natHolePunchResults = make(map[string]*NatHolePunchResult)
	}
	reg.natHolePunchResults[peerMAC] = &NatHolePunchResult{
		State:         state,
		Attempts:      attempts,
		Detail:        detail,
		BehaviorIndex: behaviorIndex,
	}
	// A new outcome must reach the relay on the next P2PStateInfo, and a
	// success must also refresh the peer list the relay builds instructions
	// from. Without this the report would sit in the map until some unrelated
	// change happened to trigger an update.
	reg.hasPendingChanges = true
}

func (p *Peer) SetFullDuplex(value bool) (bool, error) {
	changed := false
	if value {
		// A punch packet is direct evidence that the peer's packets can
		// reach us, but NOT that our packets can reach them: the punch is
		// 4 bytes, is re-sent every round, and sending it is what keeps
		// the NAT mapping open. A path that carries punches but drops real
		// frames therefore keeps "succeeding" forever, and promoting on
		// punch alone left this peer stuck at FullDuplex over a dead
		// tunnel (ARP replies went out over P2P and were silently lost).
		//
		// FRP's equivalent proof is the yamux ping/pong round trip, not the
		// nathole punch. Require the same: at least one real ProtoV frame
		// observed from this peer on the P2P socket.
		if !p.HasVerifiedDataPath() {
			// Rate-limited: SetFullDuplex(true) is called for every inbound
			// punch, and punches arrive continuously once a hole is open, so
			// an unconditional log here produces a flood (the same problem
			// LogRouteDecision solves for the per-packet route log). Log only
			// on entry into this state, then re-log periodically so a
			// long-standing unverified peer stays visible.
			p.promoteDenyMu.Lock()
			first := !p.promoteDeniedLogged
			due := time.Since(p.promoteDenyAt) >= promoteDenyReLogInterval
			if first || due {
				p.promoteDenyAt = time.Now()
				p.promoteDeniedLogged = true
			}
			p.promoteDenyMu.Unlock()
			if first || due {
				log.Printf("[P2P] not promoting peer %s to FullDuplex: punch seen but no data frame verified yet",
					net.HardwareAddr(p.Infos.MacAddr).String())
			}
			return false, nil
		}
		if p.P2PStatus != P2PAvailable && p.P2PStatus != P2PFullDuplex {
			log.Printf("[P2P] promoting peer %s from %s to FullDuplex on direct punch evidence",
				net.HardwareAddr(p.Infos.MacAddr).String(), p.P2PStatus)
		}
		// CRITICAL: also update P2PStatus so UDPAddrWithStrategy() in
		// wire.go uses the direct P2P UDP path instead of falling back
		// to the WebSocket relay.  Without this, all data (ARP, ICMP,
		// application traffic) flows through the WSS tunnel even after
		// FullDuplex is achieved — the P2P path is never selected
		// because P2PStatus stays at P2PAvailable.
		p.P2PStatus = P2PFullDuplex
	} else {
		// When FullDuplex is cleared (e.g. by a protoV ping over WSS),
		// downgrade P2PStatus so UDPAddrWithStrategy falls back to
		// the supernode relay for subsequent data messages.
		if p.IsFullDuplex && p.P2PStatus == P2PFullDuplex {
			p.P2PStatus = P2PAvailable
		}
	}
	if value != p.IsFullDuplex {
		log.Printf("updated peer %s/%s/%s with FullDuplex=%v", p.Infos.Desc, p.Infos.VirtualIp, net.HardwareAddr(p.Infos.MacAddr).String(), value)
		changed = true
	}
	// Reset the promotion-denial latch on every actual state change (in
	// either direction) so that a later demotion re-logs its first denial
	// instead of staying silent until the re-log interval expires.
	if changed {
		p.promoteDenyMu.Lock()
		p.promoteDeniedLogged = false
		p.promoteDenyMu.Unlock()
	}
	p.IsFullDuplex = value
	return changed, nil
}

func (p *Peer) UpdateP2PStatus(status P2PCapacity, checkid string) bool {
	previousStatus := p.P2PStatus
	var forcedStatement string
	skipLog := false

	// Never downgrade a confirmed direct path.
	//
	// The 3s liveness tick in edge/routines.go calls PingPeer with
	// P2PPending for every peer, and the matching pong handler calls this
	// same function with P2PAvailable. Both go over the WSS relay, so
	// without this guard a working FullDuplex path would be rewritten to
	// Pending and then to Available every 3 seconds — and since
	// UDPAddrWithStrategy only takes the direct path on exactly
	// P2PFullDuplex, a successfully punched hole would never be usable.
	//
	// P2PUnknown is covered for the same reason. A pong whose checkID no
	// longer matches the peer's current one drives the peer to Unknown
	// (edge/handlers.go:294), and that says nothing about the data path: a
	// late or reordered relay pong routinely carries a checkID that a newer
	// ping has already replaced, while real frames keep arriving on the P2P
	// socket the whole time. Allowing that transition made a working tunnel
	// oscillate on a ~9s cycle — dropped to relay, re-promoted by the next
	// punch packet, dropped again by the next stale pong — which is what the
	// 13ms-to-230ms RTT spread and the 5% loss came from.
	//
	// Demotion of a confirmed direct path stays with the data-plane authority
	// that is entitled to make it: p2pKeepAliveTick calls SetFullDuplex(false)
	// after a real timeout, and it deliberately bypasses this function. A
	// control-plane probe is never evidence that a direct path died.
	if p.P2PStatus == P2PFullDuplex && p.IsFullDuplex &&
		(status == P2PPending || status == P2PAvailable ||
			status == P2PUnknown || status == P2PUnavailable) {
		p.P2PCheckID = checkid
		p.UpdatedAt = time.Now()
		return false
	}

	if p.P2PStatus == status {
		skipLog = true
		if status == P2PPending {
			p.pendingTTL = p.pendingTTL - 1
		}
	} else {
		// Any transition INTO P2PPending starts a fresh probe cycle, not
		// just P2PUnknown -> P2PPending. The original narrow condition
		// made a peer that had once been forced to P2PUnavailable
		// permanently stuck: pendingTTL stayed < 1, so every subsequent
		// call took the "Forcefull update" branch below and the peer could
		// never leave P2PUnavailable again — not even to retry a punch that
		// would now succeed. Resetting on every entry into Pending keeps
		// the 30-tick (90s) give-up for a cycle that gets no pong at all
		// (the status stays Pending, so the counter still decrements), while
		// letting the peer recover and retry.
		if status == P2PPending {
			p.resetPendingTTL()
		}
	}
	if p.pendingTTL < 1 {
		skipLog = false
		forcedStatement = fmt.Sprintf("| Forcefull update, hole-punching TTL<0")
		p.P2PCheckID = ""
		p.P2PStatus = P2PUnavailable
	} else {
		p.P2PCheckID = checkid
		p.P2PStatus = status
	}
	p.UpdatedAt = time.Now()
	if !skipLog {
		log.Printf("updated peer %s/%s/%s with P2PStatus=%s %s", p.Infos.Desc, p.Infos.VirtualIp, net.HardwareAddr(p.Infos.MacAddr).String(), p.P2PStatus.String(), forcedStatement)
	}
	return previousStatus != status
}

func (reg *PeerRegistry) AddPeer(infos PeerInfo, overwrite bool) (*Peer, error) {
	reg.peerMu.Lock()
	defer reg.peerMu.Unlock()

	macAddr := net.HardwareAddr(infos.MacAddr).String()
	if existingPeer, exists := reg.Peers[macAddr]; exists {
		origPeer := *existingPeer
		if !overwrite {
			return nil, fmt.Errorf("peer with MAC address %s already exists", macAddr)
		}
		if existingPeer.Infos.VirtualIp != infos.VirtualIp ||
			existingPeer.Infos.PubSocket != infos.PubSocket {
			log.Printf("peer with MAC %s updated with network difference: resetting P2PStatus", macAddr)
			existingPeer.P2PStatus = P2PUnknown
			existingPeer.P2PCheckID = ""
		}

		existingPeer.Infos = infos
		existingPeer.P2PEndpoint = infos.P2PEndpoint
		existingPeer.P2PCapabilities = infos.P2PCapabilities
		existingPeer.UpdatedAt = time.Now()
		log.Printf("updated peer now hold of %s MACAddr:", macAddr)
		log.Printf(" was: vip=%s PubSocket=%s desc=%s", origPeer.Infos.VirtualIp, origPeer.Infos.PubSocket, origPeer.Infos.Desc)
		log.Printf(" now: vip=%s PubSocket=%s desc=%s", existingPeer.Infos.VirtualIp, existingPeer.Infos.PubSocket, existingPeer.Infos.Desc)
		// Re-key every address, not just pubSocket: the assisted set can
		// change between updates (an interface came up or went down), and a
		// stale key would keep resolving to this peer for an address it no
		// longer claims -- and would shadow a different peer that does.
		for _, k := range origPeer.lookupSockets() {
			delete(reg.peerBySocket, k)
		}
		for _, k := range existingPeer.lookupSockets() {
			reg.peerBySocket[k] = existingPeer
		}
		if origPeer.P2PEndpoint != "" {
			delete(reg.peerByP2PSocket, origPeer.P2PEndpoint)
		}
		if existingPeer.P2PEndpoint != "" {
			reg.peerByP2PSocket[existingPeer.P2PEndpoint] = existingPeer
		}
		reg.SetPendingChanges()
		return existingPeer, nil
	}

	peer := &Peer{
		Infos:           infos,
		P2PStatus:       P2PUnknown,
		P2PEndpoint:     infos.P2PEndpoint,
		P2PCapabilities: infos.P2PCapabilities,
		UpdatedAt:       time.Now(),
	}
	reg.Peers[macAddr] = peer
	for _, k := range peer.lookupSockets() {
		reg.peerBySocket[k] = peer
	}
	if peer.P2PEndpoint != "" {
		reg.peerByP2PSocket[peer.P2PEndpoint] = peer
	}
	log.Printf("added peer %s/%s/%s with PubSocket=%s", peer.Infos.Desc, peer.Infos.VirtualIp, net.HardwareAddr(peer.Infos.MacAddr).String(), peer.Infos.PubSocket)
	reg.SetPendingChanges()
	return peer, nil
}

func (reg *PeerRegistry) RemovePeer(MACAddr string) error {
	reg.peerMu.Lock()
	defer reg.peerMu.Unlock()

	p, exists := reg.Peers[MACAddr]
	if !exists {
		// Idempotent: silently ignore removal of non-existent peers.
		// The relay may send TypeUnregister for MACs that were never
		// registered locally (e.g. relay-side MAC confusion), or a pong
		// may arrive after the peer has already been removed.
		return nil
	}

	dDesc := p.Infos.Desc
	dVip := p.Infos.VirtualIp
	// Release every address key, not just pubSocket. A key left behind after
	// the peer is gone keeps resolving to a dead *Peer, so a punch from the
	// next machine to take that address would attach to a tombstone instead
	// of failing the lookup and taking the unknown-peer path.
	for _, k := range p.lookupSockets() {
		delete(reg.peerBySocket, k)
	}
	delete(reg.Peers, MACAddr)
	if p.P2PEndpoint != "" {
		delete(reg.peerByP2PSocket, p.P2PEndpoint)
	}
	log.Printf("removed peer %s/%s/%s", dDesc, dVip, MACAddr)
	reg.SetPendingChanges()
	return nil
}

// GetPeerByP2PSocket looks up a peer by its P2P endpoint address.
func (reg *PeerRegistry) GetPeerByP2PSocket(endpoint string) (*Peer, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("cannot GetPeerByP2PSocket with empty endpoint")
	}
	reg.peerMu.RLock()
	defer reg.peerMu.RUnlock()

	peer, exists := reg.peerByP2PSocket[endpoint]
	if !exists {
		return nil, fmt.Errorf("peer with P2PSocket %s not found", endpoint)
	}
	return peer, nil
}

func (p *Peer) UDPAddr() *net.UDPAddr {
	return parseUDPAddr(p.Infos.PubSocket)
}

// P2PAddr parses the learned P2P endpoint (IP:port) into a *net.UDPAddr.
// Returns nil if no P2P endpoint has been learned yet.
func (p *Peer) P2PAddr() *net.UDPAddr {
	if p.P2PEndpoint == "" {
		return nil
	}
	return parseUDPAddr(p.P2PEndpoint)
}

func parseUDPAddr(socket string) *net.UDPAddr {
	host, portStr, err := net.SplitHostPort(socket)
	if err != nil {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}
	port, _ := net.LookupPort("udp", portStr)
	return &net.UDPAddr{IP: ip, Port: port}
}

func (reg *PeerRegistry) GetP2PUnknownPeers() []*Peer {
	var peerlist []*Peer
	for _, p := range reg.Peers {
		if p.P2PStatus == P2PUnknown {
			peerlist = append(peerlist, p)
		}
	}
	return peerlist
}

func (reg *PeerRegistry) GetP2PendingPeers() []*Peer {
	var peerlist []*Peer
	for _, p := range reg.Peers {
		if p.P2PStatus == P2PPending {
			if p.pendingTTL > 0 {
				peerlist = append(peerlist, p)
			} else {
				p.UpdateP2PStatus(P2PUnavailable, "")
			}
		}
	}
	return peerlist
}

func (reg *PeerRegistry) GetP2PAvailablePeers() []*Peer {
	var peerlist []*Peer
	for _, p := range reg.Peers {
		if p.P2PStatus == P2PAvailable {
			peerlist = append(peerlist, p)
		}
	}
	return peerlist
}

// GetPunchedNotFullDuplexPeers returns peers we have punched (or been punched
// by) but have not yet promoted to FullDuplex.
//
// Promotion requires a real data frame, and data is only routed over P2P once
// a peer is FullDuplex — so without an explicit probe after punching, the two
// conditions can never both become true. The post-punch verification probe
// walks this list to break that deadlock. See sendPathVerificationProbe.
//
// Membership is decided by punchSeenAt (did a punch actually arrive?) rather
// than by NatHoleExecuted, which records that we ran a punch — a peer can be
// punched by the remote while we never ran one ourselves, and that is exactly
// the case where the probe is needed most.
func (reg *PeerRegistry) GetPunchedNotFullDuplexPeers() []*Peer {
	var peerlist []*Peer
	for _, p := range reg.Peers {
		if p.P2PStatus == P2PFullDuplex && p.IsFullDuplex {
			continue
		}
		// Either side counts: we received their punch, or we already ran
		// (and possibly failed) a punch against them.
		if !p.punchSeenAt.IsZero() || p.NatHoleExecuted {
			peerlist = append(peerlist, p)
		}
	}
	return peerlist
}

// GetFullDuplexPeers returns the peers we believe are reachable over direct
// UDP. The keepalive walks this list: for each entry it sends a probe and, if
// nothing came back within the timeout, demotes the peer so routing falls
// back to the relay and a fresh punch is scheduled.
func (reg *PeerRegistry) GetFullDuplexPeers() []*Peer {
	var peerlist []*Peer
	for _, p := range reg.Peers {
		if p.P2PStatus == P2PFullDuplex && p.IsFullDuplex {
			peerlist = append(peerlist, p)
		}
	}
	return peerlist
}

// LookupPeerByPubSocket looks up a peer by their pubSocket address string.
// Used during hole punching to find the target peer's P2PEndpoint as an
// additional punch target (FRP-style multi-address punching).
func (reg *PeerRegistry) LookupPeerByPubSocket(pubSocket string) *Peer {
	reg.peerMu.RLock()
	defer reg.peerMu.RUnlock()
	for _, p := range reg.Peers {
		if p.Infos.PubSocket == pubSocket {
			return p
		}
	}
	return nil
}

// CurrentNatHoleBehaviorIndex reports which behaviour-ladder rung the
// instruction currently targeting peerMAC was drawn from, so a success
// observed for that peer can be attributed to the right rung.
//
// Instructions are keyed by our own MAC (SetNatHoleInstruction stores under
// the caller's), so this scans for the one whose target is peerMAC. 0 is a
// valid rung and is also the honest answer when there is no instruction --
// the relay treats a report with no rung as attributable to nothing.
func (reg *PeerRegistry) CurrentNatHoleBehaviorIndex(peerMAC string) uint32 {
	if peerMAC == "" {
		return 0
	}
	reg.peerMu.RLock()
	defer reg.peerMu.RUnlock()
	for _, instr := range reg.natHoleInstrs {
		if instr == nil {
			continue
		}
		if tm := instr.GetTargetMac(); len(tm) > 0 && macAddrStr(tm) == peerMAC {
			return instr.GetBehaviorIndex()
		}
	}
	return 0
}

// SetNatHoleInstruction stores a relay-coordinated NAT hole instruction
// for the given MAC address. The instruction is then executed by
// executeNatHolePunch().
func (reg *PeerRegistry) SetNatHoleInstruction(macAddr []byte, instr *NatHoleInstruction) {
	reg.peerMu.Lock()
	defer reg.peerMu.Unlock()
	if reg.natHoleInstrs == nil {
		reg.natHoleInstrs = make(map[string]*NatHoleInstruction)
	}
	if reg.natHoleRetryCounts == nil {
		reg.natHoleRetryCounts = make(map[string]int)
	}
	key := macAddrStr(macAddr)
	// Only reset the retry count if this is a genuinely new instruction.
	// If the Worker re-sends the same instruction (same TTL, same ports),
	// keep the existing retry count so the edge can actually reach
	// attempts 2/5, 3/5, etc.  Without this, the retry counter always
	// shows "attempt 1/5" because the Worker broadcasts a fresh
	// PeerList (with embedded NatHoleInstruction) every time it receives
	// a P2PStateInfo (every ~2 s).
	prevInstr, exists := reg.natHoleInstrs[key]
	reg.natHoleInstrs[key] = instr
	reg.natHoleInstrKey = key
	// Remember it per peer so the self-healing path can re-run it after a
	// successful round has already deleted it from natHoleInstrs.
	if tm := instr.GetTargetMac(); len(tm) == 6 {
		if reg.lastNatHoleInstrs == nil {
			reg.lastNatHoleInstrs = make(map[string]*NatHoleInstruction)
		}
		reg.lastNatHoleInstrs[macAddrStr(tm)] = instr
	}
	if !exists || prevInstr.GetPortsRangeFrom() != instr.GetPortsRangeFrom() ||
		prevInstr.GetPortsRangeTo() != instr.GetPortsRangeTo() ||
		prevInstr.GetTtl() != instr.GetTtl() ||
		prevInstr.GetRole() != instr.GetRole() ||
		prevInstr.GetTargetMac() != nil && string(prevInstr.GetTargetMac()) != string(instr.GetTargetMac()) {
		// Genuinely new instruction — reset retry count.
		reg.natHoleRetryCounts[key] = 0
	}
}

func macAddrStr(mac []byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

// HasNatHoleInstruction returns true if there is a pending NAT hole instruction.
func (reg *PeerRegistry) HasNatHoleInstruction() bool {
	reg.peerMu.RLock()
	defer reg.peerMu.RUnlock()
	return len(reg.natHoleInstrs) > 0
}

// ReArmNatHoleInstruction re-arms the NAT hole instruction for the given peer
// MAC so the next punch tick retries it from scratch.
//
// This is the closing half of the self-healing loop. FRP's
// keepTunnelOpenWorker (client/visitor/xtcp.go:114) re-runs makeNatHole()
// whenever its health probe fails, so a dead NAT mapping recovers on its own.
// Without an equivalent here, a peer whose mapping expired stayed
// FullDuplex forever and was never re-punched.
//
// Two bugs made this a no-op, which is why a tunnel that dropped after a
// successful punch never came back:
//
//  1. It looked the instruction up by the PEER's MAC, but natHoleInstrs is
//     keyed by OUR MAC (SetNatHoleInstruction stores under macStrToBytes(ourMAC)),
//     so the lookup missed every time.
//  2. Even on a hit, a successful round deletes the instruction — so the case
//     this exists for, a tunnel that came up once and later dropped, had
//     nothing to re-arm. executeNatHolePunchLoop then skipped the pair
//     entirely (HasNatHoleInstruction was false) while the relay went on
//     suppressing it on its stale "succeeded" report.
//
// So the instruction is now looked up by our own key, and when nothing is
// pending the last instruction executed against that peer is restored from
// lastNatHoleInstrs. The restored copy keeps the targets (ports/TTL/role) the
// Worker last negotiated, so the retry punches the same addresses the relay
// believes are current.
func (reg *PeerRegistry) ReArmNatHoleInstruction(peerMAC []byte) {
	if len(peerMAC) != 6 {
		return
	}
	reg.peerMu.Lock()
	defer reg.peerMu.Unlock()
	peerKey := macAddrStr(peerMAC)

	// Our own key is the single entry in natHoleInstrs, if any is pending.
	ourKey := ""
	for k := range reg.natHoleInstrs {
		ourKey = k
		break
	}
	if ourKey == "" {
		prev, ok := reg.lastNatHoleInstrs[peerKey]
		if !ok || prev == nil {
			return
		}
		if reg.natHoleInstrs == nil {
			reg.natHoleInstrs = make(map[string]*NatHoleInstruction)
		}
		if reg.natHoleRetryCounts == nil {
			reg.natHoleRetryCounts = make(map[string]int)
		}
		key := reg.natHoleInstrKey
		if key == "" {
			// Should not happen: the key is recorded on every store. Fall
			// back to the peer's MAC rather than dropping the re-arm, so a
			// tunnel is never left with no punch scheduled because of a
			// bookkeeping gap.
			key = peerKey
		}
		reg.natHoleInstrs[key] = prev
		reg.natHoleRetryCounts[key] = 0
		log.Printf("[P2P] re-armed the punch instruction remembered for %s — its tunnel dropped after a successful round", peerKey)
		return
	}
	if _, ok := reg.natHoleInstrs[ourKey]; ok {
		reg.natHoleRetryCounts[ourKey] = 0
	}
}

// receiverProbeIPTTL is the IP TTL used for the receiver's pre-mapping probe.
//
// FRP parity: pkg/nathole/analysis.go:40-43, Mode 0 (EasyNAT & EasyNAT)
//   - index 0: {Role: sender}            | {Role: receiver, TTL: 7}
//   - index 1: {Role: receiver, TTL: 7}  | {Role: sender}
//
// so the receiver's detect packet is sent with IP TTL 7: low enough to die in
// the path before reaching the sender, while the router's NAT lookup has
// already created the receiver's mapping toward the sender. By the time the
// sender's first (normal-TTL) punch arrives, the receiver's NAT is willing to
// accept it.
//
// FRP applies this socket-wide for the duration of one sendSidMessage call
// (pkg/nathole/nathole.go:365-378: SetTTL, send, deferred restore). We do the
// same but keep the window short, because the socket is shared: handleP2P
// may be writing a punch ACK from another goroutine while the TTL is lowered,
// and an ACK sent with TTL 7 would be lost.
//
// Configurable via `--nat-hole-probe-ttl`. 7 is the FRP value and is correct
// for a consumer router, where the NAT lookup happens at hop 1. On a cloud
// network the EIP translation can sit several hops away, and a probe that
// dies before reaching it never creates the mapping it exists to create --
// measured here: E1<->E2 is a 12-hop path, so TTL 7 cannot possibly open the
// mapping and the pair can never punch. Raise it to the measured hop count
// (or set 0 to disable the probe entirely) when the path is long.
//
// A value of 0 means "never lower the TTL": the receiver's packet goes out
// with the socket's normal TTL and is simply a normal punch.
var receiverProbeIPTTL = 7

// SetReceiverProbeIPTTL overrides the default probe TTL. 0 disables the
// low-TTL pre-mapping probe. Values outside 1..255 are clamped.
func SetReceiverProbeIPTTL(ttl int) {
	if ttl < 0 {
		ttl = 0
	}
	if ttl > 255 {
		ttl = 255
	}
	receiverProbeIPTTL = ttl
}

// ReceiverProbeIPTTL reports the configured default probe TTL.
func ReceiverProbeIPTTL() int { return receiverProbeIPTTL }

// Coordination modes and ladder positions, mirroring FRP's nathole analyser
// (pkg/nathole/analysis.go). Only the ones the relay actually emits are
// named here; an unknown value falls through to the ttl field.
const (
	// natHoleModeEasyNATPair is FRP Mode 0: both peers are behind a
	// port-preserving cone NAT, so the STUN-discovered pub_socket is exact
	// and no port scan is performed.
	natHoleModeEasyNATPair = 0

	// Mode 0 ladder entries 4 and 5 -- the "no TTL" pair, where both roles
	// emit with the socket's normal TTL.
	natHoleBehaviorNoTTLSenderFirst   = 4
	natHoleBehaviorNoTTLReceiverFirst = 5
)

// sendWithIPTTL writes pkt to every addr with a temporarily lowered IP TTL.
//
// The TTL is a property of the socket, not of the individual datagram, so
// this is inherently racy against other writers on the same socket; that is
// why callers keep the burst short. Returns the number of successful writes.
// natHoleProbeTTL returns the IP TTL to use for the receiver's pre-mapping
// probe, or 0 when the chosen behaviour does not use one (the probe is then
// just an ordinary full-path punch).
//
// FRP encodes "do not touch the TTL" as ttl 0 in DetectBehavior --
// pkg/nathole/nathole.go:363 guards the SetTTL call with `if ttl > 0`, and
// mode0Behaviors entries 4 and 5 (analysis.go:38-39) carry no ttl at all:
//
//	lo.T2(RecommandBehavior{Role: DetectRoleSender},   RecommandBehavior{Role: DetectRoleReceiver}),
//	lo.T2(RecommandBehavior{Role: DetectRoleReceiver}, RecommandBehavior{Role: DetectRoleSender}),
//
// Those are the entries that work on a path longer than the TTL, which is
// the whole point of carrying the ladder rather than one hardcoded strategy.
//
// The wire format cannot express that: protobuf3 encodes an unset uint32 and
// a zero uint32 identically, so a `ttl: 0` instruction is ambiguous between
// "unset" and "deliberately no TTL". The ladder position travels in
// nat_hole_instruction.behavior_index and is what disambiguates.
//
// fallback is used when the instruction predates the field (an older relay
// that only ever emits ttl 7), so behaviour is unchanged in that case.
func natHoleProbeTTL(instr *NatHoleInstruction, fallback int) int {
	if instr == nil {
		return fallback
	}
	// Entries 4 and 5 of the Mode 0 ladder are the "no TTL" pair. Any other
	// index that explicitly says 0 (e.g. the sender's own instruction, which
	// always has ttl 0) is not a receiver probe, and entries outside the
	// ladder predate the feature.
	if instr.GetMode() == natHoleModeEasyNATPair && (instr.GetBehaviorIndex() == natHoleBehaviorNoTTLSenderFirst ||
		instr.GetBehaviorIndex() == natHoleBehaviorNoTTLReceiverFirst) {
		return 0
	}
	if t := int(instr.GetTtl()); t > 0 {
		return t
	}
	return fallback
}

func sendWithIPTTL(conn *net.UDPConn, pkt []byte, addrs []*net.UDPAddr, ttl int, gap time.Duration) int {
	if len(addrs) == 0 || ttl <= 0 {
		return 0
	}
	c := ipv4.NewConn(conn)
	original, err := c.TTL()
	if err != nil {
		log.Printf("[P2P] receiver probe: cannot read socket TTL, skipping low-TTL probe: %v", err)
		return 0
	}
	if err := c.SetTTL(ttl); err != nil {
		log.Printf("[P2P] receiver probe: cannot set socket TTL=%d, skipping low-TTL probe: %v", ttl, err)
		return 0
	}
	sent := 0
	for i, a := range addrs {
		conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := conn.WriteToUDP(pkt, a); err != nil {
			log.Printf("[P2P] receiver probe: write to %s failed: %v", a, err)
		} else {
			sent++
		}
		conn.SetWriteDeadline(time.Time{})
		if i < len(addrs)-1 {
			time.Sleep(gap)
		}
	}
	if err := c.SetTTL(original); err != nil {
		log.Printf("[P2P] receiver probe: cannot restore socket TTL=%d: %v", original, err)
	}
	return sent
}

// Nat-hole punch timing, mirroring FRP's detectBehavior defaults.
//
// FRP sends exactly one datagram per detect address and then blocks in
// waitDetectMessage for ReadTimeoutMs. The mapping it opens lives for
// seconds afterwards, so volume is not what makes a hole punch work —
// giving the peer time to answer is. The previous code instead fired a
// burst (ttl*3 packets, 20ms apart) and gave up after 300ms, i.e. it
// finished its whole send phase before the peer's mapping could plausibly
// have been created, then declared failure.
const (
	// natHoleReadTimeout mirrors FRP's ReadTimeoutMs (5000ms).
	natHoleReadTimeout = 5 * time.Second
	// natHolePollInterval is how often the wait re-checks whether the peer
	// punched back. It only reads in-memory state, never the socket.
	natHolePollInterval = 100 * time.Millisecond
)

// sendPunchOnce mirrors FRP's sendSidMessage: exactly one datagram to one
// address, with the socket's IP TTL applied for that write and restored
// immediately afterwards when ttl > 0.
//
// FRP sets the TTL per message rather than per socket because the socket is
// shared and still carrying normal traffic.
func sendPunchOnce(conn *net.UDPConn, pkt []byte, addr *net.UDPAddr, ttl uint32, label string) error {
	if conn == nil || addr == nil {
		return nil
	}
	if ttl > 0 {
		if c := ipv4.NewConn(conn); c != nil {
			original, err := c.TTL()
			if err == nil {
				if err := c.SetTTL(int(ttl)); err != nil {
					log.Printf("[P2P] %s: cannot set socket TTL=%d, sending with default TTL: %v", label, ttl, err)
				} else {
					defer func() {
						if err := c.SetTTL(original); err != nil {
							log.Printf("[P2P] %s: cannot restore socket TTL=%d: %v", label, original, err)
						}
					}()
				}
			} else {
				log.Printf("[P2P] %s: cannot read socket TTL, sending with default TTL: %v", label, err)
			}
		}
	}
	conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	_, err := conn.WriteToUDP(pkt, addr)
	conn.SetWriteDeadline(time.Time{})
	if err != nil {
		log.Printf("[P2P] %s: write to %s failed: %v", label, addr.String(), err)
	}
	return err
}

// waitForPunchSuccess mirrors FRP's waitDetectMessage: after the one-shot
// send, block until the peer's packet comes back or ReadTimeoutMs expires.
//
// It deliberately does NOT read from conn. In FRP the nathole socket is
// dedicated to the punch; here e.P2PConn also carries every tunnelled data
// packet, and reading it here would steal those packets from handleP2P and
// silently drop them from the tunnel. Instead the receive side of the
// handshake stays where it already is — handleP2P recognises the punch magic,
// ACKs the source address, and sets FullDuplex — and this function just
// polls that flag, which is the same observable FRP's blocking read produces.
func waitForPunchSuccess(reg *PeerRegistry, targetMACStr string, label string) bool {
	if targetMACStr == "" {
		return false
	}
	deadline := time.Now().Add(natHoleReadTimeout)
	log.Printf("[P2P] %s: sent, waiting up to %s for the peer's punch packet", label, natHoleReadTimeout)
	// Wait for the peer's PUNCH to arrive (punchSeenAt), not for FullDuplex.
	// FullDuplex is gated on receiving a real data frame, which only the
	// post-punch verification probe can elicit — so waiting on IsFullDuplex
	// here would always time out even when the punch landed perfectly.
	// Record the baseline first so we detect the punch belonging to THIS
	// attempt rather than an earlier one.
	var baseline time.Time
	if p, err := reg.GetPeer(targetMACStr); err == nil {
		baseline = p.punchSeenAt
	}
	for {
		if p, err := reg.GetPeer(targetMACStr); err == nil && p.punchSeenAt.After(baseline) {
			log.Printf("[P2P] %s: peer punched back within the read timeout", label)
			return true
		}
		if time.Now().After(deadline) {
			log.Printf("[P2P] %s: no peer packet within %s, treating this round as failed", label, natHoleReadTimeout)
			return false
		}
		time.Sleep(natHolePollInterval)
	}
}

// executeNatHolePunch performs the relay-coordinated NAT hole punching.
// The caller must provide the P2P UDP connection to use for sending/receiving.
// Returns true if FullDuplex was achieved.
func (reg *PeerRegistry) ExecuteNatHolePunch(p2pConn *net.UDPConn) bool {
	reg.peerMu.RLock()
	var instr *NatHoleInstruction
	instrKey := ""
	for k, v := range reg.natHoleInstrs {
		instr = v
		instrKey = k
		break
	}
	reg.peerMu.RUnlock()

	if instr == nil {
		return false
	}

	role := instr.GetRole()
	targetP2PEndpoint := instr.GetSenderP2PEndpoint()
	senderPubSocket := instr.GetSenderPubSocket()
	portsFrom := instr.GetPortsRangeFrom()
	portsTo := instr.GetPortsRangeTo()
	ttl := instr.GetTtl()

	// For the sender role, we must punch to the TARGET's pubSocket (the
	// receiver's public endpoint), NOT the sender's own pubSocket.
	// The instruction carries senderPubSocket — that's the sender's address.
	// For the receiver, senderPubSocket is correct (receiver punches to sender).
	// For the sender, look up the target peer's pubSocket from our registry.
	var punchTarget string
	if role == NatHoleRole_DetectRoleSender {
		targetMAC := instr.GetTargetMac()
		if targetMAC != nil && len(targetMAC) > 0 {
			targetMACStr := macAddrStr(targetMAC)
			if targetPeer, err := reg.GetPeer(targetMACStr); err == nil {
				punchTarget = targetPeer.Infos.PubSocket
				if punchTarget == "" {
					punchTarget = targetPeer.P2PEndpoint
				}
			}
		}
		// Fallback: if we couldn't find the target peer's pubSocket,
		// try the instruction's senderPubSocket (this only works if the
		// roles are reversed, which is a misconfiguration, but better
		// than nothing).
		if punchTarget == "" {
			log.Printf("[P2P] Sender: could not find target peer's pubSocket in registry, falling back to senderPubSocket")
			punchTarget = senderPubSocket
		}
	} else {
		// Receiver: punch to the sender's pubSocket (correct per protocol).
		//
		// Re-resolve from the local registry instead of trusting the
		// instruction blindly. The instruction is a snapshot the relay took
		// when it scheduled the pair; if the sender restarted after that,
		// the snapshot still carries the port the sender had BEFORE the
		// restart, and every attempt lands on a port nothing listens on.
		// Observed exactly this: the registry already carried the sender's
		// new pubSocket while the receiver kept punching the old one for
		// five attempts across ~11s. The sender branch above re-resolves
		// for the same reason, so both roles now behave alike.
		//
		// Registry first, instruction as fallback: right after a reconnect
		// the instruction is often the FIRST mention of the peer, and the
		// registry may legitimately have nothing yet.
		if sm := instr.GetSenderMac(); sm != nil && len(sm) > 0 {
			senderMACStr := macAddrStr(sm)
			if senderPeer, err := reg.GetPeer(senderMACStr); err == nil {
				registryTarget := senderPeer.Infos.PubSocket
				if registryTarget == "" {
					registryTarget = senderPeer.P2PEndpoint
				}
				if registryTarget != "" {
					if registryTarget != senderPubSocket {
						stale := senderPubSocket
						if stale == "" {
							stale = "<empty>"
						}
						log.Printf("[P2P] Receiver: instruction carries a stale sender address %s, using registry value %s for %s",
							stale, registryTarget, senderMACStr)
					}
					punchTarget = registryTarget
				}
			}
		}
		if punchTarget == "" {
			punchTarget = senderPubSocket
		}
	}
	if punchTarget == "" {
		punchTarget = targetP2PEndpoint
	}
	if punchTarget == "" {
		log.Printf("[P2P] executeNatHolePunch: no target address")
		return false
	}

	targetAddr, err := net.ResolveUDPAddr("udp", punchTarget)
	if err != nil {
		log.Printf("[P2P] executeNatHolePunch: cannot resolve target %s: %v", punchTarget, err)
		return false
	}

	if role == NatHoleRole_DetectRoleSender {
		// Sender: send UDP punch packets to the target's public socket.
		// The receiver is listening on its P2P socket; our packets will
		// create a NAT mapping on our side and punch through on theirs.
		//
		// FRP-style fix: collect ALL known candidate addresses for the
		// target peer (pubSocket + P2PEndpoint + any other learned addresses)
		// and send punch packets to EACH of them. This mirrors FRP's
		// sendSidMessage which iterates over all candidate addresses.
		punchPacket := []byte{0xFF, 0xFE, 0xFD, 0xFC} // magic bytes for punch detection

		if p2pConn == nil {
			return false
		}

		// Build list of candidate addresses to punch.
		//
		// FRP parity, and the order is the whole point --
		// pkg/nathole/nathole.go:210-215:
		//
		//	if role == DetectRoleSender {
		//		detectAddrs = m.AssistedAddrs
		//		detectAddrs = append(detectAddrs, m.CandidateAddrs...)
		//	} else {
		//		detectAddrs = m.CandidateAddrs
		//	}
		//
		// The peer's LAN addresses come first because when both ends share
		// a broadcast domain the delivery is direct: no NAT mapping has to
		// exist yet, and no router has to hairpin. The STUN-reflexive
		// address -- the one every other candidate resolves to, and the
		// only one that can work across the internet -- comes after.
		//
		// This is not a fallback arrangement: on a shared LAN the assisted
		// address is answered by the peer itself, while the public one
		// depends on the local router supporting hairpinning, which many do
		// not. Putting it second would mean paying a full punch timeout
		// before trying the one address that actually works.
		//
		// Ordering across networks: the loop below sends one datagram per
		// candidate and only then waits, so a private address that is
		// unroutable from here costs a single dropped sendto, never a
		// timeout -- which is why FRP can list every local IP unconditionally
		// without caring whether the peer is actually on the same segment.
		//
		// The peer's OBSERVED raddr is still prepended ahead of all of this
		// further below: it is the address we most recently proved is
		// reachable, which outranks anything merely predicted.
		var candidates []*net.UDPAddr
		seenCandidate := map[string]bool{}
		appendCandidate := func(a *net.UDPAddr) {
			if a == nil || a.IP == nil {
				return
			}
			key := a.String()
			if seenCandidate[key] {
				return
			}
			seenCandidate[key] = true
			candidates = append(candidates, a)
		}

		// NOTE: instr.SenderAssistedEndpoints is deliberately NOT read here.
		//
		// It carries the SENDER's own LAN addresses, so a sender that
		// punched at it would be sending to itself. FRP's equivalent
		// (nathole.go:210-215, `detectAddrs = m.AssistedAddrs`) reads a
		// field holding the PEER's addresses, because frps builds each
		// side's NatHoleResp separately and fills it with the other side's
		// data (controller.go:365). n2n-go broadcasts one instruction to
		// both roles instead, so the `sender*` fields can only describe the
		// sender -- which makes them usable by the RECEIVER (it needs the
		// sender's addresses) and useless to the sender.
		//
		// The receiver's LAN addresses therefore come from the peer
		// registry below, keyed on TargetMac. That is the same source as
		// P2PRaddr and P2PEndpoint, so all three are consistent snapshots
		// of one peer rather than a mix of instruction-time and
		// registry-time addresses.

		// The STUN-reflexive address, and everything else the registry knows.
		appendCandidate(targetAddr)

		// FRP fix 3: also try the target's P2PEndpoint (TAP-side address).
		// In some configurations, the peer's P2P endpoint is directly
		// routable even when the STUN-discovered pubSocket is not.
		if peerInfo := reg.LookupPeerByPubSocket(punchTarget); peerInfo != nil {
			if peerInfo.P2PEndpoint != "" {
				if ep, err := net.ResolveUDPAddr("udp", peerInfo.P2PEndpoint); err == nil {
					appendCandidate(ep)
				}
			}
			// FRP parity: the peer also advertises its LAN addresses.
			// Normally already present via the instruction, but the
			// instruction is a snapshot and the registry entry may be
			// newer (or the instruction may predate this field entirely,
			// when talking to an older relay).
			for _, raw := range peerInfo.Infos.GetAssistedSockets() {
				if raw == "" {
					continue
				}
				if ep, err := net.ResolveUDPAddr("udp", raw); err == nil {
					appendCandidate(ep)
				}
			}
		} else {
			// Also try resolving targetP2PEndpoint from the instruction.
			if targetP2PEndpoint != "" && targetP2PEndpoint != punchTarget {
				if ep, err := net.ResolveUDPAddr("udp", targetP2PEndpoint); err == nil {
					appendCandidate(ep)
				}
			}
		}

		// FRP fix: for HardNAT (symmetric NAT), also send the receiver's
		// P2PEndpoint which may be on a directly routable subnet.
		// Collect additional IPs from the peer's Info if available.
		targetMAC := instr.GetTargetMac()
		if targetMAC != nil && len(targetMAC) > 0 {
			if p, err := reg.GetPeer(macAddrStr(targetMAC)); err == nil {
				// === A: prefer the OBSERVED address over the predicted one ===
				// p.P2PRaddr is the address this edge actually received a
				// packet from (learned from a punch packet or a relayed
				// packet's source). Under a NAT that allocates a different
				// public port per destination, the STUN-derived pubSocket is
				// only valid for the STUN server's destination — punching to
				// it lands on nothing. FRP has the same property and solves
				// it by always replying to the observed raddr; here we go one
				// step further and punch straight at the observed address.
				if p.P2PRaddr != "" {
					if ra, err2 := net.ResolveUDPAddr("udp", p.P2PRaddr); err2 == nil && ra != nil {
						// Put the observed address FIRST so it is tried
						// before any predicted/published candidates.
						candidates = append([]*net.UDPAddr{ra}, candidates...)
						log.Printf("[P2P] Sender: using OBSERVED raddr %s for target %s (ahead of predicted candidates)",
							p.P2PRaddr, macAddrStr(targetMAC))
					}
				}
				// The receiver's own LAN addresses -- FRP's m.AssistedAddrs,
				// which the sender tries ahead of the predicted/public
				// candidates. Same reason as above: on a shared LAN the
				// packet is answered by the peer itself and needs no NAT
				// mapping to exist yet, whereas the public address depends
				// on the local router hairpinning.
				//
				// Added right after the observed address rather than ahead
				// of it: raddr was proven reachable by an actual packet,
				// these are only claims. Order among themselves is the
				// order the peer reported them, so a multi-homed host
				// keeps its own preference.
				assistedRaw := p.Infos.GetAssistedSockets()
				// Rank the peer's LAN addresses by whether they sit on a
				// subnet this host is also on, so the one address that can
				// actually complete a shared-LAN punch is tried first
				// instead of after every guaranteed-to-fail virtual
				// interface the peer happens to own. Reported order is kept
				// among equally-ranked entries (stable sort).
				localPrefixes := localNATPunchPrefixes(reg.SelfTapName, reg.SelfTapIP(), reg.SelfMAC())
				assisted := sortAssistedByLocalAffinity(assistedRaw, localPrefixes)
				if !sameOrder(assistedRaw, assisted) {
					log.Printf("[P2P] Sender: target %s reported LAN addresses %v, reordered to %v "+
						"(same-subnet-first against our %d local subnet(s))",
						macAddrStr(targetMAC), assistedRaw, assisted, len(localPrefixes))
				}
				for _, raw := range assisted {
					if raw == "" {
						continue
					}
					if ep, err2 := net.ResolveUDPAddr("udp", raw); err2 == nil {
						appendCandidate(ep)
					}
				}
				if len(assisted) > 0 {
					log.Printf("[P2P] Sender: target %s reported %d LAN address(es) (%v), added as punch candidates",
						macAddrStr(targetMAC), len(assisted), assisted)
				}

				// Try P2PEndpoint as an additional candidate
				if p.P2PEndpoint != "" {
					if ep, err2 := net.ResolveUDPAddr("udp", p.P2PEndpoint); err2 == nil && ep != nil {
						alreadyAdded := false
						for _, c := range candidates {
							if c.String() == ep.String() {
								alreadyAdded = true
								break
							}
						}
						if !alreadyAdded {
							candidates = append(candidates, ep)
						}
					}
				}
			}
		}

		log.Printf("[P2P] Sender: punching to %d candidate addresses (primary=%s, ports %d-%d, ttl=%d)",
			len(candidates), punchTarget, portsFrom, portsTo, ttl)

		// FRP parity: one datagram per address, then wait.
		//
		// The previous code burst ttl*3 packets 20ms apart and slept 300ms
		// before giving up. That conflated the IP hop limit with a packet
		// count, and — more importantly — compressed the entire send phase
		// into ~420ms, which is shorter than the time the peer needs to
		// answer. The NAT mapping created by these packets stays valid for
		// seconds, so a single packet followed by a long wait is both closer
		// to FRP and strictly more likely to be observed.
		for ci, candAddr := range candidates {
			if candAddr == nil {
				continue
			}
			if err := sendPunchOnce(p2pConn, punchPacket, candAddr, ttl, "Sender"); err != nil {
				log.Printf("[P2P] Sender: punch to candidate %d (%s) failed: %v", ci, candAddr.String(), err)
			} else {
				log.Printf("[P2P] Sender: punched candidate %d %s once (ttl=%d)", ci, candAddr.String(), ttl)
			}

			// Port scanning: one datagram per port. FRP likewise emits a
			// single packet per CandidatePort; the mapping it opens is what
			// matters, not repetition.
			scanMin := int(portsFrom)
			scanMax := int(portsTo)
			if scanMin >= 1 && scanMax >= scanMin {
				for port := scanMin; port <= scanMax; port++ {
					if candAddr.IP == nil || port == candAddr.Port {
						continue
					}
					punchAddr := &net.UDPAddr{IP: candAddr.IP, Port: port}
					_ = sendPunchOnce(p2pConn, punchPacket, punchAddr, ttl, "Sender/scan")
				}
				log.Printf("[P2P] Sender: candidate %d done — exact addr %s + one packet per port %d-%d",
					ci, candAddr.String(), scanMin, scanMax)
			} else {
				log.Printf("[P2P] Sender: candidate %d done — exact addr %s (no port scan)", ci, candAddr.String())
			}
		}

		// Long wait, as FRP's waitDetectMessage does.
		if tm := instr.GetTargetMac(); tm != nil && len(tm) > 0 {
			waitForPunchSuccess(reg, macAddrStr(tm), "Sender")
		} else {
			// Without a target MAC there is nothing to poll; fall back to
			// the same timeout so the round still lasts as long as FRP's.
			log.Printf("[P2P] Sender: instruction carries no target MAC, waiting %s without a success check", natHoleReadTimeout)
			time.Sleep(natHoleReadTimeout)
		}
	} else {
		// Receiver: for HardNAT, we must also send punch packets to the
		// sender's pubSocket to create a NAT mapping on our side, otherwise
		// the sender's packets will be dropped by our symmetric NAT.
		// We also listen briefly for the sender's punch packets.
		log.Printf("[P2P] Receiver: punching to %s and listening on ports %d-%d for punch packets",
			punchTarget, portsFrom, portsTo)
		if p2pConn == nil {
			return false
		}

		// Send punch packets to the sender's pubSocket to create our NAT mapping.
		// For HardNAT, scan the port range as well.
		senderAddr, err := net.ResolveUDPAddr("udp", punchTarget)
		if err != nil {
			log.Printf("[P2P] Receiver: cannot resolve sender pubSocket %s: %v", punchTarget, err)
		} else {
			punchPacket := []byte{0xFF, 0xFE, 0xFD, 0xFC}
			senderIP := senderAddr.IP
			if senderIP == nil || senderIP.IsUnspecified() {
				// Fallback: single address
				for i := 0; i < int(ttl); i++ {
					p2pConn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
					_, err := p2pConn.WriteToUDP(punchPacket, senderAddr)
					if err != nil {
						log.Printf("[P2P] Receiver: punch write error: %v", err)
					}
					time.Sleep(50 * time.Millisecond)
				}
			} else {
				// Always send to the sender's exact pubSocket first.
				//
				// This mirrors the sender branch ("CRITICAL FIX: always send
				// at least one packet to the receiver's exact pubSocket
				// port first"). Without it, a Mode 0 instruction — which
				// deliberately carries portsRangeFrom/To = 0 to disable
				// scanning — would make the receiver emit no punch packets
				// at all, so its own NAT mapping would never be created and
				// the sender's packets would always be dropped.
				// === FRP Mode 0: low-TTL pre-mapping probe ===
				//
				// Before anything else, push a few copies of the punch
				// packet at the sender with a lowered IP TTL. The datagrams
				// are discarded somewhere along the path and never reach
				// the sender, but the NAT on the way out has already
				// allocated a mapping for (our socket, sender's pubSocket)
				// -- which is exactly the mapping the sender's own punch
				// needs the receiver's NAT to have open.
				//
				// The delay that used to be missing is the whole point of
				// this probe: it front-loads our mapping by the time the
				// sender starts punching, without waiting for the sender's
				// first packet to arrive and be accepted.
				//
				// FRP parity, Mode 0 (analysis.go:33-49). Ladder entries 0-3
				// carry a TTL and get the probe; entries 4 and 5 carry none
				// at all, and sendSidMessage (nathole.go:363 `if ttl > 0`)
				// leaves the socket's normal TTL in place for them. Those are
				// the entries to reach for on a path longer than the TTL:
				// a probe that dies before the NAT translation point creates
				// no mapping at all, so the pair can never punch. Protobuf3
				// cannot tell an unset ttl from 0, so the ladder position
				// travels in its own field and is what we consult here.
				probeTTL := natHoleProbeTTL(instr, receiverProbeIPTTL)
				if probeTTL <= 0 {
					log.Printf("[P2P] Receiver: ladder entry mode=%d index=%d carries no TTL — sending the probe with the socket's normal TTL (full path)",
						instr.GetMode(), instr.GetBehaviorIndex())
				}
				probeTargets := []*net.UDPAddr{senderAddr}
				for port := int(portsFrom); port >= 1 && port <= int(portsTo) && len(probeTargets) < 32; port++ {
					if port == senderAddr.Port {
						continue
					}
					probeTargets = append(probeTargets, &net.UDPAddr{IP: senderIP, Port: port})
				}
				if n := sendWithIPTTL(p2pConn, punchPacket, probeTargets, probeTTL, 20*time.Millisecond); n > 0 {
					log.Printf("[P2P] Receiver: sent %d/%d pre-mapping probe(s) to %s (IP TTL=%d, mode=%d index=%d, --nat-hole-probe-ttl default=%d)",
						n, len(probeTargets), punchTarget, probeTTL, instr.GetMode(), instr.GetBehaviorIndex(), receiverProbeIPTTL)
				}

				// FRP parity: one datagram at the exact address, then wait.
				// Replaces the previous burst of ttl*3 packets 20ms apart, which
				// (like the sender branch) conflated the IP hop limit with a
				// packet count and finished sending before the peer's mapping
				// could plausibly have existed.
				if err := sendPunchOnce(p2pConn, punchPacket, senderAddr, ttl, "Receiver"); err != nil {
					log.Printf("[P2P] Receiver: punch to sender %s failed: %v", senderAddr.String(), err)
				} else {
					log.Printf("[P2P] Receiver: punched sender %s once (ttl=%d)", senderAddr.String(), ttl)
				}

				// Port scanning for HardNAT only. A zero range means Mode 0
				// (FRP sends an empty CandidatePorts list), i.e. the exact
				// address above is sufficient and scanning is disabled.
				// One datagram per port, as FRP emits per CandidatePort.
				for port := int(portsFrom); port >= 1 && port <= int(portsTo); port++ {
					if port == senderAddr.Port {
						continue
					}
					_ = sendPunchOnce(p2pConn, punchPacket, &net.UDPAddr{IP: senderIP, Port: port}, ttl, "Receiver/scan")
				}
			}

			// Long wait, as FRP's waitDetectMessage does. Both roles watch the
			// same observable: handleP2P sets FullDuplex when it recognises the
			// peer's punch magic and ACKs the peer's source address.
			if tm := instr.GetTargetMac(); tm != nil && len(tm) > 0 {
				waitForPunchSuccess(reg, macAddrStr(tm), "Receiver")
			} else {
				log.Printf("[P2P] Receiver: instruction carries no target MAC, waiting %s without a success check", natHoleReadTimeout)
				time.Sleep(natHoleReadTimeout)
			}
		}
		// NOTE: The handleP2P/handleUDP/handleWSS loop now sends a punch
		// ACK response back to the sender's source address when it receives
		// a punch packet. This mirrors FRP's waitDetectMessage behavior:
		// the receiver responds to raddr (NAT-mapped source) not pubSocket,
		// allowing bidirectional connectivity through cloud NATs that lack
		// explicit UDP port forwarding.
	}

	// Note: FullDuplex is NOT set here optimistically. It is only set to true
	// when the receiver's handleP2P detects the inbound punch magic bytes,
	// proving bidirectional UDP connectivity. If UDP is not routable between
	// peers (e.g., behind Cloudflare Tunnel), the PING/PONG exchange via
	// WebSocket will keep FullDuplex=false and data will flow through the
	// supernode relay.

	// Check if we achieved FullDuplex with the target peer. If so, clear
	// the instruction. If not, keep it for retry on the next cycle (up to
	// a maximum number of attempts) so that transient NAT timing issues
	// don't permanently prevent hole punching.
	targetMAC := instr.GetTargetMac()
	achievedFullDuplex := false
	if targetMAC != nil && len(targetMAC) > 0 {
		targetMACStr := macAddrStr(targetMAC)
		if p, err := reg.GetPeer(targetMACStr); err == nil {
			if p.IsFullDuplex {
				achievedFullDuplex = true
			}
		}
	}

	if achievedFullDuplex {
		log.Printf("[P2P] NatHole punch succeeded — FullDuplex achieved with target, clearing instruction")
		reg.peerMu.Lock()
		if _, ok := reg.natHoleInstrs[instrKey]; ok {
			delete(reg.natHoleInstrs, instrKey)
			delete(reg.natHoleRetryCounts, instrKey)
		} else {
			// Instruction was already replaced or cleared — clear all
			for k := range reg.natHoleInstrs {
				delete(reg.natHoleInstrs, k)
			}
		}
		reg.peerMu.Unlock()
	} else {
		// Check retry count using the captured instrKey instead of
		// pointer comparison (v == instr was buggy because
		// SetNatHoleInstruction may replace the instruction pointer
		// between the RLock and the subsequent Lock, causing the
		// pointer comparison to fail and retryCount to reset to 0
		// every cycle — resulting in "attempt 1/5" repeating forever).
		reg.peerMu.Lock()
		currentInstr, ok := reg.natHoleInstrs[instrKey]
		if !ok {
			// Instruction was cleared or replaced by the Worker.
			// If a new instruction exists, use its key.
			for k := range reg.natHoleInstrs {
				instrKey = k
				currentInstr = reg.natHoleInstrs[k]
				ok = true
				break
			}
		}
		if ok {
			retryCount := reg.natHoleRetryCounts[instrKey]
			if retryCount >= 0 && retryCount < 5 {
				// Increment retry count and keep instruction for next cycle.
				reg.natHoleRetryCounts[instrKey] = retryCount + 1
				log.Printf("[P2P] NatHole punch attempt %d/5 failed (no FullDuplex yet), will retry in ~2s", retryCount+1)
				// Tell the relay a round is still in flight so it does not
				// push a duplicate instruction while we are still working.
				if currentInstr != nil {
					if tm := currentInstr.GetTargetMac(); len(tm) > 0 {
						tmStr := macAddrStr(tm)
						if reg.natHolePunchResults == nil {
							reg.natHolePunchResults = make(map[string]*NatHolePunchResult)
						}
						reg.natHolePunchResults[tmStr] = &NatHolePunchResult{
							State:         NatHolePunchState_PunchStateInProgress,
							Attempts:      uint32(retryCount + 1),
							Detail:        "retrying",
							BehaviorIndex: currentInstr.GetBehaviorIndex(),
						}
						reg.hasPendingChanges = true
					}
				}
			} else {
				// Max retries reached, clear instruction to stop retrying
				log.Printf("[P2P] NatHole punch failed after 5 attempts, clearing instruction")
				delete(reg.natHoleInstrs, instrKey)
				delete(reg.natHoleRetryCounts, instrKey)
				// Mark peer as P2PUnavailable so data uses WebSocket relay.
				// NOTE: do NOT call reg.GetPeer() here — we already hold
				// peerMu.Lock() and GetPeer() takes peerMu.RLock(). Go's
				// RWMutex is NOT reentrant, so that self-deadlocks the whole
				// process (observed: edge froze permanently after the 5th
				// failed punch, and later deadlocked handlePeerInfoMessage
				// which was blocked on AddPeer waiting for the write lock).
				// Look the peer up directly in the map instead.
				if currentInstr != nil {
					targetMAC := currentInstr.GetTargetMac()
					if targetMAC != nil && len(targetMAC) > 0 {
						targetMACStr := macAddrStr(targetMAC)
						if p, ok := reg.Peers[targetMACStr]; ok {
							p.P2PStatus = P2PUnavailable
							log.Printf("[P2P] Marked peer %s as P2PUnavailable after failed hole punch", targetMACStr)
						}
						// Report the failure so the relay stops waiting on
						// this instruction and re-broadcasts a fresh one
						// (under its own backoff) instead of assuming the
						// pair is still in progress. Written directly
						// because peerMu is already held here.
						if reg.natHolePunchResults == nil {
							reg.natHolePunchResults = make(map[string]*NatHolePunchResult)
						}
						reg.natHolePunchResults[targetMACStr] = &NatHolePunchResult{
							State:         NatHolePunchState_PunchStateFailed,
							Attempts:      5,
							Detail:        "exhausted 5 punch attempts",
							BehaviorIndex: currentInstr.GetBehaviorIndex(),
						}
						reg.hasPendingChanges = true
						log.Printf("[P2P] Reported punch FAILED for %s to relay", targetMACStr)
					}
				}
			}
			_ = currentInstr // suppress unused variable warning
		}
		reg.peerMu.Unlock()
	}

	return achievedFullDuplex
}

// HandlePeerInfoList processes a peer.PeerInfoList and updates the registry accordingly.
// Depending on the event type, it may override or populate the full registry (ListEvent),
// with an option to overwrite existing P2PStatuses, or it may add or delete peers.
func (reg *PeerRegistry) HandlePeerInfoList(peerInfoList *PeerInfoList, reset bool, overwrite bool) error {

	// Compute our MAC once for self-skip in all event types.
	ourMAC := ""
	if reg.Me != nil {
		ourMAC = net.HardwareAddr(reg.Me.Infos.MacAddr).String()
	}

	switch PeerInfoEventType(peerInfoList.GetEventType()) {
	case TypeList:
		if reset {
			reg.peerMu.Lock()
			reg.Peers = make(map[string]*Peer)
			reg.peerBySocket = make(map[string]*Peer)
			reg.peerByP2PSocket = make(map[string]*Peer)
			reg.peerMu.Unlock()
			log.Printf("resetting peer registry")
		}
		if peerInfoList.GetHasOrigin() {
			me := &Peer{
				Infos:     *peerInfoList.GetOrigin(),
				UpdatedAt: time.Now(),
			}
			reg.Me = me
			log.Printf("setting self PeerInfo from Origin Peerlist in supernode")
			ourMAC = net.HardwareAddr(me.Infos.MacAddr).String()
		}
		for _, info := range peerInfoList.GetPeerInfos() {
			peerMAC := net.HardwareAddr(info.MacAddr).String()
			if ourMAC != "" && peerMAC == ourMAC {
				// Skip self — the relay broadcasts the full peer list to
				// each edge, which includes this edge's own entry. Adding
				// ourselves to our own registry causes self-pings and
				// incorrect NAT hole-punching target lookups.
				continue
			}
			_, err := reg.AddPeer(*info, overwrite)
			if err != nil {
				return fmt.Errorf("failed to add peer: %v", err)
			}
		}
		if !reset {
			// Remove peers that are not in the new list.
			// Also explicitly exclude our own MAC so that any stale self-entry
			// (from a previous broadcast where reg.Me was nil) is cleaned up.
			newPeers := make(map[string]struct{})
			for _, info := range peerInfoList.GetPeerInfos() {
				macAddr := net.HardwareAddr(info.MacAddr).String()
				if ourMAC != "" && macAddr == ourMAC {
					continue // never treat self as a "new" peer
				}
				newPeers[macAddr] = struct{}{}
			}

			for macAddr := range reg.Peers {
				if macAddr == ourMAC {
					// Self-peer in registry — remove it to fix self-ping bug
					_ = reg.RemovePeer(macAddr)
					log.Printf("removed stale self-peer with MAC %s from registry", macAddr)
					continue
				}
				if _, exists := newPeers[macAddr]; !exists {
					reg.RemovePeer(macAddr)
					log.Printf("removed peer with MAC address %s not in new list", macAddr)
				}
			}
		}
	case TypeRegister:
		for _, info := range peerInfoList.GetPeerInfos() {
			peerMAC := net.HardwareAddr(info.MacAddr).String()
			if ourMAC != "" && peerMAC == ourMAC {
				continue
			}
			_, err := reg.AddPeer(*info, overwrite)
			if err != nil {
				return fmt.Errorf("failed to add peer: %v", err)
			}
		}
	case TypeUnregister:
		// FRP parity: pkg/nathole/controller.go:269-274
		//
		//   session, ok := c.sessions[m.Sid]
		//   if !ok { return }
		//
		// A frpc never holds a registry of its peers, so a peer leaving can
		// only ever be expressed as "this one specific node is gone" -- and
		// even that is not modelled as a removal, only as the expiry of the
		// per-pair session. Nothing a remote peer does can reach into this
		// process and delete an unrelated entry.
		//
		// The self-skip matters because the relay may legitimately include
		// our own entry (it is building the list from the full peer table,
		// and we are one of its peers). Deleting our own registry entry
		// silently breaks GetPeer/AddPeer for every later message.
		for _, info := range peerInfoList.GetPeerInfos() {
			macAddr := net.HardwareAddr(info.MacAddr).String()
			if ourMAC != "" && macAddr == ourMAC {
				continue
			}
			err := reg.RemovePeer(macAddr)
			if err != nil {
				return fmt.Errorf("failed to remove peer: %v", err)
			}
		}
	default:
		return fmt.Errorf("unknown event type: %v", peerInfoList.GetEventType())
	}
	return nil
}
