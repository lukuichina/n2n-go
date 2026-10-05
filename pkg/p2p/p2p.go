package p2p

import (
	"fmt"
	"n2n-go/pkg/log"
	"net"
	"net/netip"
	"sort"
	"strconv"
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
	Infos        PeerInfo
	P2PStatus    P2PCapacity
	IsFullDuplex bool
	P2PCheckID   string
	pendingTTL   int
	UpdatedAt    time.Time
	P2PEndpoint  string
	// p2pEndpointAt is when P2PEndpoint was last replaced by an
	// announcement, and is what distinguishes a live address from a retired
	// one.
	//
	// A peer re-punching allocates a fresh temporary UDP socket every time, so
	// the endpoint it advertises changes while the process keeps running, and
	// the previous value stops being valid the moment that socket closes. The
	// long-lived socket is separate, so "which port does this peer answer on"
	// is not answerable from anything but the newest announcement: observed
	// 2026-09-30, E2 moved 59679 -> 58634 at 16:11:22 and reported the change
	// five times, yet E1 still punched 59679 at 16:12:00, five failed rounds
	// later. Timestamping each announced endpoint lets that staleness be
	// detected rather than guessed at.
	//
	// Set by SetP2PEndpoint; read via LastP2PEndpointAt. Guarded by the
	// registry's peerMu, like the rest of the P2P address state.
	p2pEndpointAt   time.Time
	P2PCapabilities []string
	// NatHoleExecuted marks whether this peer has already executed the
	// relay-coordinated NAT hole-punching instruction.
	NatHoleExecuted bool
	// P2PRaddr stores the NAT-mapped source address observed by this edge
	// when receiving punch/ACK packets from the peer. This is the "raddr"
	// equivalent in FRP — the actual address through which the peer can
	// be reached (accounting for Symmetric NAT port remapping), which may
	// differ from the STUN-discovered pubSocket.
	//
	// Written from the receive goroutine on every punch/ACK and read from the
	// data path on every packet (UDPAddrWithStrategy), so it is guarded by
	// raddrMu. Use GetP2PRaddr/SetP2PRaddr rather than touching the field.
	P2PRaddr string
	raddrMu  sync.RWMutex
	// raddrAt is when P2PRaddr last took a new value, i.e. when we last heard
	// from this peer on the socket that raddr describes. Guarded by raddrMu,
	// stamped by SetP2PRaddr.
	//
	// Its only purpose is to date the raddr against pubSocketChangedAt: an
	// observed source address is evidence about one socket generation, and a
	// peer that re-announces a different public mapping has provably moved to
	// another one. See RaddrAt and PubSocketChangedAt.
	raddrAt time.Time
	// pubSocketChangedAt is when this peer's advertised public mapping last
	// took a different value -- not when it was last re-announced. An
	// unchanged re-announcement must not bump it: peers re-broadcast their
	// PeerP2PInfos every few seconds, and dating the freshness test on those
	// would expire every raddr within seconds and throw away the one address
	// that survives a symmetric NAT.
	//
	// Guarded by the registry's peerMu, like the rest of the P2P address
	// state; stamped by AddPeer.
	pubSocketChangedAt time.Time
	// indexedRaddr is the key currently held in PeerRegistry.peerBySocket on
	// this peer's behalf as an observed raddr. Guarded by the registry's
	// peerMu, not by P2PRaddr: P2PRaddr is assigned before the index is
	// updated, so it cannot be used to find what to retire.
	indexedRaddr string

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

	// punchPathOpen records that the punch handshake for this pair
	// completed: we exchanged punch packets and both NAT mappings are open,
	// so packets can flow even though no real data frame has been
	// confirmed yet.
	//
	// This is the missing half of the punch verdict and it exists because
	// P2PStatus cannot express it. P2PStatus answers "which path may this
	// peer use", and its only affirmative answers are Available and
	// FullDuplex. But FullDuplex is gated on a verified data frame
	// (HasVerifiedDataPath), so during the window between "the hole is
	// punched" and "the first frame proves it" there is no status that is
	// both true and affirmative -- and the punch loop's own report of that
	// window, PunchStateInProgress, was being smuggled into the status
	// field on its way to the relay. The relay read it back, and a control
	// plane probe arriving in the same instant overwrote the peer's status
	// with Unknown, discarding a path that was already carrying traffic.
	//
	// Observed 2026-10-04 on log3 (192.168.10.7) against log4
	// (172.22.2.44), both behind CGNAT 111.101.5.1. The pair reached
	// strat=2 via p2p at 21:08:52 and was demoted to relay by Unknown
	// nine times before the first data frame landed at 21:09:28 -- 36 of
	// the 40 seconds the pair needed, spent re-punching a hole that had
	// been open the whole time.
	//
	// It is a capability, not a status: it never travels to the relay and
	// never appears in PeerP2PInfos. Nothing should set it from a control
	// plane message. Guarded by raddrMu with the other punch evidence,
	// since NotePunchPacket on the reader goroutine sets it.
	punchPathOpen   bool
	punchPathOpenAt time.Time

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
	key := fmt.Sprintf("%s|%s|%s|%s", p.P2PStatus.String(), p.GetP2PRaddr(), p.UDPAddr(), path)

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
			net.HardwareAddr(p.Infos.MacAddr).String(), p.P2PStatus, p.GetP2PRaddr(), p.UDPAddr(), strategy, path, target)
	}
}

// SetP2PEndpoint updates the peer's P2P endpoint address (e.g. "host:port")
// and stamps it as freshly announced, so LastP2PEndpointAt can order records
// by how recently they were heard.
func (p *Peer) SetP2PEndpoint(endpoint string) {
	p.P2PEndpoint = endpoint
	p.p2pEndpointAt = time.Now()
}

// LastP2PEndpointAt reports when this peer's P2P endpoint was last announced.
func (p *Peer) LastP2PEndpointAt() time.Time {
	return p.p2pEndpointAt
}

// SetP2PCapabilities updates the peer's P2P capability list.
func (p *Peer) SetP2PCapabilities(caps []string) {
	p.P2PCapabilities = caps
}

// GetP2PRaddr returns the peer's observed NAT-mapped source address.
//
// The data path calls this once per packet, so the read lock is taken and
// released here rather than by the caller reaching into the field.
func (p *Peer) GetP2PRaddr() string {
	p.raddrMu.RLock()
	defer p.raddrMu.RUnlock()
	return p.P2PRaddr
}

// SetP2PRaddr stores the NAT-mapped source address observed when receiving
// packets from this peer. This is the actual reachable address under
// Symmetric NAT (where the STUN-discovered port may differ).
func (p *Peer) SetP2PRaddr(addr string) {
	p.raddrMu.Lock()
	if p.P2PRaddr != addr {
		// Only a genuinely new value proves the peer is still on the socket
		// this address describes. Re-stamping on an identical address would
		// make the freshness test in ResolvePunchTarget pass forever.
		p.raddrAt = time.Now()
	}
	p.P2PRaddr = addr
	p.raddrMu.Unlock()
}

// RaddrAt reports when this peer's observed source address last changed.
// A zero time means the peer has never been heard from on any socket.
func (p *Peer) RaddrAt() time.Time {
	p.raddrMu.RLock()
	defer p.raddrMu.RUnlock()
	return p.raddrAt
}

// PubSocketChangedAt reports when this peer last announced a *different*
// public mapping than before.
func (p *Peer) PubSocketChangedAt() time.Time {
	return p.pubSocketChangedAt
}

// RaddrCoversCurrentMapping reports whether P2PRaddr can still describe the
// socket this peer is using now.
//
// It can, as long as the peer has not announced a different public mapping
// since we last heard from it. A peer that re-registers behind a new mapping
// has either restarted or had its NAT mapping rotated, and in both cases the
// previous mapping's port belongs to a socket that no longer exists -- so an
// raddr observed before that moment is stale, however much we trusted it when
// we first saw it.
//
// Observed 2026-10-03: E1 and E2 punched 111.101.5.1:63654 and
// 111.101.5.1:60735 101 and 84 times respectively -- log3's and log4's ports
// from the previous processes -- while the live peers announced
// 111.101.5.1:53781 and :49570. Both receivers were punching the correct
// address, so the pair failed in one direction only, and every round burned
// all five retries against a closed port. The peers share one MAC across
// restarts, so the registry keeps the record; the raddr in it is what outlived
// the socket.
func (p *Peer) RaddrCoversCurrentMapping() bool {
	if p.GetP2PRaddr() == "" {
		return false
	}
	return !p.pubSocketChangedAt.After(p.RaddrAt())
}

// NotePunchPacket records that a punch/ACK arrived from this peer.
//
// It deliberately does NOT promote the peer to FullDuplex. See the comment on
// punchSeenAt/dataSeenAt: a punch alone is not proof the data path works.
// IndexPeerRaddr makes the peer's observed raddr resolvable by
// GetPeerBySocket, and retires the previous one.
//
// The raddr is the source address a packet from this peer actually arrived
// from, which under SNAT is an address neither side ever advertised: the
// router's own WAN address. It therefore cannot appear in the assisted set
// that lookupSockets indexes, so a data frame arriving from it failed the
// lookup, was never attributed, and the peer was never promoted to
// FullDuplex -- even though the packets were demonstrably getting through.
// Punch packets escaped this only because they are matched by MAC through a
// separate attribution window, which is why the hole looked punched while
// the data path stayed dead.
func (reg *PeerRegistry) IndexPeerRaddr(p *Peer, raddr string) {
	if reg == nil || p == nil || raddr == "" {
		return
	}
	key := normalizeSocketKey(raddr)

	reg.peerMu.Lock()
	defer reg.peerMu.Unlock()

	// Retire the previously indexed raddr, but only if it is not also a
	// legitimately advertised address -- deleting a pubSocket or assisted key
	// here would break lookups that still need to resolve. The previous key
	// comes from indexedRaddr, not from p.P2PRaddr: callers assign P2PRaddr
	// before calling this, so reading it back would always yield the new key
	// and the old one would live forever.
	if prev := p.indexedRaddr; prev != "" && prev != key {
		advertised := make(map[string]bool)
		for _, k := range p.lookupSockets() {
			advertised[k] = true
		}
		if !advertised[prev] {
			if owner, ok := reg.peerBySocket[prev]; ok && owner == p {
				delete(reg.peerBySocket, prev)
			}
		}
	}
	p.indexedRaddr = key
	reg.peerBySocket[key] = p
}

func normalizeSocketKey(raw string) string {
	if raw == "" {
		return ""
	}
	if ua, err := net.ResolveUDPAddr("udp", raw); err == nil && ua != nil {
		return ua.String()
	}
	return raw
}

func (p *Peer) NotePunchPacket() {
	p.raddrMu.Lock()
	p.punchSeenAt = time.Now()
	p.raddrMu.Unlock()
}

// PunchSeenAt reports when a punch/ACK last arrived from this peer. Read
// under raddrMu for the same reason as LastDataSeenAt: the P2P reader
// goroutine writes it while the punch wait loop and
// GetPunchedNotFullDuplexPeers read it from their own goroutines.
func (p *Peer) PunchSeenAt() time.Time {
	p.raddrMu.RLock()
	defer p.raddrMu.RUnlock()
	return p.punchSeenAt
}

// NoteDataPacket records that a real ProtoV frame arrived from this peer over
// the P2P UDP socket. This is the only evidence that promotes FullDuplex.
//
// Guarded by raddrMu, the same lock P2PRaddr uses. The writer here is the
// P2P socket reader goroutine (routines.go handleP2P) and the readers are the
// keepalive tick plus every promotion gate, which run concurrently on their
// own goroutines. As a bare field this was a data race, and the failure mode
// was silent and expensive: the keepalive read a stale time.Time, computed a
// timeout that grew without bound (37s, 47s, ... 28m -- monotonically, because
// the stale value never moved), and demoted a peer that was in fact still
// exchanging real frames. Observed 2026-10-02 between log3 (192.168.10.7) and
// log4 (172.22.2.44): 166 demotions while the direct path carried traffic
// right through to the end of the log.
func (p *Peer) NoteDataPacket() {
	p.raddrMu.Lock()
	p.dataSeenAt = time.Now()
	// A real frame is the strongest form of the same fact the punch handshake
	// records, so it must keep the capability set even if the handshake was
	// the slower of the two to land.
	p.punchPathOpen = true
	p.punchPathOpenAt = p.dataSeenAt
	p.raddrMu.Unlock()
}

// NotePunchPathOpen records that the punch handshake completed for this
// peer, so a direct path exists even if no data frame has been verified yet.
// Deliberately idempotent and monotonic within a path's lifetime: a later
// punch packet cannot un-open a hole. Only ClearPunchPath, driven by the
// data-plane keepalive timeout, closes it again.
func (p *Peer) NotePunchPathOpen() {
	p.raddrMu.Lock()
	if !p.punchPathOpen {
		p.punchPathOpenAt = time.Now()
		p.punchPathOpen = true
	}
	p.raddrMu.Unlock()
}

// PunchPathOpen reports whether a direct path to this peer is known to be
// open -- either because the punch handshake completed or because a real data
// frame arrived. Guarded by raddrMu, like the punch evidence it is derived
// from.
func (p *Peer) PunchPathOpen() bool {
	p.raddrMu.RLock()
	defer p.raddrMu.RUnlock()
	return p.punchPathOpen
}

// ClearPunchPath withdraws the open-path capability. The only caller is the
// data-plane keepalive, which is the sole authority entitled to say a direct
// path stopped working: a control plane probe failing to arrive is not
// evidence that traffic stopped.
func (p *Peer) ClearPunchPath() {
	p.raddrMu.Lock()
	p.punchPathOpen = false
	p.punchPathOpenAt = time.Time{}
	p.raddrMu.Unlock()
}

// LastDataSeenAt returns when a real data frame was last received from this
// peer over P2P (zero time if never).
func (p *Peer) LastDataSeenAt() time.Time {
	p.raddrMu.RLock()
	defer p.raddrMu.RUnlock()
	return p.dataSeenAt
}

// HasVerifiedDataPath reports whether a real data frame has ever been
// received from this peer over the P2P socket. Used as the promotion gate.
func (p *Peer) HasVerifiedDataPath() bool {
	return !p.LastDataSeenAt().IsZero()
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
	// graceUnlisted holds peers removed purely for being absent from a
	// PeerInfoList, keyed by MAC, pending reappearance within
	// GraceUnlistedTTL. Guarded by peerMu. See GraceUnlistedTTL for why.
	graceUnlisted map[string]*graceTombstone
	p2pDatasMu    sync.RWMutex
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
	// natHoleInstrKey is the key SetNatHoleInstruction last stored under. Kept
	// for ReArmNatHoleInstruction, which is called with the PEER's MAC and
	// cannot always derive the current key itself.
	natHoleInstrKey string
	// natHoleRoundRobin rotates which pending instruction ExecuteNatHolePunch
	// serves next, so every peer awaiting a punch gets one instead of the same
	// one winning every round.
	natHoleRoundRobin uint64
	// Latest hole-punch outcome per peer MAC, reported to the relay in
	// GetPeerP2PInfos so it can stop re-broadcasting for pairs that are
	// already up and re-arm pairs that just failed. Without this feedback
	// the relay is blind and either loops forever or gives up too early.
	natHolePunchResults map[string]*NatHolePunchResult
	// natHoleLastRound records when a punch round last reported an outcome
	// for a peer, and natHoleStallCount how many times
	// ReArmStalledNatHolePeers has re-armed a pair that never reached a
	// verified data path. Both are keyed by MAC and guarded by peerMu. See
	// ReArmStalledNatHolePeers for why a pair that fell back to the relay
	// used to have no way back.
	natHoleLastRound  map[string]time.Time
	natHoleStallCount map[string]int
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
		graceUnlisted:       make(map[string]*graceTombstone),
		natHoleInstrs:       make(map[string]*NatHoleInstruction),
		natHoleRetryCounts:  make(map[string]int),
		lastNatHoleInstrs:   make(map[string]*NatHoleInstruction),
		natHolePunchResults: make(map[string]*NatHolePunchResult),
	}
}

func (reg *PeerRegistry) GetPeerP2PInfos() *PeerP2PInfos {
	reg.peerMu.Lock()
	// Sweep expired tombstones here because this runs on every periodic
	// publish, which is frequent enough to keep the grace window honest
	// without needing a timer of its own. Done under the write lock rather
	// than the read lock below because the sweep mutates the maps.
	reg.expireGraceTombstonesLocked(time.Now())
	reg.peerMu.Unlock()

	reg.peerMu.RLock()
	if reg.Me == nil {
		reg.peerMu.RUnlock()
		return &PeerP2PInfos{}
	}
	var to []*PeerInfo
	// Punch outcomes handed to this message, cleared once the RLock is
	// released. See the pickup site below for why they are consumed.
	delivered := make([]string, 0, len(reg.natHolePunchResults))
	for _, v := range reg.Peers {
		// Publish the OBSERVED source address for each peer. This is the
		// address the peer's packets actually arrive from — the only one
		// guaranteed to traverse the peer's NAT. The Worker forwards it to
		// the other side so it can punch to a verified-reachable address
		// instead of the STUN snapshot (which may be stale or bound to a
		// different NAT mapping).
		infos := v.Infos
		// Only while the observation still covers the socket the peer is on
		// now. Reporting it regardless is how a stale address travels: the
		// Worker takes each entry as that peer's observedRaddr, so one host
		// still holding another's pre-restart raddr republishes it as current,
		// and the divergence then shows up in the relay's own record.
		//
		// Observed 2026-10-03 in the relay log for log3:
		//
		//	eligible mac=ea:2f:de:90:a5:72 pubSocket=111.101.5.1:53781
		//	                  observedRaddr=111.101.5.1:63654
		//
		// where :63654 was log3's port in its previous process, republished by
		// log4, which still held it in its registry. The relay does not
		// dispatch from observedRaddr, so the pairing was unaffected -- but the
		// field is read as "where packets from this peer actually arrive", and
		// on a symmetric NAT it is the field an operator would trust.
		if vrd := v.GetP2PRaddr(); vrd != "" && v.RaddrCoversCurrentMapping() {
			infos.ObservedRaddr = vrd
		}
		// Report the current status toward this peer so the relay can tell
		// whether a success it recorded still describes a live tunnel.
		// Without this the relay only learns that a punch once worked, never
		// that it stopped, and has to either suppress the pair forever or
		// re-punch a healthy one -- both seen in the field.
		//
		// This is published for every peer, not only those with a punch
		// outcome pending. It used to sit inside the `res != nil` branch
		// below, so a peer reported no status at all unless it had just been
		// punched -- which is exactly the peer whose status the relay most
		// needs. The relay reads it back off `to[].p2pStatus` (see
		// shouldRetireSuccess in the Worker), and reads it as undefined for
		// such a peer, so a live FullDuplex tunnel looked indistinguishable
		// from an unobservable one and the relay kept driving it.
		infos.P2PStatus = uint32(v.P2PStatus)

		// Hand over our latest punch outcome for this peer so the relay learns
		// whether to keep pushing instructions (in-progress/failed) or stop
		// entirely (succeeded). Reports are per-peer and carry the MAC they
		// refer to, so the relay never has to guess whose round this was.
		// Already holding peerMu.RLock for the whole traversal above; taking
		// it again here would risk a recursive-read deadlock against a waiting
		// writer.
		//
		// The outcome is consumed here rather than left in the map to be
		// re-sent. A punch result is an event -- "a round ended, this is how" --
		// not a level, so the relay only ever needs to hear it once; the relay
		// keeps the verdict in its own natHolePunchState. Leaving it resident
		// replayed the same event on every 2s publish instead:
		//
		//   [recordPunchResult] pair ... succeeded on ladder index 1 -> score 10
		//   [recordPunchResult] pair ... in-progress ... punch dispatched to ...
		//   [coordinateNatHole]  pair ... scheduled (...@1), backoff=15000ms
		//
		// The `score 10` is the damage: every repeat fed the analyzer again,
		// pushing the rung's score to its ceiling and erasing the signal the
		// ladder is meant to read. Observed 2026-10-03, where one pair logged
		// 1332 + 619 + 74 + 45 identical "succeeded" records.
		mac := macAddrStr(v.Infos.MacAddr)
		if res := reg.natHolePunchResults[mac]; res != nil {
			infos.PunchResult = res
			infos.PunchResultPeerMac = mac
			delivered = append(delivered, mac)
		}
		to = append(to, &infos)
	}
	infos := &PeerP2PInfos{
		From: &reg.Me.Infos,
		To:   to,
	}
	reg.peerMu.RUnlock()

	// Drop the outcomes this message just carried. Written under the write
	// lock, so it has to happen after the RLock above is released; the keys
	// were collected while it was held. A result recorded in the meantime
	// replaces the map entry outright, so deleting by key can only ever
	// discard the one that was actually reported, never a fresher verdict.
	//
	// If the publish fails after this point the outcome is lost, and the relay
	// drives one more round before hearing the verdict again. That costs a
	// round, not correctness: P2PStatus above still tells the relay the
	// tunnel is up, and the next round re-reports. This matches how
	// sendP2PInfos already treats pending changes -- ClearPendingChanges runs
	// before SendStruct for the same reason.
	if len(delivered) > 0 {
		reg.peerMu.Lock()
		for _, mac := range delivered {
			delete(reg.natHolePunchResults, mac)
		}
		reg.peerMu.Unlock()
	}
	return infos
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
		// Available, not Unavailable.
		//
		// At this point we have registered and our path to the supernode is
		// working -- the peer is reachable, merely over the relay rather than
		// direct. Available is what that means; Unavailable reads as "cannot be
		// reached at all", which is false from the moment STUN completes.
		//
		// Unavailable here was not merely a wrong label, it was load-bearing
		// in the wrong direction: UpdateP2PStatus force-writes Unavailable
		// whenever pendingTTL < 1 (p2p.go:919-922), and a Peer built by this
		// constructor rather than AddPeer never gets resetPendingTTL() called on
		// it, so its pendingTTL is the Go zero value. The peer was therefore
		// pinned at Unavailable by every subsequent status update and could not
		// leave that state -- observed as a peer that stayed Unavailable for the
		// whole run while relaying normally.
		P2PStatus: P2PAvailable,
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
	raw := make([]string, 0, 2+len(p.Infos.GetAssistedSockets()))
	if a := p.UDPAddr(); a != nil {
		raw = append(raw, a.String())
	}
	// P2PEndpoint must be indexed too, not just pubSocket and the assisted
	// set. It is the peer's own local listen address, which is the one a
	// punch packet most often arrives from once a router has rewritten the
	// source: behind 192.168.10.7 -> 192.168.10.1/172.22.1.17 the observed
	// source is the router, and neither pubSocket nor the assisted list
	// matched it. The packet then fell through to the mid-instruction
	// fallback in handleP2P, which attributed it to whichever peer the
	// current instruction named -- so a packet from ea:2f landing during a
	// punch with aa:bc got recorded against aa:bc, and log4 never learned
	// anything about log3 (observed 2026-10-02 07:37:44,
	// "Punch packet from 172.22.1.17:52784 attributed to instruction peer
	// aa:bc:3a:74:37:b1").
	if p.P2PEndpoint != "" {
		raw = append(raw, p.P2PEndpoint)
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

// receiverPunchCandidates ranks the addresses a receiver should punch at
// its sender, best first.
//
// The pubSocket is kept, but not first: it is the hardest path whenever both
// ends sit behind the same carrier NAT, because it can only work if the CGNAT
// hairpins. The sender's own LAN addresses come first when one of them is on
// a subnet we share, since that is direct routing by definition.
//
// The sender's overlay address is dropped. Our registry already knows their
// virtual IP, and punching an address inside the overlay delivers the packet
// back through the tunnel -- the self-referential path that made one node log
// 16779 packets from a peer's tap address.
func receiverPunchCandidates(instr *NatHoleInstruction, reg *PeerRegistry, pubSocket *net.UDPAddr) []*net.UDPAddr {
	return RankReceiverCandidates(instr, reg, pubSocket,
		LocalNATPunchPrefixes(reg.SelfTapName, reg.SelfTapIP(), reg.SelfMAC()))
}

func RankReceiverCandidates(instr *NatHoleInstruction, reg *PeerRegistry, pubSocket *net.UDPAddr, localPrefixes []netip.Prefix) []*net.UDPAddr {
	var out []*net.UDPAddr
	seen := make(map[string]bool)
	// A candidate that is one of our own addresses can never be the peer. The
	// relay fills these fields from what each side published, so a peer's
	// endpoint can arrive carrying our address back at us -- the relay has no
	// reason to prefer the correct pairing, and a peer behind a different
	// masquerade can legitimately publish something that collides with us.
	//
	// Observed 2026-10-05 on log5 (192.168.10.13) resolving a punch against
	// E2: the candidate list came back as
	//
	//	57.129.106.133:54369 (peer's endpoint)
	//	192.168.10.13:41559 (log5's own address)
	//
	// The second was rejected, but by the reachable-candidate filter rather
	// than by any judgement about identity, and that filter exists to drop
	// unroutable addresses -- not to recognise our own. Anything that made
	// our own address look reachable would punch at ourselves, spend the
	// whole ladder on it, and log a target resolution that reads as though
	// the peer were the problem.
	//
	// Port is deliberately not part of the test: the masquerade rewrites the
	// source port too, so an address with the wrong port is still us, and
	// requiring a port match would let our own address through whenever a
	// peer happens to publish a colliding one.
	selfIPs := localIPSet(reg)
	add := func(a *net.UDPAddr) {
		if a == nil || a.IP == nil || seen[a.String()] {
			return
		}
		if _, ours := selfIPs[a.IP.String()]; ours {
			log.Printf("[P2P] dropping punch candidate %s: it is one of our own addresses", a)
			return
		}
		seen[a.String()] = true
		out = append(out, a)
	}

	// The sender is identified by its pubSocket, not by TargetMac: in this
	// instruction TargetMac is the *receiver*, so the sender branch uses it
	// to look up the receiver's addresses. Reading it here would have found
	// our own overlay IP and filtered the wrong address.
	var peerTapIP string
	var observedRaddr string
	if reg != nil && pubSocket != nil {
		if sp := reg.LookupPeerByPubSocket(pubSocket.String()); sp != nil {
			peerTapIP = sp.Infos.GetVirtualIp()
			// The sender's observed raddr is the only address we have ever
			// seen its traffic come from, and it is routinely the only one
			// that works. The sender branch has sprayed to it since the
			// observed-raddr work; the receiver did not, which is
			// one-sided.
			//
			// Observed 2026-10-04 on log5 vs log3: log3 advertises
			// P2PEndpoint 192.168.10.7:58186 and is on the same /24 as
			// log5 (192.168.10.13), so the receiver ranked that address
			// first. It is undialable: a wireless repeater between them
			// splits the segment and masquerades, so log3's packets reach
			// log5 from 192.168.0.1:58186 and never from 192.168.10.7.
			// 117 status changes, no FullDuplex, fall back to relay. The
			// receiver's own log showed the 121 frames arriving from
			// 192.168.0.1 -- an address in no peer's registry entry.
			//
			// Spraying it costs one datagram and is gated on freshness, so a
			// stale raddr (one that predates the peer's current mapping) is
			// still skipped rather than turned back into a primary target.
			if r := sp.GetP2PRaddr(); r != "" && sp.RaddrCoversCurrentMapping() {
				observedRaddr = r
			}
		}
	}

	// The observed source goes in front: it is measured rather than declared,
	// so it outranks anything the peer said about itself. The rest of the
	// list still gets its packet -- this widens the spray, it does not
	// replace it. A dead observed address simply goes unanswered and costs
	// one datagram, which is the self-correcting property that made
	// observed-priority worth having in the first place.
	if observedRaddr != "" {
		if ra, err := net.ResolveUDPAddr("udp", observedRaddr); err == nil && ra != nil && ra.IP != nil {
			add(ra)
		}
	}

	var sameSubnet, rest []*net.UDPAddr
	for _, raw := range instr.GetSenderAssistedEndpoints() {
		if raw == "" {
			continue
		}
		ep, err := net.ResolveUDPAddr("udp", raw)
		if err != nil || ep == nil || ep.IP == nil {
			continue
		}
		// The sender's own tap: never a punch target.
		if peerTapIP != "" && ep.IP.Equal(net.ParseIP(peerTapIP)) {
			continue
		}
		// Loopback and link-local can never be punched across.
		if ep.IP.IsLoopback() || ep.IP.IsLinkLocalUnicast() {
			continue
		}
		if AddrInLocalPrefix(ep.IP, localPrefixes) {
			sameSubnet = append(sameSubnet, ep)
		} else {
			rest = append(rest, ep)
		}
	}

	for _, a := range sameSubnet {
		add(a)
	}
	add(pubSocket)
	for _, a := range rest {
		add(a)
	}
	return out
}

func AddrStrings(list []*net.UDPAddr) []string {
	out := make([]string, 0, len(list))
	for _, a := range list {
		if a != nil {
			out = append(out, a.String())
		}
	}
	return out
}

// AddrInLocalPrefix reports whether ip sits inside one of the subnets this
// host is also attached to. A peer address that does is reachable by direct
// routing, so it beats any predicted public address.
func AddrInLocalPrefix(ip net.IP, prefixes []netip.Prefix) bool {
	if ip == nil {
		return false
	}
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	a = a.Unmap()
	// An address in the CGNAT pool is never "on a LAN we are also on", even
	// when a prefix list says it is. NetBird, WireGuard and n2n itself all
	// draw from 100.64.0.0/10, so a host behind one of those tunnels shares
	// an overlay subnet with a peer on the same tunnel -- and this predicate
	// is what promotes a punch candidate ahead of the public address. Left
	// unguarded it promotes the overlay: the punch then "succeeds" while the
	// bytes go over the overlay (the relay by another name), and the peer's
	// P2PRaddr flaps between the overlay and the public address. Observed on
	// 2026-09-30 with NetBird on both ends.
	if IsCGNATOverlay(a) {
		return false
	}
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func ContainsAddr(list []*net.UDPAddr, a *net.UDPAddr) bool {
	if a == nil {
		return false
	}
	for _, c := range list {
		if c != nil && c.String() == a.String() {
			return true
		}
	}
	return false
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

// IsOwnEndpoint reports whether addr is one of this host's own P2P sockets:
// the P2P listen address we are bound to, or the NAT-mapped address the
// supernode/StunServer learned for it.
//
// Why this must gate every punch target: a punch packet we send to ourselves
// never leaves the host. It comes straight back through our own receive loop,
// so handleP2P sees it, falls through to the mid-instruction fallback, gets
// attributed to whichever peer the instruction named, and stamps that peer's
// P2PRaddr with our own address. The result is self-sustaining: the next
// round reads back the poisoned P2PRaddr and punches it again. Observed
// 2026-10-02 on 192.168.10.13 (log5), which punched 192.168.10.13:43828 495
// times in a minute and, on receiving its own traffic, promoted ea:2f to
// FullDuplex 50 times while the real peer sat on the relay -- the peer only
// looked connected because we were congratulating ourselves.
//
// Comparison is by resolved host:port so spellings cannot slip past.
func (reg *PeerRegistry) IsOwnEndpoint(addr string) bool {
	if reg == nil || reg.Me == nil || addr == "" {
		return false
	}
	key := addr
	if ua, err := net.ResolveUDPAddr("udp", addr); err == nil && ua != nil {
		key = ua.String()
	}
	own := make([]string, 0, 2)
	own = append(own, reg.Me.P2PEndpoint)
	if ua := reg.Me.UDPAddr(); ua != nil {
		own = append(own, ua.String())
	}
	for _, own := range own {
		if own == "" {
			continue
		}
		k := own
		if ua, err := net.ResolveUDPAddr("udp", own); err == nil && ua != nil {
			k = ua.String()
		}
		if k == key {
			return true
		}
	}
	return false
}

// UnlistPeer removes a peer because it was absent from a PeerInfoList, but
// keeps its learned direct-path state in a tombstone for GraceUnlistedTTL.
//
// This is the only removal path allowed to be provisional. An explicit
// UnregisterRequest (handlers_missing.go) stays final: there the relay is
// telling us the peer is deliberately gone, and keeping its addresses would
// attribute a later punch from that address to a machine no longer present.
//
// The address indexes are released either way, so nothing routes to the peer
// and a punch arriving in the gap fails the lookup and takes the unknown-peer
// path -- it just no longer destroys the state needed to resume instantly.
func (reg *PeerRegistry) UnlistPeer(MACAddr string) error {
	reg.peerMu.Lock()
	defer reg.peerMu.Unlock()
	reg.UnlistPeerLocked(MACAddr)
	return nil
}

// UnlistPeerLocked is UnlistPeer for callers already holding peerMu (the
// PeerInfoList removal loop).
func (reg *PeerRegistry) UnlistPeerLocked(MACAddr string) {
	p, exists := reg.Peers[MACAddr]
	if !exists {
		return
	}

	dDesc := p.Infos.Desc
	dVip := p.Infos.VirtualIp
	for _, k := range p.lookupSockets() {
		delete(reg.peerBySocket, k)
	}
	if p.P2PEndpoint != "" {
		delete(reg.peerByP2PSocket, p.P2PEndpoint)
	}
	delete(reg.Peers, MACAddr)
	reg.graceUnlisted[MACAddr] = &graceTombstone{
		peer:      p,
		expiresAt: time.Now().Add(GraceUnlistedTTL),
		pubSocket: p.Infos.PubSocket,
	}
	log.Printf("unlisted peer %s/%s/%s — keeping direct-path state for %v in case it returns",
		dDesc, dVip, MACAddr, GraceUnlistedTTL)
	reg.SetPendingChanges()
}

// expireGraceTombstones drops tombstones whose peer neither came back nor was
// re-listed. Caller must hold peerMu.
func (reg *PeerRegistry) expireGraceTombstonesLocked(now time.Time) {
	for mac, t := range reg.graceUnlisted {
		if now.Before(t.expiresAt) {
			continue
		}
		p := t.peer
		for _, k := range p.lookupSockets() {
			if reg.peerBySocket[k] == p {
				delete(reg.peerBySocket, k)
			}
		}
		if p.P2PEndpoint != "" && reg.peerByP2PSocket[p.P2PEndpoint] == p {
			delete(reg.peerByP2PSocket, p.P2PEndpoint)
		}
		delete(reg.graceUnlisted, mac)
		log.Printf("grace period expired for %s/%s/%s — forgetting it", p.Infos.Desc, p.Infos.VirtualIp, mac)
	}
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
// PeerClaimingPort returns the peer, other than exclude, that already claims
// this UDP port on any address known to the registry -- pubSocket, P2P
// endpoint, assisted set or observed raddr.
//
// Behind a shared NAT gateway the IP cannot separate peers: log3 and log5
// both publish 111.101.5.1 and differ only in port (62040 vs 48009). An IP
// match there returns whichever peer the map happens to yield, so an inbound
// packet gets charged to the wrong node and the two peers' raddrs end up
// transposed -- each then sends to the other's address and neither answers.
// Observed 2026-10-02 on log4: it recorded log3 at 172.22.1.17:48009 and
// log5 at 172.22.1.17:62040, exactly swapped, so it could ping E1 and
// nothing else.
//
// The port is therefore the tie-breaker, and it must be checked before any
// address-based attribution overwrites what is already known.
func (reg *PeerRegistry) PeerClaimingPort(port uint16, exclude *Peer) *Peer {
	if reg == nil || port == 0 {
		return nil
	}
	reg.peerMu.RLock()
	defer reg.peerMu.RUnlock()

	for key, owner := range reg.peerBySocket {
		if owner == nil || owner == exclude {
			continue
		}
		if _, ps, err := net.SplitHostPort(key); err != nil {
			continue
		} else if pn, err := strconv.Atoi(ps); err == nil && uint16(pn) == port {
			return owner
		}
	}
	return nil
}

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
	reg.recordNatHolePunchResultLocked(peerMAC, state, attempts, detail, behaviorIndex)
}

// recordNatHolePunchResultLocked is RecordNatHolePunchResult for callers that
// already hold peerMu.
//
// ExecuteNatHolePunch reports its exhausted-round failure from inside the
// peerMu critical section, so it cannot call the exported form: that takes the
// write lock itself, and Go's RWMutex is not reentrant. The previous code
// worked around this by writing reg.natHolePunchResults inline at that site,
// which duplicated the struct literal and, more importantly, left the two
// paths free to drift -- they already had.
func (reg *PeerRegistry) recordNatHolePunchResultLocked(peerMAC string, state NatHolePunchState, attempts uint32, detail string, behaviorIndex uint32) {
	if reg.natHolePunchResults == nil {
		reg.natHolePunchResults = make(map[string]*NatHolePunchResult)
	}
	reg.natHolePunchResults[peerMAC] = &NatHolePunchResult{
		State:         state,
		Attempts:      attempts,
		Detail:        detail,
		BehaviorIndex: behaviorIndex,
	}
	// Single choke point for every outcome (in progress, failed, succeeded),
	// so this is the one place that has to know a round just ended. The
	// stall re-arm measures its backoff from here.
	if reg.natHoleLastRound == nil {
		reg.natHoleLastRound = make(map[string]time.Time)
	}
	reg.natHoleLastRound[peerMAC] = time.Now()
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
		// Withdraw the punch-path capability only when the data plane has concluded,
		// on a real timeout, that the path is dead -- which is what the
		// caller in keepAliveTick is doing. The asymmetry is the point: a
		// control-plane probe failing to arrive must not be able to take a
		// direct path away, so the capability is opened by the punch
		// handshake and closed only here.
		//
		// SetFullDuplex(false) deliberately does NOT withdraw it. That
		// function is also called from handlePeerToPing when a pong arrives
		// via the supernode, meaning only that *this liveness probe* took the
		// relay -- which is true of every probe in the window between a
		// successful punch and the first data frame, and says nothing about
		// whether the hole is open. Clearing the capability there made the
		// guard useless: log3 against log4, both behind CGNAT 111.101.5.1,
		// was punched successfully at 18:24:48 and had the capability
		// withdrawn 40ms later by a relay pong, so the pair oscillated
		// between p2p and relay through 316 seconds of re-punching (2026-10-05,
		// superseding the 36-second case the capability was added for).
		//
		// Not withdrawing it on that path would be the mirror-image bug if it
		// were also skipped on the data-plane path: a genuinely dead path
		// would keep its capability, UpdateP2PStatus would keep refusing
		// every later Unknown, and the only way out would be another
		// successful punch. Hence the split -- keepAliveTick withdraws,
		// handlePeerToPing does not.
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

// NatHolePunchResultsSnapshotLocked is NatHolePunchResultsForTest for a caller
// that already holds peerMu. It exists because peerMu is not reentrant: a test
// holding the write lock cannot call the RLock-taking accessor without
// deadlocking against itself.
func (reg *PeerRegistry) NatHolePunchResultsSnapshotLocked() map[string]*NatHolePunchResult {
	out := make(map[string]*NatHolePunchResult, len(reg.natHolePunchResults))
	for k, v := range reg.natHolePunchResults {
		out[k] = v
	}
	return out
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

	// Same rule, one rung lower. P2PAvailable is where a pair sits in the
	// window between "hole punched" and "data frame verified", and it is
	// reached only after a successful punch, so a control-plane demotion
	// arriving in that window threw away a working path and made the pair
	// re-punch.
	//
	// The status is demoted but the routing decision is not: this returns
	// early with P2PStatus left alone, so UDPAddrWithStrategy keeps taking
	// the direct path. The distinction matters because the two pieces of
	// evidence answer different questions. P2PStatus is what the peer is
	// worth over the relay -- and over the relay a pair awaiting its first
	// data frame genuinely is worth no more than before. The punch path
	// capability is what can be sent directly right now, and the handshake
	// has already answered that affirmatively.
	//
	// Without this, the punch loop's own report of that window fought the
	// status: it reports PunchStateInProgress, publishes, and a pong with a
	// superseded checkID lands in the same instant, and the pair fell back
	// to relay nine times in 36s (log3/log4, 2026-10-04) while its hole was
	// open the entire time.
	if status == P2PUnknown && p.PunchPathOpen() &&
		p.P2PStatus != P2PUnavailable {
		p.P2PCheckID = checkid
		p.UpdatedAt = time.Now()
		log.Printf("not demoting peer %s to Unknown on a control-plane probe: its punch path is still open (reporting %s to the relay instead)",
			net.HardwareAddr(p.Infos.MacAddr).String(), p.P2PStatus.String())
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

// GraceUnlistedTTL is how long a peer removed because it was absent from a
// PeerInfoList keeps its learned direct-path state while staying out of the
// active registry.
//
// Why this exists: a PeerInfoList is a snapshot, and snapshots are routinely
// incomplete for reasons that have nothing to do with the missing peer. When
// one node drops off, the relay rebroadcasts, and every receiver rebuilds from
// that list -- so a peer that was perfectly healthy a second earlier gets
// removed along with the one that actually left. Observed 2026-10-02 at
// 11:19:03 on log3: 52:eb (log5) went offline, and in the same refresh
// 9e:6e (log4), 0a:e3 (E1) and aa:bc (E2) were removed too. log4 had been
// FullDuplex over a verified direct path since 10:30 and lost it, because
// RemovePeer dropped the *Peer outright and AddPeer rebuilt it at P2PUnknown
// with an empty P2PRaddr. That is unrecoverable on its own: the direct path
// is gated on a non-empty raddr (wire.go), the raddr can only be filled by a
// direct data frame, and every frame falls back to the relay until the raddr
// is set. Both sides then wait on each other indefinitely -- log3 logged "not
// promoting 9e:6e: punch seen but no data frame verified yet" every few
// seconds for the rest of the run, and log3->log4 fell back to the Cloudflare
// relay, turning a 17ms path into a three-digit one.
//
// So removal for absence is now provisional: the peer leaves reg.Peers (so
// nothing routes to it) but its address, raddr and verification timestamps
// move to a tombstone. A reappearance within the TTL restores the state
// intact; a longer absence expires the tombstone and the peer is genuinely
// forgotten. An explicit Unregister is not provisional and never consults this.
const GraceUnlistedTTL = 90 * time.Second

// peerRecentlyAliveWindow is how recently we must have observed a peer for a
// control-plane "this peer is gone" list to be disbelieved. It is generous
// on purpose: a peer that is genuinely gone cannot produce a data frame, so
// the window only has to outlast a couple of missed keepalives. Erring wide
// means we occasionally keep a dead peer for one extra interval, which costs
// a stale entry; erring narrow means we tear down live tunnels, which costs
// the mesh.
const peerRecentlyAliveWindow = 45 * time.Second

// recentlyAliveLocked reports whether we have positive evidence that peer is
// still reachable: either a confirmed direct path, or a direct data frame
// recent enough to rule out a relay-side claim that it went away.
//
// Caller must hold peerMu (RLock is enough).
func (reg *PeerRegistry) recentlyAliveLocked(p *Peer) bool {
	if p.IsFullDuplex {
		return true
	}
	last := p.LastDataSeenAt()
	return !last.IsZero() && time.Since(last) < peerRecentlyAliveWindow
}

type graceTombstone struct {
	peer      *Peer
	expiresAt time.Time
	// pubSocket is the peer's advertised public mapping at the moment it was
	// unlisted. The tombstoned raddr was observed against that mapping, so
	// restoring it is only meaningful while the mapping still holds. If the
	// peer comes back advertising a different pubSocket its NAT has re-mapped
	// and the remembered raddr is a dead address.
	//
	// Without this, a peer that restarts inside the grace window resumes with
	// its previous port. Observed on E1: log3/log4/log5 were unlisted at
	// 02:32:06 and re-registered at 02:33:07-25 with new STUN mappings
	// (65060/46112/58813), yet the restore handed back the old raddrs
	// (57443/37557/61401). E1 then punched those dead addresses 516/178/106
	// times over the next 27 minutes and never reached FullDuplex with any of
	// them -- while E2, whose mapping never moved, punched fine. See
	// AddPeer's grace restore below.
	pubSocket string
}

// SetP2PRaddr for a tombstoned peer still works, so a punch arriving while
// the peer is unlisted can refresh it; the registry just will not route to it.
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
		if existingPeer.Infos.PubSocket != infos.PubSocket {
			// The peer's public mapping moved. Whatever we observed about the
			// old one is now evidence about a closed socket, so date the move
			// -- RaddrCoversCurrentMapping compares against it to stop the
			// stale raddr outranking this fresh pubSocket. The raddr itself is
			// left in place: it is still the best record of the peer's address
			// for inbound matching until a packet arrives on the new socket,
			// and clearing it would also lose the index key that resolves
			// those packets.
			existingPeer.pubSocketChangedAt = time.Now()
			log.Printf("peer %s changed public mapping %s -> %s; an observed raddr older than this no longer describes its socket",
				macAddr, existingPeer.Infos.PubSocket, infos.PubSocket)
		}

		existingPeer.Infos = infos
		existingPeer.SetP2PEndpoint(infos.P2PEndpoint)
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
		P2PCapabilities: infos.P2PCapabilities,
		UpdatedAt:       time.Now(),
	}
	// Via the setter so the endpoint timestamp is stamped; the struct literal
	// cannot call it.
	peer.SetP2PEndpoint(infos.P2PEndpoint)
	reg.Peers[macAddr] = peer
	// A tombstone means this peer was unlisted, not that it is new. Restore
	// the direct-path state it had learned before, so a peer that merely
	// went missing from one snapshot resumes on the path it already had
	// instead of re-proving it from P2PUnknown with an empty raddr.
	//
	// Only the observation carries over. P2PStatus stays Unknown on
	// purpose: while it was gone we could not hear from it, so claiming the
	// tunnel is still up would be exactly the "control-plane state lies"
	// failure this tombstone exists to avoid. What the raddr buys us is the
	// ability to finish one punch round and be back, rather than negotiating
	// a fresh raddr against a dead end.
	if t, ok := reg.graceUnlisted[macAddr]; ok {
		if r := t.peer.GetP2PRaddr(); r != "" {
			// Only restore if the public mapping we observed that raddr
			// against is still the one the peer is advertising. A peer that
			// comes back with a different pubSocket has been re-mapped by its
			// NAT, so the remembered address is a closed socket -- restoring
			// it would send every punch into the void.
			//
			// The pubSocketChangedAt stamp still has to be set on the new
			// peer in the mismatch case: AddPeer took the not-exists branch
			// here, so the stamp is not set anywhere else, and without it
			// RaddrCoversCurrentMapping cannot protect any raddr the peer
			// records from this point on.
			if t.pubSocket != "" && t.pubSocket != infos.PubSocket {
				peer.pubSocketChangedAt = time.Now()
				log.Printf("peer %s/%s/%s returned within grace but its public mapping moved %s -> %s; not restoring raddr %s, it describes a closed socket",
					peer.Infos.Desc, peer.Infos.VirtualIp, macAddr, t.pubSocket, infos.PubSocket, r)
			} else {
				peer.SetP2PRaddr(r)
				log.Printf("peer %s/%s/%s returned within grace — restored raddr %s from before it was unlisted",
					peer.Infos.Desc, peer.Infos.VirtualIp, macAddr, r)
			}
		}
		delete(reg.graceUnlisted, macAddr)
	}
	for _, k := range peer.lookupSockets() {
		reg.peerBySocket[k] = peer
	}
	// The tombstone above restored an raddr, but lookupSockets deliberately
	// excludes it -- it is not an advertised address. Without this line the
	// restored raddr is set on the peer and absent from the index, so the
	// first inbound packet from it resolves to nobody and the restored state
	// is worse than useless: it looks recovered and is not reachable.
	//
	// Inlined rather than routed through IndexPeerRaddr because AddPeer
	// already holds reg.peerMu and that method takes it again.
	if r := peer.GetP2PRaddr(); r != "" {
		if k := normalizeSocketKey(r); k != "" {
			reg.peerBySocket[k] = peer
			peer.indexedRaddr = k
		}
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
	// reg.Peers is mutated under peerMu by AddPeer/RemovePeer; iterating it
	// without the read lock races those writers (and can trip Go's concurrent
	// map access detector).
	reg.peerMu.RLock()
	defer reg.peerMu.RUnlock()
	var peerlist []*Peer
	for _, p := range reg.Peers {
		if p.P2PStatus == P2PUnknown {
			peerlist = append(peerlist, p)
		}
	}
	return peerlist
}

func (reg *PeerRegistry) GetP2PendingPeers() []*Peer {
	// reg.Peers is mutated under peerMu by AddPeer/RemovePeer; iterating it
	// without the read lock races those writers (and can trip Go's concurrent
	// map access detector).
	reg.peerMu.RLock()
	defer reg.peerMu.RUnlock()
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
	// reg.Peers is mutated under peerMu by AddPeer/RemovePeer; iterating it
	// without the read lock races those writers (and can trip Go's concurrent
	// map access detector).
	reg.peerMu.RLock()
	defer reg.peerMu.RUnlock()
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
	// reg.Peers is mutated under peerMu by AddPeer/RemovePeer; iterating it
	// without the read lock races those writers (and can trip Go's concurrent
	// map access detector).
	reg.peerMu.RLock()
	defer reg.peerMu.RUnlock()
	var peerlist []*Peer
	for _, p := range reg.Peers {
		if p.P2PStatus == P2PFullDuplex && p.IsFullDuplex {
			continue
		}
		// Either side counts: we received their punch, or we already ran
		// (and possibly failed) a punch against them.
		if !p.PunchSeenAt().IsZero() || p.NatHoleExecuted {
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
	// reg.Peers is mutated under peerMu by AddPeer/RemovePeer; iterating it
	// without the read lock races those writers (and can trip Go's concurrent
	// map access detector).
	reg.peerMu.RLock()
	defer reg.peerMu.RUnlock()
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

// natHoleInstrKeyFor returns the key an instruction is stored under: the
// TARGET peer's MAC.
//
// Falling back to our own MAC covers the degenerate case of an instruction with
// no target, which is not actionable anyway (ExecuteNatHolePunch has nothing to
// wait on), but it must not collide with a real target's entry -- hence the
// "?" prefix, which is not valid MAC syntax.
func natHoleInstrKeyFor(instr *NatHoleInstruction, ourMAC []byte) string {
	if tm := instr.GetTargetMac(); len(tm) == 6 {
		return macAddrStr(tm)
	}
	return "?" + macAddrStr(ourMAC)
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
	// Key on the TARGET, not on ourselves.
	//
	// The key used to be our own MAC, which is the same for every instruction
	// this edge ever receives -- so with two or more peers to punch, each new
	// instruction silently overwrote the previous one and only the last
	// arrival survived. Observed 2026-09-30 with three edges up: E1 was told to
	// punch both E2 and the third host, and every round went to the third host
	// while E2 sat as receiver punching an E1 that never punched back. E2's
	// five attempts all timed out and the pair was marked P2PUnavailable,
	// which is the exact failure this keying caused.
	//
	// Keying by target MAC makes the map a per-peer work queue: one entry per
	// peer we owe a punch to, all live at once. SetNatHoleInstruction is
	// idempotent per target, so the Worker re-broadcasting the same
	// instruction every ~2s still just refreshes the entry.
	key := natHoleInstrKeyFor(instr, macAddr)
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

// ReArmStalledNatHolePeers re-arms the punch for every pair that has never
// reached a verified data path and is currently sitting on the relay.
// Returns how many were re-armed.
//
// The hole this closes is the one ReArmNatHoleInstruction's caller could not:
// that loop only walks GetFullDuplexPeers, so it fires when a working tunnel
// dies. A pair that never worked was left with no retry at all. It burned its
// five attempts, fell back to the relay, and then nothing would ever re-arm it
// again — p2pKeepAliveTick's demote branch never sees it, and the relay
// suppresses the pair on its stale "succeeded" report. Measured on E1<->E2:
// both sides punched into the void (E2 23:53:58-23:54:16, E1 23:54:36-23:54:42 —
// windows missed each other by 20s), then went quiet for the rest of the run
// with routing pinned to the relay.
//
// FRP's equivalent is keepTunnelOpenWorker (client/visitor/xtcp.go:114), which
// re-runs makeNatHole() every MinRetryInterval=90s for as long as the tunnel
// is not healthy. This is that, restricted to the pairs that never came up.
//
// The backoff starts below FRP's 90s on purpose. FRP can afford a flat 90s
// because KCP holds its NAT mapping open underneath (pkg/util/net/kcp.go:96);
// this edge has no lower layer, and its failure mode here is a *narrow window
// misalignment* — the two sides' five attempts are ~30s each and can start
// 20s apart, so a retry that lands promptly walks straight into the other
// side's window instead of missing it again. It grows by 2x to the 300s cap
// so a genuinely unreachable peer settles down instead of looping.
//
// Peers that already carry real traffic are left alone: they are the
// FullDuplex case, which ReArmNatHoleInstruction handles on keepalive timeout.
func (reg *PeerRegistry) ReArmStalledNatHolePeers(now time.Time, baseBackoff, maxBackoff, healthyWindow time.Duration) int {
	if baseBackoff <= 0 {
		return 0
	}
	if maxBackoff < baseBackoff {
		maxBackoff = baseBackoff
	}

	reg.peerMu.Lock()
	var candidates []*Peer
	for _, p := range reg.Peers {
		if p == nil || p.P2PStatus == P2PFullDuplex && p.IsFullDuplex {
			continue
		}
		// A pair that is carrying traffic right now is not stalled.
		//
		// This was HasVerifiedDataPath() alone, which is a latch that is set
		// once and never cleared -- it records that a real data frame was ever
		// seen, not that one is being seen now. So the first successful punch
		// permanently excluded the pair, and E1 (which did reach FullDuplex
		// with 3 real frames from E2) never re-armed for the rest of the run
		// even after E2 went dark. Gate on recency instead.
		if p.HasVerifiedDataPath() {
			if last := p.LastDataSeenAt(); !last.IsZero() && now.Sub(last) < healthyWindow {
				continue
			}
		}
		// No instruction was ever negotiated for this peer, so there is
		// nothing to re-arm: the Worker never considered the pair punchable.
		peerKey := macAddrStr(p.Infos.MacAddr)
		if _, ok := reg.lastNatHoleInstrs[peerKey]; !ok {
			continue
		}
		if last, ok := reg.natHoleLastRound[peerKey]; ok && now.Sub(last) < reg.stallBackoff(reg.natHoleStallCount[peerKey], baseBackoff, maxBackoff) {
			continue
		}
		candidates = append(candidates, p)
	}
	if len(candidates) == 0 {
		reg.peerMu.Unlock()
		return 0
	}

	// ReArmNatHoleInstruction takes the write lock itself, so the restore has
	// to happen after the unlock rather than inside this critical section.
	macs := make([][]byte, 0, len(candidates))
	for _, p := range candidates {
		macs = append(macs, p.Infos.MacAddr)
	}
	reg.peerMu.Unlock()

	rearmed := 0
	for _, mac := range macs {
		key := macAddrStr(mac)
		reg.ReArmNatHoleInstruction(mac)
		reg.peerMu.Lock()
		if _, pending := reg.natHoleInstrs[key]; pending {
			if reg.natHoleStallCount == nil {
				reg.natHoleStallCount = make(map[string]int)
			}
			reg.natHoleStallCount[key]++
			rearmed++
		}
		reg.peerMu.Unlock()
		log.Printf("[P2P] re-arming stalled punch for %s (attempt %d since it never reached a verified data path)",
			key, reg.natHoleStallCount[key])
	}
	return rearmed
}

// stallBackoff is the wait before the n-th consecutive stalled re-arm.
func (reg *PeerRegistry) stallBackoff(n int, base, max time.Duration) time.Duration {
	if n <= 0 {
		return base
	}
	d := base
	for i := 0; i < n && d < max; i++ {
		d *= 2
	}
	if d > max {
		d = max
	}
	return d
}

// ResetNatHoleStallCount clears the backoff for a peer, so a pair that has
// just been promoted is not held at its longest wait if it ever drops again.
func (reg *PeerRegistry) ResetNatHoleStallCount(peerMAC []byte) {
	if len(peerMAC) != 6 {
		return
	}
	reg.peerMu.Lock()
	defer reg.peerMu.Unlock()
	delete(reg.natHoleStallCount, macAddrStr(peerMAC))
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

	// natHoleInstrs is keyed by target MAC, so this peer's entry is found
	// directly. That is the lookup the comment below spent its life working
	// around: while the map held a single entry keyed by OUR MAC, every
	// lookup by peer MAC missed, which is bug 1 in the note above.
	//
	// It also means a re-arm for one peer no longer depends on whether the map
	// happens to be empty. The old code early-returned when any instruction was
	// pending and then only reset the retry count of whichever key the map
	// yielded first -- so a tunnel that dropped while another peer was being
	// punched got its re-arm applied to that peer's counter, or silently lost.
	if _, ok := reg.natHoleInstrs[peerKey]; ok {
		reg.natHoleRetryCounts[peerKey] = 0
		log.Printf("[P2P] re-armed the pending punch instruction for %s — resetting its attempt count", peerKey)
		return
	}

	// Nothing pending: this is the case the function exists for. A successful
	// round deleted the entry, so restore the last instruction the Worker
	// negotiated for this peer. It keeps the targets (ports/TTL/role) the relay
	// believes are current.
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
	reg.natHoleInstrs[peerKey] = prev
	reg.natHoleRetryCounts[peerKey] = 0
	log.Printf("[P2P] re-armed the punch instruction remembered for %s — its tunnel dropped after a successful round", peerKey)
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
	// NatHoleModeEasyNATPair is FRP Mode 0: both peers are behind a
	// port-preserving cone NAT, so the STUN-discovered pub_socket is exact
	// and no port scan is performed.
	NatHoleModeEasyNATPair = 0

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
	// A non-positive fallback is `--nat-hole-probe-ttl 0`: the operator asked
	// for no low-TTL probe at all. That has to beat the instruction's own ttl,
	// not just stand in for it. The relay picks the ladder entry from the two
	// NAT types, which cannot see where a cloud EIP translation actually sits;
	// on a path where that point is further away than the probe's hop limit,
	// every probe dies before the NAT it exists to open, and neither side ever
	// sees a packet. Before this the flag only moved the fallback, so an
	// instruction carrying ttl 7 still went out at ttl 7 and the documented
	// "set 0 to disable" did nothing -- measured: E1<->E2 is an 11-hop path
	// (ping ttl=53), the probe is capped at 7, and the pair never punched.
	if fallback <= 0 {
		return 0
	}
	// Entries 4 and 5 of the Mode 0 ladder are the "no TTL" pair. Any other
	// index that explicitly says 0 (e.g. the sender's own instruction, which
	// always has ttl 0) is not a receiver probe, and entries outside the
	// ladder predate the feature.
	if instr.GetMode() == NatHoleModeEasyNATPair && (instr.GetBehaviorIndex() == natHoleBehaviorNoTTLSenderFirst ||
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
		baseline = p.PunchSeenAt()
	}
	for {
		if p, err := reg.GetPeer(targetMACStr); err == nil && p.PunchSeenAt().After(baseline) {
			// The hole is open. Both NAT mappings now exist and packets can
			// pass, which is a fact the status field cannot hold (see
			// Peer.punchPathOpen): FullDuplex still owes a real data frame.
			// Recording it here rather than at the FullDuplex promotion is
			// what lets a control-plane probe arriving during that window
			// leave the direct path in place.
			p.NotePunchPathOpen()
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
// ExpectedPunchPeerMAC returns the MAC of the peer the pending
// NatHoleInstruction is about, or "" when there is no instruction.
//
// The caller uses it to bound how long it will attribute a punch arriving
// from an unrecognised source address. The instruction names the peer, so
// the peer is known to exist; what is unknown is only the address it is
// currently reachable at, which a forwarding router may have rewritten.
func (reg *PeerRegistry) ExpectedPunchPeerMAC() string {
	reg.peerMu.RLock()
	defer reg.peerMu.RUnlock()

	// "Us" is never a valid answer: GetPeer on our own MAC always misses,
	// which silently degrades the attribution window to its fallback branch.
	var self string
	if reg.Me != nil {
		self = macAddrStr(reg.Me.Infos.GetMacAddr())
	}

	// Scan every pending instruction, in a stable order. Two things were
	// wrong here and they compounded:
	//
	//   - the loop body ended in `return ""`, so the scan stopped after the
	//     *first* instruction examined;
	//   - "first" was whatever Go's randomised map iteration yielded, and
	//     several peers are routinely mid-punch at once.
	//
	// So whenever the one instruction drawn happened to name us as target
	// (or carried neither MAC), the answer was "" and the attribution
	// window was silently closed for the entire round -- the correct punch
	// then arrived, was answered, and was not recorded, because only the
	// attribution branch records an raddr. Nothing logged the loss.
	//
	// Observed 2026-10-03 on log3: 10 consecutive punches from
	// 52:eb:72:ed:64:1f arriving at 192.168.10.2:33377 -- the address an
	// OpenWrt in the path had rewritten the source to -- were answered as
	// "Punch packet from unknown peer", which records no raddr, so the peer
	// stayed indexed only under its advertised 192.168.10.13:33377. The one
	// round that drew a usable instruction logged "attributed to instruction
	// peer (source address was rewritten in transit)", recorded 192.168.10.2
	// and closed the tunnel immediately: 42s after the first punch, decided
	// by map iteration order rather than by anything the protocol knew.
	keys := make([]string, 0, len(reg.natHoleInstrs))
	for k := range reg.natHoleInstrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		instr := reg.natHoleInstrs[k]
		if instr == nil {
			continue
		}
		var sender, target string
		if sm := instr.GetSenderMac(); len(sm) > 0 {
			sender = macAddrStr(sm)
		}
		if tm := instr.GetTargetMac(); len(tm) > 0 {
			target = macAddrStr(tm)
		}
		// TargetMac, not SenderMac. handleNatHoleInstruction rebuilds the
		// instruction with SenderMac overwritten to our own MAC, so SenderMac
		// is "us" in the rebuilt copy and names nobody. TargetMac is the
		// peer at the other end of this punch in both roles: for a receiver
		// instruction the Worker fills it with the sender's MAC, for a
		// sender instruction with the receiver's.
		if target != "" && target != self {
			return target
		}
		if sender != "" && sender != self {
			return sender
		}
		// This instruction names no peer we can attribute to; try the next
		// one rather than closing the window.
	}
	return ""
}

// NextNatHoleInstruction picks the peer to punch in the next round and advances
// the rotation.
//
// Round-robin over a sorted key list, not map iteration order. Go randomises map
// iteration, so "pick whatever the range yields first" is not merely unfair
// between peers -- it makes a peer that is punched once get picked again on the
// very next round whenever two keys collide in the (small) random ordering,
// which is exactly the starvation this replaces. Sorting also makes the
// behaviour reproducible in logs, which matters when diagnosing why a
// particular pair never came up.
//
// Peers that are already FullDuplex are skipped: the Worker keeps an entry
// until the round that promoted it completes, and re-punching a working tunnel
// is pure overhead that would delay the peers that still need it.
func (reg *PeerRegistry) NextNatHoleInstruction() (*NatHoleInstruction, string) {
	reg.peerMu.Lock()
	defer reg.peerMu.Unlock()

	if len(reg.natHoleInstrs) == 0 {
		return nil, ""
	}

	keys := make([]string, 0, len(reg.natHoleInstrs))
	for k := range reg.natHoleInstrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Consider each candidate once before recycling, so no peer can be skipped
	// forever by the rotation even if one round takes much longer than the
	// others.
	n := len(keys)
	for i := 0; i < n; i++ {
		idx := int(reg.natHoleRoundRobin % uint64(n))
		reg.natHoleRoundRobin++
		k := keys[idx]
		instr := reg.natHoleInstrs[k]
		if instr == nil {
			continue
		}
		if tm := instr.GetTargetMac(); len(tm) == 6 {
			if p, ok := reg.Peers[macAddrStr(tm)]; ok && p.IsFullDuplex {
				// Already direct; the entry is waiting on the round that
				// promoted it. Drop it now so it stops occupying the
				// rotation -- the post-round cleanup below would have
				// removed it anyway.
				delete(reg.natHoleInstrs, k)
				delete(reg.natHoleRetryCounts, k)
				continue
			}
		}
		return instr, k
	}
	return nil, ""
}

// ExecuteNatHolePunch runs one punch round against ONE peer and reports whether
// that peer reached FullDuplex.
//
// One round per call is deliberate: a round blocks for up to natHoleReadTimeout
// (5s) waiting for the peer's punch to come back, so running every pending
// instruction sequentially would let a single unreachable peer stall the others
// by 5s each. The caller re-invokes on its 3s ticker, and the round-robin
// selection below is what guarantees every pending peer is actually served
// rather than whichever one the map iterator happened to yield.
//
// The return value describes only the target this round ran against. Callers
// that need "is anything direct now" must ask the peers themselves -- which is
// what edge/routines.go does, via GetPunchedNotFullDuplexPeers and the
// peer registry's own FullDuplex flags.
func (reg *PeerRegistry) ExecuteNatHolePunch(p2pConn *net.UDPConn) bool {
	instr, instrKey := reg.NextNatHoleInstruction()

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
		// Sender: send UDP punch packets to the target's public socket.
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
	// Highest priority for both roles: the address the peer's packets
	// demonstrably arrive from. Everything considered above is derived from
	// what the peer believes about itself, and behind a NAT none of it can be
	// dialled from here -- the peer's private interface, and its STUN
	// reflection, which needs the router to hairpin. Only an observed source
	// address survives that, because a packet has already been proven to
	// arrive from it.
	//
	// Placed here rather than in the Sender candidate builder below so the
	// Receiver gets it too: the Receiver is the side that has usually heard
	// the peer already, since a rewritten punch source is precisely what the
	// mid-instruction fallback in handleP2P cannot attribute. Observed
	// 2026-10-02 on 192.168.10.7 -> 192.168.10.1/172.22.1.17 -> 172.22.2.44,
	// where log4 held 172.22.1.17:52784 and still spent five rounds per rung
	// punching 111.101.5.1:52784.
	//
	// Gated on the observation still covering the peer's current mapping.
	// This block overwrites whatever ResolvePunchTarget chose, so the gate
	// there does not protect it. Observed 2026-10-03: log4 restarted on
	// 111.101.5.1:49570 while log3 still held 172.22.2.44:60735 from the
	// previous process, and every round from 14:38 to 14:48 opened with this
	// line naming the dead port as the primary target. Ten minutes of failed
	// rounds, rescued only when the live port happened to be punched as the
	// secondary candidate.
	if obsMAC := macAddrStr(instr.GetTargetMac()); obsMAC != "" {
		if tp, terr := reg.GetPeer(obsMAC); terr == nil && tp != nil {
			raddr := tp.GetP2PRaddr()
			switch {
			case raddr == "" || reg.IsOwnEndpoint(raddr):
				// nothing to prefer, or it is us
			case !tp.RaddrCoversCurrentMapping():
				log.Printf("[P2P] Receiver: ignoring stale observed raddr %s for %s (it predates the peer's current public mapping, so that socket is closed); using the address resolved from what it advertises",
					raddr, obsMAC)
			case !raddrPunchableByReceiver(raddr):
				// Off-link private. Punching it opens the hole at our own
				// router's WAN address, so the peer's return packets only
				// reach us if that router happens to hold a matching
				// port-forward -- the exception, not the rule. Under CGNAT
				// the peer's advertised public mapping is the only address
				// where the return path is guaranteed to be walked, and the
				// edge-side resolver already chose it for us.
				//
				// Observed 2026-10-04 on log3 against log4: this branch made
				// 172.22.2.44:58813 the primary target for 188 rounds across
				// 28 minutes while the public 111.101.5.1:58813 sat unused
				// as the secondary; the pair never reached FullDuplex.
				log.Printf("[P2P] Receiver: not preferring off-link private observed raddr %s for %s (the return path needs a port-forward on our router that we cannot count on); keeping the address resolved from what it advertises",
					raddr, obsMAC)
			default:
				punchTarget = raddr
				log.Printf("[P2P] Receiver: using observed raddr %s as punch target for %s (ahead of self-reported addresses)", raddr, obsMAC)
			}
		}
	}
	if punchTarget == "" {
		punchTarget = targetP2PEndpoint
	}
	if punchTarget == "" {
		log.Printf("[P2P] executeNatHolePunch: no target address")
		return false
	}

	// Last line of defence, covering every branch above plus any future one:
	// never punch ourselves. See PeerRegistry.IsOwnEndpoint for why a
	// self-addressed punch is worse than no punch at all -- it manufactures
	// a FullDuplex promotion out of our own echo. Bail and let the next rung
	// re-dispatch with a sane target rather than poisoning the peer's raddr.
	if reg.IsOwnEndpoint(punchTarget) {
		log.Printf("[P2P] executeNatHolePunch: refusing to punch our own endpoint %s (role=%v target=%s); skipping round",
			punchTarget, role, macAddrStr(instr.GetTargetMac()))
		return false
	}

	targetAddr, err := net.ResolveUDPAddr("udp", punchTarget)
	if err != nil {
		log.Printf("[P2P] executeNatHolePunch: cannot resolve target %s: %v", punchTarget, err)
		return false
	}

	// punchExchanged records whether the peer actually answered our punch
	// packets this round. It is a separate signal from FullDuplex: reaching
	// the peer proves the mapping opened, while FullDuplex additionally
	// requires a verified data frame, so a round can be genuinely productive
	// and still not be FullDuplex yet. The two are reported differently.
	punchExchanged := false

	// Report InProgress as soon as the round has actually started.
	//
	// Without this the relay stays blind until the round ends. It only hears
	// from us in two places: handlePunchDatagram, which fires when the PEER's
	// packet finally lands (so the whole punch phase is invisible), and the
	// exhausted-round Failed at the bottom of this function. A peer that never
	// answers is therefore reported exactly once, as Failed, after all five
	// attempts -- and until then it is indistinguishable from a peer that is
	// merely slow.
	//
	// The relay's state machine distinguishes "instruction dispatched" from
	// "punch is running", and only the latter lets it tell a stalled round
	// from a dead pair.
	//
	// On the relay side state 1 is deliberately inert: recordPunchResult skips
	// the failCount increment and the backoff re-arm (both are state 2 only),
	// so this costs one P2PStateInfo and cannot escalate a pair's backoff.
	//
	// Declared out here, beside punchExchanged, because both the sender and the
	// receiver branch must reach it and the branch bodies sit at a deeper
	// indentation than their common `if role` header.
	//
	// Fires once per round. Every candidate gets its own dispatch and the port
	// scan emits one datagram per port; reporting each would flood the relay
	// for no extra information.
	punchStarted := false
	reportPunchStarted := func(attempt uint32, addr string) {
		if punchStarted {
			return
		}
		punchStarted = true
		tm := instr.GetTargetMac()
		if tm == nil || len(tm) == 0 {
			return
		}
		reg.RecordNatHolePunchResult(
			macAddrStr(tm),
			NatHolePunchState_PunchStateInProgress,
			attempt,
			fmt.Sprintf("punch dispatched to %s, awaiting peer's packet", addr),
			// The rung this round runs. Read through the accessor because
			// currentInstr is not in scope here -- it is fetched later, under
			// peerMu, for the failure report at the end of this round. Taking
			// peerMu here would deadlock: Go's RWMutex is not reentrant.
			reg.CurrentNatHoleBehaviorIndex(macAddrStr(tm)),
		)
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

		// Report InProgress as soon as the round has actually started.
		//
		// Without this the relay stays blind until the round ends. It only
		// hears from us in two places: handlePunchDatagram, which fires when
		// the PEER's packet finally lands (so the whole punch phase is
		// invisible), and the exhausted-round Failed at the bottom of this
		// function. A peer that never answers is therefore reported exactly
		// once, as Failed, after all five attempts -- and a peer that answers
		// is not distinguishable from one that did not until then either.
		//
		// The relay's state machine distinguishes "instruction dispatched"
		// from "punch is running"; only the latter lets it stop re-arming a
		// pair mid-round and tell a stalled round from a dead pair.
		//
		// On the relay side, state 1 is deliberately inert: recordPunchResult
		// skips the failCount increment and the backoff re-arm (both are
		// state 2 only), so this costs one P2PStateInfo and cannot escalate
		// a pair's backoff.
		//
		// Fire once per round. Every candidate gets its own dispatch, and the
		// port scan emits one datagram per port -- reporting each would flood
		// the relay for no extra information.
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
				if pRaddr := p.GetP2PRaddr(); pRaddr != "" {
					if !p.RaddrCoversCurrentMapping() {
						log.Printf("[P2P] Sender: skipping stale OBSERVED raddr %s for target %s (it predates the peer's current public mapping, so that socket is closed)",
							pRaddr, macAddrStr(targetMAC))
					} else if ra, err2 := net.ResolveUDPAddr("udp", pRaddr); err2 == nil && ra != nil {
						// Put the observed address FIRST so it is tried
						// before any predicted/published candidates.
						candidates = append([]*net.UDPAddr{ra}, candidates...)
						log.Printf("[P2P] Sender: using OBSERVED raddr %s for target %s (ahead of predicted candidates)",
							pRaddr, macAddrStr(targetMAC))
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
				localPrefixes := LocalNATPunchPrefixes(reg.SelfTapName, reg.SelfTapIP(), reg.SelfMAC())
				assisted := SortAssistedByLocalAffinity(assistedRaw, localPrefixes)
				if !SameOrder(assistedRaw, assisted) {
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

				// Ranked-first is not the same as tried-first. The
				// same-subnet reordering above only reorders the peer's own
				// addresses, but the STUN-reflexive pubSocket was appended
				// unconditionally as candidate 0 -- so for a peer on the
				// same LAN behind the same NAT we tried the public address
				// first and the reachable one last:
				//
				//   candidate 0  111.101.5.1:61706    CGNAT, needs hairpin
				//   ...
				//   candidate 5  192.168.10.7:61706   one hop away
				//
				// The public address is the *hardest* path for such a peer
				// and the LAN address the easiest, so ordering them the other
				// way round spends the whole punch budget on a detour. FRP
				// tries m.AssistedAddrs ahead of the predicted public
				// address (nathole.go:210-215) for exactly this reason.
				//
				// Promote only addresses that sit on a subnet we are also on
				// -- an address on some other LAN is no better than the
				// public one, it just fails differently.
				var lanFirst []*net.UDPAddr
				for _, raw := range assisted {
					ep, err2 := net.ResolveUDPAddr("udp", raw)
					if err2 != nil || ep == nil {
						continue
					}
					if AddrInLocalPrefix(ep.IP, localPrefixes) {
						lanFirst = append(lanFirst, ep)
					}
				}
				if len(lanFirst) > 0 {
					rest := candidates[:0]
					for _, c := range candidates {
						if !ContainsAddr(lanFirst, c) {
							rest = append(rest, c)
						}
					}
					candidates = append(append([]*net.UDPAddr{}, lanFirst...), rest...)
					log.Printf("[P2P] Sender: promoted %d same-subnet candidate(s) %v ahead of the public address %s for %s",
						len(lanFirst), lanFirst, punchTarget, macAddrStr(targetMAC))
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

				// The peer's observed raddr, when we have one. This is the
				// address its packets demonstrably arrive from, which
				// self-reported addresses cannot establish behind NAT: the
				// registry entry holds 192.168.10.7 while the only thing
				// reachable from here is the router's 172.22.1.17. Preferring
				// it here means a side that has already heard the peer --
				// even just once, even before the relay reports anything --
				// punches an address that works, instead of re-deriving the
				// same unreachable set every round.
				// Prepended, not appended, and deliberately ahead of both
				// the same-subnet promotion above and every self-reported
				// address. It is the only entry backed by observation: the
				// peer's own endpoint and assisted list describe addresses
				// the peer believes it has, while this one is where its
				// packets demonstrably arrive. Behind a NAT only the latter
				// is reachable -- 192.168.10.7's packets leave its router as
				// 172.22.1.17, and neither 192.168.10.7 nor its STUN
				// reflection 111.101.5.1 can be dialled from the far side.
				//
				// Ordering matters as much as membership: the first
				// candidate is what punchTarget defaults to, so an appended
				// raddr would still lose to a hairpin address that silently
				// drops every packet.
				if raddr := p.GetP2PRaddr(); raddr != "" {
					if !p.RaddrCoversCurrentMapping() {
						// Same gate as above. This one also owns punchTarget,
						// so leaving it ungated puts a closed port at the
						// front of the round and as its primary.
						log.Printf("[P2P] Sender: not promoting stale observed raddr %s for %s to primary (it predates the peer's current public mapping)",
							raddr, macAddrStr(targetMAC))
					} else if ra, err3 := net.ResolveUDPAddr("udp", raddr); err3 == nil && ra != nil {
						alreadyPresent := false
						for _, c := range candidates {
							if c.String() == ra.String() {
								alreadyPresent = true
								break
							}
						}
						if !alreadyPresent {
							candidates = append([]*net.UDPAddr{ra}, candidates...)
							log.Printf("[P2P] Sender: promoted observed raddr %s for %s to the front of %d candidate(s)",
								raddr, macAddrStr(targetMAC), len(candidates))
						}
						// Also make it the primary, not just a candidate.
						// punchTarget is what the ladder logs as "primary"
						// and what the port scan ranges around; leaving it
						// pointing at an unreachable self-reported address
						// keeps the round failing even though a working
						// address is now in the list.
						punchTarget = ra.String()
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
				reportPunchStarted(uint32(ci)+1, candAddr.String())
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
			punchExchanged = waitForPunchSuccess(reg, macAddrStr(tm), "Sender")
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
				// The receiver used to punch exactly one address: the
				// sender's pubSocket. The note above says
				// SenderAssistedEndpoints is "usable by the RECEIVER", but
				// this branch never read it, so every one of the five
				// attempts re-sent the same datagram to the same place.
				//
				// That is fatal precisely in the case that should be
				// easiest. Two hosts behind one carrier NAT share a public
				// address, so punching it means asking the CGNAT to hairpin
				// to itself -- which carrier-grade NATs generally refuse. The
				// field log for a same-ISP pair showed exactly that: five
				// attempts, all to 111.101.5.1:45848, all failed, while the
				// sender using its full candidate list reached the peer over
				// P2P. The receiver's own LAN addresses are the ones that can
				// actually work, and the instruction carries them.
				//
				// Ranked the same way the sender ranks them, so a sender on
				// our own subnet is punched first.
				receiverCands := receiverPunchCandidates(instr, reg, senderAddr)
				if len(receiverCands) > 1 {
					log.Printf("[P2P] Receiver: sender has %d reachable candidate(s) %v, ranked ahead of the pubSocket %s",
						len(receiverCands)-1, AddrStrings(receiverCands), punchTarget)
				}

				probeTargets := receiverCands
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
				// The mapping we need is created by the datagrams leaving us,
				// so every candidate is worth one -- not just the pubSocket.
				for ci, cand := range receiverCands {
					if cand == nil {
						continue
					}
					if err := sendPunchOnce(p2pConn, punchPacket, cand, ttl, "Receiver"); err != nil {
						log.Printf("[P2P] Receiver: punch to candidate %d %s failed: %v", ci, cand.String(), err)
					} else {
						log.Printf("[P2P] Receiver: punched candidate %d %s once (ttl=%d)", ci, cand.String(), ttl)
						reportPunchStarted(uint32(ci)+1, cand.String())
					}
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
				punchExchanged = waitForPunchSuccess(reg, macAddrStr(tm), "Receiver")
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
		log.Printf("[P2P] NatHole punch succeeded — FullDuplex achieved with %s, clearing instruction", macAddrStr(targetMAC))
		reg.peerMu.Lock()
		// Tell the relay, and make it the only way out of "in progress".
		//
		// Nothing here reported success: this branch cleared the instruction
		// and logged, and PunchStateSucceeded had no producer anywhere in the
		// edge (only the enum in p2p.pb.go). The relay therefore never saw a
		// pair succeed -- it saw InProgress, then silence, because the success
		// path also drops the instruction so no further report follows. Two
		// consequences: shouldRetireSuccess() was dead (it only fires on
		// state 3), and the strategy analyzer never got credit, so a rung that
		// genuinely worked scored the same as one that never ran.
		//
		// It is reported here, at the one point where the claim is backed by a
		// real data frame: SetFullDuplex(true) refuses to promote a peer
		// without HasVerifiedDataPath(), and FullDuplex in this function is
		// read off p.IsFullDuplex, so state 3 can only mean real traffic moved
		// over the direct path.
		attempts := 1
		if n := reg.natHoleRetryCounts[instrKey]; n > 0 {
			attempts = n
		}
		reg.recordNatHolePunchResultLocked(
			macAddrStr(targetMAC),
			NatHolePunchState_PunchStateSucceeded,
			uint32(attempts),
			"FullDuplex verified by a real data frame",
			instr.GetBehaviorIndex(),
		)
		// A pair that has come up should not sit at its longest stalled
		// backoff if it drops again.
		delete(reg.natHoleStallCount, macAddrStr(targetMAC))
		// Clear this target's entry and nothing else.
		//
		// The old code cleared EVERY entry when the key it had captured was
		// gone, which was safe only because there could ever be one. With
		// per-target keying that fallback would wipe the queue for every other
		// peer the moment one round raced with a Worker re-broadcast -- silently
		// dropping punches that had not been attempted yet.
		//
		// A target MAC is part of the key by construction, so clearing by MAC
		// is equivalent to clearing instrKey and is robust to the key having
		// been replaced underneath us.
		if tm := targetMAC; len(tm) == 6 {
			cleared := macAddrStr(tm)
			delete(reg.natHoleInstrs, cleared)
			delete(reg.natHoleRetryCounts, cleared)
			// Also drop the legacy single-key entry if one survives.
			delete(reg.natHoleInstrs, instrKey)
			delete(reg.natHoleRetryCounts, instrKey)
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
		// Re-resolve this round's target by MAC, not by the captured key. The
		// key IS the target MAC, so looking it up that way is stable even if the
		// Worker re-broadcast a newer instruction for the same peer mid-round.
		//
		// The old fallback ("if my key vanished, take whichever instruction the
		// map yields") silently retargeted the round at a DIFFERENT peer, so a
		// failure against E1 could be recorded against E2's retry count. With
		// per-target keying there is nothing sensible to fall back to: if this
		// target's entry is gone, the Worker withdrew it.
		targetKey := ""
		if len(targetMAC) == 6 {
			targetKey = macAddrStr(targetMAC)
		}
		currentInstr, ok := reg.natHoleInstrs[targetKey]
		instrKey = targetKey
		if !ok {
			log.Printf("[P2P] instruction for %s was withdrawn by the relay while the round was running, not recording a result", targetKey)
		}
		if ok {
			retryCount := reg.natHoleRetryCounts[instrKey]
			if retryCount >= 0 && retryCount < 5 {
				// Increment retry count and keep instruction for next cycle.
				reg.natHoleRetryCounts[instrKey] = retryCount + 1
				// Two very different situations land here, and calling both
				// "failed" sent a reader (me, once) looking for a relay-side
				// penalty that does not exist: the state reported below is
				// InProgress in both cases, and the relay escalates nothing.
				//
				//   - punch exchanged, data path unverified: the mapping is
				//     open and the round did its job. The data frame is
				//     usually already in flight; it becomes FullDuplex a
				//     moment later.
				//   - nothing came back: a genuine miss worth retrying.
				if punchExchanged {
					log.Printf("[P2P] NatHole punch attempt %d/5: peer punched back, data path not yet verified — reporting InProgress, retrying in ~2s",
						retryCount+1)
				} else {
					log.Printf("[P2P] NatHole punch attempt %d/5 failed (no packet from peer), will retry in ~2s",
						retryCount+1)
				}
				// Tell the relay a round is still in flight so it does not
				// push a duplicate instruction while we are still working.
				if currentInstr != nil {
					if tm := currentInstr.GetTargetMac(); len(tm) > 0 {
						tmStr := macAddrStr(tm)
						// Shares the writer with the exhausted path below and with
						// RecordNatHolePunchResult. This site already read the rung off
						// currentInstr and never deleted the instruction first, so it was
						// not the misattribution the failure site had -- but it was the
						// third hand-built NatHolePunchResult, and the drift between the
						// two inline copies is exactly what produced the wrong-rung
						// report on 2026-09-30. One writer removes the class of bug
						// rather than this instance.
						reg.recordNatHolePunchResultLocked(
							tmStr,
							NatHolePunchState_PunchStateInProgress,
							uint32(retryCount+1),
							"retrying",
							currentInstr.GetBehaviorIndex(),
						)
					}
				}
			} else {
				// Max retries reached, clear instruction to stop retrying
				log.Printf("[P2P] NatHole punch failed after 5 attempts, clearing instruction")
				delete(reg.natHoleInstrs, instrKey)
				delete(reg.natHoleRetryCounts, instrKey)
				// Drop back to Available, NOT Unavailable.
				//
				// A failed punch does not make the peer unreachable -- the relay
				// path is still up and traffic keeps flowing over it, which is
				// exactly what Available means. Unavailable reads as "cannot be
				// reached at all", and writing it here was self-locking: the
				// periodic liveness loop in edge/routines.go:39-48 walks only
				// GetP2PPendingPeers and GetP2PAvailablePeers, so a peer marked
				// Unavailable drops out of both lists and is never pinged again.
				// Nothing can move it back to Available, because the only code
				// that would do so is the ping loop that can no longer see it.
				// The pair then stays on the relay until the process restarts
				// (observed: E2 sat at Unavailable for 39 minutes while
				// relaying normally, and never re-punched).
				//
				// Available keeps it inside the liveness loop, so the next
				// round of relay pongs re-establishes the state and a later
				// NatHoleInstruction can promote it to FullDuplex.
				//
				// NOTE: do NOT call reg.GetPeer() here -- we already hold
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
							if p.P2PStatus != P2PFullDuplex && p.P2PStatus != P2PAvailable {
								p.P2PStatus = P2PAvailable
								log.Printf("[P2P] Marked peer %s as P2PAvailable after failed hole punch (relay path still up)", targetMACStr)
							}
						}
						// Report the failure so the relay stops waiting on
						// this instruction and re-broadcasts a fresh one
						// (under its own backoff) instead of assuming the
						// pair is still in progress.
						//
						// behaviorIndex comes from currentInstr -- the
						// instruction this round actually ran. It must not be
						// re-derived from the registry: the entry for this
						// target was deleted two lines above, so any lookup
						// that scans the cache finds nothing and falls back to
						// 0. That is how a round of rung 4 was reported as a
						// rung 0 failure on 2026-09-30: the relay penalised an
						// entry that had never run, drove the score to its -10
						// floor, and then kept re-arming the pair at the 300s
						// cap because the blamed rung and the dispatched rung
						// did not match.
						reg.recordNatHolePunchResultLocked(
							targetMACStr,
							NatHolePunchState_PunchStateFailed,
							5,
							"exhausted 5 punch attempts",
							currentInstr.GetBehaviorIndex(),
						)
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
					// UnlistPeer, not RemovePeer: absence from one snapshot is
					// not proof of departure. See graceUnlistedTL.
					reg.UnlistPeerLocked(macAddr)
					log.Printf("peer with MAC address %s absent from new list — unlisted, state kept for grace", macAddr)
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
		//
		// A peer we have positive, recent evidence for stays. This event is
		// the relay's *claim* that these peers are gone; it is not proof. A
		// peer we heard a direct frame from seconds ago is demonstrably
		// here, and destroying it costs a proven P2P path -- its raddr and
		// FullDuplex marker -- for nothing.
		//
		// Why this matters concretely: the relay used to build this payload
		// from getOnlinePeers(), i.e. the nodes that were *staying*, so one
		// node going offline named every other node as departed. Observed
		// 2026-10-02 at 13:32:27 with log5 leaving: log3 removed E1 and
		// log4, log4 removed E1 and log3, each losing a working direct path
		// that had been up since 12:56. Both then spent the rest of the run
		// stuck at Available/Pending with "punch seen but no data frame
		// verified yet", because a rebuilt peer has no raddr and the direct
		// path is gated on one -- a wait on each other that never closes.
		//
		// The relay side is fixed too (relay_room.js must pass peerOverride,
		// as handler.js already did). This guard is the second line: it makes
		// one missed argument non-fatal instead of a full-mesh outage.
		for _, info := range peerInfoList.GetPeerInfos() {
			macAddr := net.HardwareAddr(info.MacAddr).String()
			if ourMAC != "" && macAddr == ourMAC {
				continue
			}
			// Read under the lock, then release before RemovePeer, which
			// takes the write lock itself. This loop runs unlocked: it is
			// inside a switch, not a critical section, and holding peerMu
			// across RemovePeer would deadlock on the non-reentrant RWMutex.
			reg.peerMu.RLock()
			p, known := reg.Peers[macAddr]
			alive := known && reg.recentlyAliveLocked(p)
			reg.peerMu.RUnlock()

			if alive {
				log.Printf("[P2P] unregister list names %s but we have seen it within %v -- keeping it (list is stale or over-broad)",
					macAddr, peerRecentlyAliveWindow)
				continue
			}
			if err := reg.RemovePeer(macAddr); err != nil {
				return fmt.Errorf("failed to remove peer: %v", err)
			}
		}
	default:
		return fmt.Errorf("unknown event type: %v", peerInfoList.GetEventType())
	}
	return nil
}

// The hooks below exist only because test/p2p is an external package and cannot
// reach unexported identifiers or fields.
//
// They are deliberately methods rather than exported fields. The alternative --
// exporting NatHoleInstructions, GraceUnlisted and the peerMu lock itself --
// would let any caller reach inside the registry without going through the
// locking that every other access has to take, and would turn an implementation
// detail into something the compiler now treats as API. A caller can still
// misuse these, but misuse is visible at the call site instead of silent.

// LockForTest takes the registry lock. Exported for test/p2p; not part of the
// supported API.
func (reg *PeerRegistry) LockForTest() { reg.peerMu.Lock() }

// UnlockForTest releases the registry lock. Exported for test/p2p; not part of
// the supported API.
func (reg *PeerRegistry) UnlockForTest() { reg.peerMu.Unlock() }

// NatHoleInstructionsForTest returns the live instruction map, not a copy, so a
// test can seed and clear entries directly.
//
// The map is not safe to touch without LockForTest, exactly as the registry's
// own accessors require. Exported for test/p2p; not part of the supported API.
func (reg *PeerRegistry) NatHoleInstructionsForTest() map[string]*NatHoleInstruction {
	return reg.natHoleInstrs
}

// GraceUnlistedCountForTest reports how many grace tombstones are held.
// Exported for test/p2p; not part of the supported API.
func (reg *PeerRegistry) GraceUnlistedCountForTest() int {
	return len(reg.graceUnlisted)
}

// ExpireGraceTombstonesForTest runs tombstone expiry as of now. The caller must
// hold the registry lock, as the internal caller does. Exported for test/p2p;
// not part of the supported API.
func (reg *PeerRegistry) ExpireGraceTombstonesForTest(now time.Time) {
	reg.expireGraceTombstonesLocked(now)
}

// RecordNatHolePunchResultForTest records a punch result. The caller must hold
// the registry lock, as the internal caller does. Exported for test/p2p; not
// part of the supported API.
func (reg *PeerRegistry) RecordNatHolePunchResultForTest(peerMAC string, state NatHolePunchState, attempts uint32, detail string, behaviorIndex uint32) {
	reg.recordNatHolePunchResultLocked(peerMAC, state, attempts, detail, behaviorIndex)
}

// NatHolePunchResultsForTest returns the live punch-result map, not a copy, so a
// test can seed and clear entries directly. Not safe to touch without
// LockForTest. Exported for test/p2p; not part of the supported API.
// NatHolePunchResultsForTest returns a snapshot of the punch results, for
// tests that poll while a punch goroutine is running.
//
// It copies under peerMu rather than handing back the live map. Returning the
// map itself made every such poll a data race against
// recordNatHolePunchResultLocked, which -race reports as a failure of the test
// under test rather than of the accessor, so the race detector was unusable on
// this package. The copy also keeps a test from observing a half-written
// NatHolePunchResult.
func (reg *PeerRegistry) NatHolePunchResultsForTest() map[string]*NatHolePunchResult {
	reg.peerMu.RLock()
	defer reg.peerMu.RUnlock()
	return reg.NatHolePunchResultsSnapshotLocked()
}

// NatHoleRetryCountsForTest returns the live retry-count map, not a copy. Not
// safe to touch without LockForTest. Exported for test/p2p; not part of the
// supported API.
func (reg *PeerRegistry) NatHoleRetryCountsForTest() map[string]int {
	return reg.natHoleRetryCounts
}

// SetNatHoleInstructionsForTest replaces the instruction map wholesale, so a
// test can seed several entries in one assignment. The caller must hold the
// registry lock. Exported for test/p2p; not part of the supported API.
func (reg *PeerRegistry) SetNatHoleInstructionsForTest(m map[string]*NatHoleInstruction) {
	reg.natHoleInstrs = m
}

// SetNatHoleRetryCountsForTest replaces the retry-count map wholesale. The
// caller must hold the registry lock. Exported for test/p2p; not part of the
// supported API.
func (reg *PeerRegistry) SetNatHoleRetryCountsForTest(m map[string]int) {
	reg.natHoleRetryCounts = m
}

// LookupSockets returns the socket keys this peer is indexed under, without the
// caller having to re-derive the rule that IndexPeerRaddr follows. Exported for
// test/p2p; not part of the supported API.
func (p *Peer) LookupSockets() []string { return p.lookupSockets() }

// SetPeerBySocketForTest installs one socket->peer entry. The caller must hold
// the registry lock. Exported for test/p2p; not part of the supported API.
func (reg *PeerRegistry) SetPeerBySocketForTest(key string, p *Peer) {
	if reg.peerBySocket == nil {
		reg.peerBySocket = map[string]*Peer{}
	}
	reg.peerBySocket[key] = p
}

// LastNatHoleInstrs returns the live last-instruction map, not a copy, so a
// test can seed entries directly. Not safe to touch without LockForTest.
// Exported for test/p2p; not part of the supported API.
func (reg *PeerRegistry) LastNatHoleInstrs() map[string]*NatHoleInstruction {
	return reg.lastNatHoleInstrs
}
