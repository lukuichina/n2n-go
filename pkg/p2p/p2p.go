package p2p

import (
	"fmt"
	"n2n-go/pkg/log"
	"net"
	"sync"
	"time"
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
}

func (p *Peer) resetPendingTTL() {
	p.pendingTTL = 30
}

type PeerRegistry struct {
	CommunityName string
	peerMu        sync.RWMutex
	Me            *Peer
	Peers         map[string]*Peer //keyed by MACAddr.String()
	peerBySocket  map[string]*Peer // keyed by net.UDPAddr.String()
	p2pDatasMu    sync.RWMutex
	P2PCommunityDatas
	IsWaitingCommunityDatas bool
	hasPendingChanges       bool
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
		CommunityName: communityName,
		Peers:         make(map[string]*Peer),
		peerBySocket:  make(map[string]*Peer),
	}
}

func (reg *PeerRegistry) GetPeerP2PInfos() *PeerP2PInfos {
	var to []*PeerInfo
	for _, v := range reg.Peers {
		to = append(to, &v.Infos)
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

func (reg *PeerRegistry) GetPeer(MACAddr string) (*Peer, error) {
	reg.peerMu.RLock()
	defer reg.peerMu.RUnlock()

	peer, exists := reg.Peers[MACAddr]
	if !exists {
		return nil, fmt.Errorf("peer with MAC address %s not found", MACAddr)
	}
	return peer, nil
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

func (p *Peer) SetFullDuplex(value bool) (bool, error) {
	changed := false
	if value {
		if !(p.P2PStatus == P2PAvailable) {
			return false, fmt.Errorf("cannot set full duplex without first P2PAvailable state")
		}
	}
	if value != p.IsFullDuplex {
		log.Printf("updated peer %s/%s/%s with FullDuplex=%v", p.Infos.Desc, p.Infos.VirtualIp, net.HardwareAddr(p.Infos.MacAddr).String(), value)
		changed = true
	}
	p.IsFullDuplex = value
	return changed, nil
}

func (p *Peer) UpdateP2PStatus(status P2PCapacity, checkid string) bool {
	previousStatus := p.P2PStatus
	var forcedStatement string
	skipLog := false
	if p.P2PStatus == status {
		skipLog = true
		if status == P2PPending {
			p.pendingTTL = p.pendingTTL - 1
		}
	} else {
		if p.P2PStatus == P2PUnknown && status == P2PPending {
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
		existingPeer.UpdatedAt = time.Now()
		log.Printf("updated peer now hold of %s MACAddr:", macAddr)
		log.Printf(" was: vip=%s PubSocket=%s desc=%s", origPeer.Infos.VirtualIp, origPeer.Infos.PubSocket, origPeer.Infos.Desc)
		log.Printf(" now: vip=%s PubSocket=%s desc=%s", existingPeer.Infos.VirtualIp, existingPeer.Infos.PubSocket, existingPeer.Infos.Desc)
		delete(reg.peerBySocket, origPeer.UDPAddr().String())
		reg.peerBySocket[existingPeer.UDPAddr().String()] = existingPeer
		reg.SetPendingChanges()
		return existingPeer, nil
	}

	peer := &Peer{
		Infos:     infos,
		P2PStatus: P2PUnknown,
		UpdatedAt: time.Now(),
	}
	reg.Peers[macAddr] = peer
	reg.peerBySocket[peer.UDPAddr().String()] = peer
	log.Printf("added peer %s/%s/%s with PubSocket=%s", peer.Infos.Desc, peer.Infos.VirtualIp, net.HardwareAddr(peer.Infos.MacAddr).String(), peer.Infos.PubSocket)
	reg.SetPendingChanges()
	return peer, nil
}

func (reg *PeerRegistry) RemovePeer(MACAddr string) error {
	reg.peerMu.Lock()
	defer reg.peerMu.Unlock()

	p, exists := reg.Peers[MACAddr]
	if !exists {
		return fmt.Errorf("peer with MAC address %s not found", MACAddr)
	}

	dDesc := p.Infos.Desc
	dVip := p.Infos.VirtualIp
	dUDPAddrString := p.UDPAddr().String()
	delete(reg.Peers, MACAddr)
	delete(reg.peerBySocket, dUDPAddrString)
	log.Printf("removed peer %s/%s/%s", dDesc, dVip, MACAddr)
	reg.SetPendingChanges()
	return nil
}

func (p *Peer) UDPAddr() *net.UDPAddr {
	return parseUDPAddr(p.Infos.PubSocket)
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

// HandlePeerInfoList processes a peer.PeerInfoList and updates the registry accordingly.
// Depending on the event type, it may override or populate the full registry (ListEvent),
// with an option to overwrite existing P2PStatuses, or it may add or delete peers.
func (reg *PeerRegistry) HandlePeerInfoList(peerInfoList *PeerInfoList, reset bool, overwrite bool) error {

	switch PeerInfoEventType(peerInfoList.GetEventType()) {
	case TypeList:
		if reset {
			reg.peerMu.Lock()
			reg.Peers = make(map[string]*Peer)
			reg.peerBySocket = make(map[string]*Peer)
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
		}
		for _, info := range peerInfoList.GetPeerInfos() {
			_, err := reg.AddPeer(*info, overwrite)
			if err != nil {
				return fmt.Errorf("failed to add peer: %v", err)
			}
		}
		if !reset {
			// Remove peers that are not in the new list
			newPeers := make(map[string]struct{})
			for _, info := range peerInfoList.GetPeerInfos() {
				macAddr := net.HardwareAddr(info.MacAddr).String()
				newPeers[macAddr] = struct{}{}
			}

			for macAddr := range reg.Peers {
				if _, exists := newPeers[macAddr]; !exists {
					reg.RemovePeer(macAddr)
					log.Printf("removed peer with MAC address %s not in new list", macAddr)
				}
			}
		}
	case TypeRegister:
		for _, info := range peerInfoList.GetPeerInfos() {
			_, err := reg.AddPeer(*info, overwrite)
			if err != nil {
				return fmt.Errorf("failed to add peer: %v", err)
			}
		}
	case TypeUnregister:
		for _, info := range peerInfoList.GetPeerInfos() {
			macAddr := net.HardwareAddr(info.MacAddr).String()
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
