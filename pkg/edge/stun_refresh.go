package edge

import (
	"net"
	"time"

	"n2n-go/pkg/log"
)

// STUNResult is the outcome of a discovery.
type STUNResult struct {
	Addr *net.UDPAddr
	// AllAddrs holds every reflexive address seen, in observation order.
	AllAddrs   []string
	NatFeature *NatFeature
}

// stRefresh is the periodic public-mapping refresh.
//
// The mapping is what the relay hands to the peer as a punch target, so a
// socket that has been re-bound -- by an edge restart, or the kernel
// re-assigning the port -- must be re-advertised or every subsequent round
// punches at an address that no longer exists.
//
// FRP has no equivalent problem by construction: nathole.Prepare() builds a
// fresh ListenConn and returns MappedAddrs for the current round, and
// Controller.HandleClient replaces session.clientMsg wholesale on every
// NatHoleClient (pkg/nathole/controller.go:255). Here the equivalent is a
// periodic re-probe on the P2P socket.
//
// The probe is safe to run while punching because it never reads the socket
// itself -- see STUNClient in stun_probe.go. An earlier version called
// pubSocketString() from this loop and deadlocked the whole goroutine for 75
// minutes on 2026-10-01, taking PeerP2PInfos reporting down with it.
const NatHoleAddrRefreshInterval = 15 * time.Second

// beginNatHoleAddrRefresh starts a probe and returns it. The caller (the
// handleP2P loop, which owns the socket) feeds the response in via
// e.STUNClient.Feed and then calls finishNatHoleAddrRefresh.
func (e *EdgeClient) beginNatHoleAddrRefresh() *PendingProbe {
	if e.STUNClient == nil || e.Peers == nil || e.Peers.Me == nil {
		return nil
	}
	probe, err := e.STUNClient.BeginRefresh()
	if err != nil {
		return nil
	}
	return probe
}

// finishNatHoleAddrRefresh records the outcome. It re-advertises only when
// the mapping actually moved: pubSocketString's caller used to do this, and
// an unconditional write would add a registry bump plus an extra
// P2PStateInfo on every tick forever.
func (e *EdgeClient) finishNatHoleAddrRefresh(probe *PendingProbe) {
	if probe == nil {
		return
	}
	result, err := probe.Wait()
	if err != nil || result == nil || result.Addr == nil {
		// A failed probe must leave the advertised mapping alone. Overwriting
		// it with a zero or partial address would point the peer's punch at
		// nothing, which is strictly worse than a stale-but-working value.
		return
	}

	after := result.Addr.String()
	if after == e.Peers.Me.Infos.PubSocket {
		// Log the confirmation too. A refresh that succeeds quietly is
		// indistinguishable from one that never ran -- and during the
		// 2026-10-01 deadlock that ambiguity cost hours of chasing a
		// missing log line instead of a blocked goroutine.
		log.Printf("[P2P] public mapping confirmed %s", after)
		return
	}

	before := e.Peers.Me.Infos.PubSocket
	e.Peers.Me.Infos.PubSocket = after
	if result.NatFeature != nil {
		e.NatFeature = result.NatFeature
	}
	e.Peers.SetPendingChanges()
	log.Printf("[P2P] public mapping moved %s -> %s, re-advertising to relay", before, after)
}
