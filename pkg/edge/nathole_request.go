package edge

import (
	"n2n-go/pkg/log"
	"time"
)

// How long the post-registration punch-request burst runs, and how often it
// re-announces.
const (
	punchRequestWindow = 24 * time.Second
	punchRequestPeriod = 2 * time.Second
)

// requestNatHoleAfterRegister re-announces our P2P reachability to the
// supernode repeatedly for a short window after registering, so the relay has
// several chances to schedule our pair.
//
// Why this is needed at all: the relay only ever runs coordinateNatHole when a
// P2PStateInfo arrives, and the edge does not send those periodically.
// sendP2PInfos() short-circuits on HasPendingChanges() and the pending flag is
// consumed by the first successful send, so after registration the edge goes
// quiet until some peer state changes. When the relay's stagger gate defers a
// pair -- it holds the first round until the newer peer has been registered
// long enough for its NAT mapping to exist -- it arms a Durable Object alarm
// to come back and re-drive. That alarm is single-slot and shares storage with
// the relay's save alarm, so it can be overwritten. When it is, nothing ever
// re-evaluates the pair: the edge is silent, the relay is waiting for an
// alarm that will not come, and the two sides punch past each other. Observed
// as a 30 second gap between a restart and the first punch attempt, with the
// far end hammering a dead port the whole time.
//
// A short burst makes the handshake self-healing rather than dependent on a
// single alarm surviving. It costs a handful of small messages and stops on
// its own; the steady state is unchanged, because the edge still sends no
// P2PStateInfo when nothing is pending.
//
// The burst stops early once the relay has answered with something better
// than silence: a NatHoleInstruction addressed to us. At that point the relay
// is demonstrably driving and extra announces would only add noise. The window
// is the backstop for when it never answers.
func (e *EdgeClient) requestNatHoleAfterRegister() {
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()

		announce := func() bool {
			// Force a send: sendP2PInfos() is a no-op unless something is
			// pending, and nothing is pending now that an earlier announce
			// consumed the flag.
			e.Peers.SetPendingChanges()
			return e.sendP2PInfos() == nil
		}

		// First announce goes out immediately. reg.Me is already fully
		// populated -- STUN completed before the registration ACK -- so the
		// relay can act on this pass rather than waiting out a tick.
		if !announce() {
			log.Printf("punch-request: first announce failed, giving up")
			return
		}

		deadline := time.Now().Add(punchRequestWindow)
		for {
			select {
			case <-e.ctx.Done():
				return
			case <-time.After(punchRequestPeriod):
			}

			// Stop only once the relay has actually handed us an
			// instruction. Merely learning that a peer exists is not
			// enough: the peer list arrives on the first PeerInfoList,
			// long before the relay decides to schedule anything, and
			// bailing out there would reintroduce exactly the stall this
			// burst exists to prevent.
			if e.Peers.HasNatHoleInstruction() {
				log.Printf("punch-request burst: instruction received, stopping")
				return
			}
			if time.Now().After(deadline) {
				log.Printf("punch-request burst: window elapsed after %s, no instruction received",
					punchRequestWindow)
				return
			}
			if !announce() {
				log.Printf("punch-request burst: announce failed, stopping")
				return
			}
		}
	}()
}
