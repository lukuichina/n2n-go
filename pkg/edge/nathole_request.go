package edge

import (
	"n2n-go/pkg/log"
	"time"
)

// How the post-registration punch-request burst behaves.
const (
	// How often we re-announce our P2P reachability while we are still
	// waiting for the relay to hand us a NatHoleInstruction.
	punchRequestPeriod = 2 * time.Second

	// Upper bound on the initial burst. The burst backs off past this, it
	// does not stop here: the relay's per-pair backoff used to reach 5
	// minutes (300000ms in handler.js), and a burst that ends before the
	// relay's cooldown does leaves the pair with nobody asking for an
	// instruction. Observed on 2026-09-30: the edge announced for 24s, gave
	// up, and the pair sat silent for 4m38s more until the relay's periodic
	// save alarm happened to fire.
	punchRequestInitialWindow = 24 * time.Second

	// Ceiling for the slowed cadence. The relay's worst-case per-pair backoff
	// is 300s, so announcing at 30s still leaves several chances inside it
	// while keeping a permanently-unpunchable pair from being announced at a
	// meaningful rate.
	punchRequestMaxPeriod = 30 * time.Second
)

// requestNatHoleAfterRegister re-announces our P2P reachability to the supernode
// until the relay answers with a NatHoleInstruction addressed to us.
//
// Why this is needed at all: the relay only ever runs coordinateNatHole when a
// P2PStateInfo arrives, and the edge does not send those periodically.
// sendP2PInfos() short-circuits on HasPendingChanges() and the pending flag is
// consumed by the first successful send, so after registration the edge goes
// quiet until some peer state changes. When the relay's stagger gate defers a
// pair, or when its per-pair backoff has not yet expired, it relies on a
// Durable Object alarm to come back and re-drive. That alarm is single-slot and
// shares storage with the relay's save alarm, so it can be overwritten. When it
// is, nothing re-evaluates the pair: the edge is silent, the relay is waiting
// for an alarm that will not come, and the two sides punch past each other or
// never punch at all.
//
// A repeating announce makes the handshake self-healing rather than dependent on
// a single alarm surviving. It stops as soon as the relay demonstrably takes
// over, i.e. hands us an instruction.
//
// Shutdown notes: a stopped edge stops announcing, so this cannot outlive the
// process. The loop is bounded by ctx.Done() on the other side.
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

		// Back off after the initial window instead of stopping. The relay's
		// own cooldown is the thing we are waiting on, so our cadence only has
		// to stay comfortably below it; going slower keeps a pair that cannot
		// punch from being announced forever at 2s while still landing well
		// inside the worst-case 300s window.
		period := punchRequestPeriod
		deadline := time.Now().Add(punchRequestInitialWindow)
		started := time.Now()
		slowed := false

		for {
			select {
			case <-e.ctx.Done():
				return
			case <-time.After(period):
			}

			// Stop only once the relay has actually handed us an
			// instruction. Merely learning that a peer exists is not
			// enough: the peer list arrives on the first PeerInfoList,
			// long before the relay decides to schedule anything, and
			// bailing out there would reintroduce exactly the stall this
			// burst exists to prevent.
			if e.Peers.HasNatHoleInstruction() {
				log.Printf("punch-request: instruction received after %s, stopping",
					time.Since(started).Truncate(time.Millisecond))
				return
			}

			if !announce() {
				log.Printf("punch-request: announce failed, stopping")
				return
			}

			// Keep announcing, slower. Held separately from the wait above so
			// the cadence change lands after the announce rather than
			// stretching the gap between two of them. `slowed` keeps this to
			// one log line instead of one per iteration.
			if !slowed && time.Now().After(deadline) {
				period *= 2
				if period > punchRequestMaxPeriod {
					period = punchRequestMaxPeriod
				}
				slowed = true
				log.Printf("punch-request: no instruction after %s, slowing to %s and continuing",
					punchRequestInitialWindow, period)
			}
		}
	}()
}
