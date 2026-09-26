package p2p

import (
	"sync"
	"time"
)

// NAT hole-punch wire format.
//
// A punch is 4 magic bytes; the acknowledgement is 8. The original
// implementation built the ACK by concatenating the punch with itself:
//
//	[]byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFF, 0xFE, 0xFD, 0xFC}
//
// and the receive path classified a packet purely by its first four bytes:
//
//	if n >= 4 && buf[0] == 0xFF && buf[1] == 0xFE && buf[2] == 0xFD && buf[3] == 0xFC
//
// That made an ACK indistinguishable from a punch, so BOTH edges answered
// every ACK with another ACK. Each datagram produced exactly one reply, which
// is a self-sustaining echo loop running at 1/RTT (~90 pkt/s at the 23.7ms
// E1<->E2 RTT), and it only died when a UDP datagram was lost — the loop has
// no independent driver. Observed on E2: 7 four-byte punches against 558
// eight-byte ACKs.
//
// The fix is to make the ACK carry its own marker so it stops matching the
// punch predicate. Byte 4 is 0x00 for a new-style ACK, while the legacy ACK
// repeats 0xFF there; a legacy ACK is still recognised as evidence that the
// path is open, it is simply never answered.
//
// Mixed-version deployments degrade safely: an upgraded edge never answers a
// legacy ACK, so the chain terminates after one hop even if the peer still
// runs the old binary.
var (
	// punchMagic is the 4-byte prefix of every punch/ACK datagram.
	punchMagic = [4]byte{0xFF, 0xFE, 0xFD, 0xFC}

	// punchAckMarker is the byte at offset 4 of a new-style ACK. It
	// deliberately differs from 0xFF (the legacy ACK's value there).
	punchAckMarker byte = 0x00
)

// punchAckBytes is the new-style acknowledgement. It reuses the punch magic so
// that peers still gating on the first four bytes keep treating it as punch
// traffic, and only differs in the marker byte.
var punchAckBytes = []byte{0xFF, 0xFE, 0xFD, 0xFC, 0x00, 0xFE, 0xFD, 0xFC}

// punchAckThrottle is the minimum spacing between two ACKs sent to the same
// peer. The protocol only needs one ACK per punch; this bounds the damage if
// a peer (or an old build) keeps re-sending punches, so the reply rate can
// never become the dominant traffic on the socket.
const punchAckThrottle = 500 * time.Millisecond

// punchPublishThrottle bounds how often inbound punch/ACK traffic is allowed
// to publish state to the supernode. NotePunchPacket and SetFullDuplex are
// cheap and idempotent, but SetPendingChanges + RecordNatHolePunchResult make
// the edge emit a PeerP2PInfos update, so doing them per packet turns a punch
// burst into supernode churn (and, via the state flapping that follows, into
// periodic fallback to the relay).
const punchPublishThrottle = 1 * time.Second

// IsPunchAck reports whether buf is a punch ACK, of either the current or the
// legacy encoding. It is still punch evidence — the peer reached our socket —
// it just must not be answered.
func IsPunchAck(buf []byte, n int) bool {
	if !IsPunch(buf, n) {
		return false
	}
	// Current ACK: 8 bytes with the marker byte.
	if n >= 8 && buf[4] == punchAckMarker {
		return true
	}
	// Legacy ACK: the punch repeated twice.
	if n >= 8 && buf[4] == 0xFF {
		return true
	}
	return false
}

// IsPunch reports whether buf is punch traffic — a punch or an ACK. It is the
// shared predicate for "this datagram is part of hole punching".
func IsPunch(buf []byte, n int) bool {
	if n < 4 {
		return false
	}
	return buf[0] == punchMagic[0] && buf[1] == punchMagic[1] &&
		buf[2] == punchMagic[2] && buf[3] == punchMagic[3]
}

// ShouldAnswerPunch reports whether this datagram deserves an ACK.
//
// The answer is "only for an actual punch". Answering an ACK is what created
// the echo loop; an ACK already carries the confirmation its sender needs, so
// re-answering it is pure amplification.
func ShouldAnswerPunch(buf []byte, n int) bool {
	return IsPunch(buf, n) && !IsPunchAck(buf, n)
}

// PunchAckBytes returns a fresh copy of the ACK datagram.
func PunchAckBytes() []byte {
	out := make([]byte, len(punchAckBytes))
	copy(out, punchAckBytes)
	return out
}

// punchAckMu guards lastAckSentAt / lastPunchPublishedAt.
var punchAckMu sync.Mutex

// AllowPunchAck implements the per-peer ACK rate limit. It reports whether an
// ACK may be sent now, and records the send.
func (p *Peer) AllowPunchAck(now time.Time) bool {
	p.punchAckMu.Lock()
	defer p.punchAckMu.Unlock()
	if !p.lastAckSentAt.IsZero() && now.Sub(p.lastAckSentAt) < punchAckThrottle {
		return false
	}
	p.lastAckSentAt = now
	return true
}

// AllowPunchPublish reports whether inbound punch traffic may refresh the
// state this edge publishes about the peer.
func (p *Peer) AllowPunchPublish(now time.Time) bool {
	p.punchAckMu.Lock()
	defer p.punchAckMu.Unlock()
	if !p.lastPunchPublishedAt.IsZero() && now.Sub(p.lastPunchPublishedAt) < punchPublishThrottle {
		return false
	}
	p.lastPunchPublishedAt = now
	return true
}
