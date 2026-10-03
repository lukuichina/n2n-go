package edge

import (
	"net"
	"sync"
	"time"

	"n2n-go/pkg/log"
)

// RawRecvRelogInterval bounds how often an unchanged datagram shape is traced
// again. Long enough that a steady stream is a handful of lines instead of one
// per packet, short enough that a path that stops carrying traffic is noticed
// within a log interval rather than never.
const RawRecvRelogInterval = 2 * time.Second

type rawRecvShape struct {
	size      int
	firstByte byte
	lastAt    time.Time
}

// RawRecvLogger decides which received datagrams are worth a log line.
//
// This used to be logged unconditionally for every non-punch datagram, which is
// one log write per packet on the single receive loop, and the sink is not
// always a terminal. With the SQLite sink (edge.EnsureEdgeLogger, which the
// edge selects unless -l/--stdout-log is given) each write costs an fsync, and
// on a cloud volume that blocks the loop long enough for the UDP buffer to
// overflow. Measured 2026-10-03 on the E1/E2 pair, FullDuplex via p2p, with the
// public ICMP path between the same two hosts at 15.0ms and 0% loss:
//
//	E2 on the SQLite sink      78.4ms avg, 3% loss
//	both on the console sink   19.2ms avg, 8-12% loss
//	ICMP, same two hosts       15.0ms, 0% loss
//
// So the trace was costing ~60ms of RTT on the side that fsynced, and the loss
// showed up on both sides -- the console sink still pays a format and a write
// per packet, it just does not pay a disk. The route-decision trace above has
// the same problem and has been on change-only since it was written; this is
// that rule applied here.
//
// The shape key is source, size and first byte, which is what actually varies
// and what makes the line useful when diagnosing a path: a peer switching from
// 105-byte data to 88-byte probes, or an unexpected source appearing.
type RawRecvLogger struct {
	// now overrides the clock for tests; nil means time.Now.
	now    func() time.Time
	mu     sync.Mutex
	shapes map[string]rawRecvShape
}

func (l *RawRecvLogger) ShouldLog(addr net.Addr, n int, first byte) bool {
	key := addr.String()
	now := l.clock()

	l.mu.Lock()
	defer l.mu.Unlock()

	prev, seen := l.shapes[key]
	if seen && prev.size == n && prev.firstByte == first && now.Sub(prev.lastAt) < RawRecvRelogInterval {
		return false
	}
	if !seen {
		if l.shapes == nil {
			l.shapes = make(map[string]rawRecvShape)
		}
	}

	// Only the sources still carrying traffic are worth remembering. A peer
	// that goes quiet has to be able to log again immediately when it returns,
	// which it cannot do if its slot is only overwritten on the next packet.
	if seen && now.Sub(prev.lastAt) > 10*RawRecvRelogInterval {
		delete(l.shapes, key)
	}

	l.shapes[key] = rawRecvShape{size: n, firstByte: first, lastAt: now}
	return true
}

// Forget drops a source's shape so its next datagram is always traced. Called
// when a socket closes or a peer goes away, so a stale slot cannot silence a
// path that comes back.
func (l *RawRecvLogger) Forget(addr net.Addr) {
	l.mu.Lock()
	delete(l.shapes, addr.String())
	l.mu.Unlock()
}

// rawRecvLoggerForP2P traces the dedicated P2P socket's receive loop.
var rawRecvLoggerForP2P = &RawRecvLogger{}

// LogRawRecv traces one datagram off the P2P socket, subject to the change-only
// rule in RawRecvLogger.
func LogRawRecv(addr net.Addr, n int, first byte) {
	if rawRecvLoggerForP2P.ShouldLog(addr, n, first) {
		log.Printf("[P2P-DEBUG] raw recv %d bytes from %v, first byte=0x%02x", n, addr, first)
	}
}

// clock is the logger's source of time. A nil now means real time, so the
// zero value of RawRecvLogger stays usable and the production instance at
// var rawRecvLoggerForP2P needs no construction.
func (l *RawRecvLogger) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

// NewRawRecvLoggerForTest returns a logger that reads time from now instead of
// the real clock. It exists so test/edge can exercise the re-log and eviction
// timing without sleeping, and without reaching into the logger's own state.
//
// Exported for test/edge; not part of the supported API.
func NewRawRecvLoggerForTest(now func() time.Time) *RawRecvLogger {
	return &RawRecvLogger{now: now}
}
