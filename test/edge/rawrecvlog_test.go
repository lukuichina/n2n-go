package edge_test

import (
	. "n2n-go/pkg/edge"
	"net"
	"testing"
	"time"
)

// The receive loop logs through this. Before 2026-10-03 it logged every
// non-punch datagram unconditionally, which is one log write per packet on the
// single loop that also has to keep the UDP buffer drained.
//
// The failure it caused was not cosmetic: with the SQLite sink the edge selects
// by default, each write fsyncs, and on the E1/E2 pair that pushed RTT from
// 19ms to 78ms on the fsyncing side while the plain ICMP path between the same
// two hosts stayed at 15ms.
//
// These pin the rule, not the motivation.

func recvAddr(port string) *net.UDPAddr {
	return &net.UDPAddr{IP: net.IPv4(57, 129, 106, 133), Port: atoiOr(port, 2060)}
}

func atoiOr(s string, def int) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// A steady stream of identical datagrams is traced once, not once per packet.
func TestRawRecvLoggerThrottlesUnchangedStream(t *testing.T) {
	l, _ := newTestLogger()
	addr := recvAddr("2060")

	if !l.ShouldLog(addr, 105, 0x51) {
		t.Fatal("the first datagram from a source was not traced")
	}
	for i := 0; i < 500; i++ {
		if l.ShouldLog(addr, 105, 0x51) {
			t.Fatalf("datagram %d of an unchanged stream was traced", i+1)
		}
	}
}

// The trace is the only record of what a path is carrying, so a change has to
// get through even at full rate. Size and first byte are both checked: a peer
// switching between 105-byte data, 88-byte path probes and 49-byte keepalives
// is exactly the transition worth seeing.
func TestRawRecvLoggerTracesShapeChanges(t *testing.T) {
	l, _ := newTestLogger()
	addr := recvAddr("2060")

	if !l.ShouldLog(addr, 105, 0x51) {
		t.Fatal("first datagram not traced")
	}
	if !l.ShouldLog(addr, 88, 0x05) {
		t.Error("a size change was swallowed")
	}
	if !l.ShouldLog(addr, 88, 0x06) {
		t.Error("a first-byte change was swallowed")
	}
	// Back to a shape already seen: still traced, because the transition is the
	// signal and suppressing it would hide a peer changing its behaviour twice.
	if !l.ShouldLog(addr, 105, 0x51) {
		t.Error("returning to a previous shape was swallowed")
	}
}

// A source that has gone quiet must not be able to stay silent when it returns.
func TestRawRecvLoggerRetracesAfterSilence(t *testing.T) {
	l, clk := newTestLogger()
	addr := recvAddr("2060")

	l.ShouldLog(addr, 105, 0x51)
	// Long enough ago that the slot is eligible for eviction. The clock is
	// injected, so this costs nothing in wall time.
	clk.add(11 * RawRecvRelogInterval)

	if !l.ShouldLog(addr, 105, 0x51) {
		t.Error("a source returning after a long silence was not re-traced")
	}
}

// Different peers are tracked independently: one busy source must not silence
// another.
func TestRawRecvLoggerSeparatesSources(t *testing.T) {
	l, _ := newTestLogger()
	a := recvAddr("2060")
	b := recvAddr("45001")

	if !l.ShouldLog(a, 105, 0x51) {
		t.Fatal("first source not traced")
	}
	if !l.ShouldLog(b, 76, 0x05) {
		t.Error("a second source was silenced by traffic on the first")
	}
	if l.ShouldLog(a, 105, 0x51) || l.ShouldLog(b, 76, 0x05) {
		t.Error("both sources should be quiet on their second datagram")
	}
}

func TestRawRecvLoggerForgetReopensASource(t *testing.T) {
	l, _ := newTestLogger()
	addr := recvAddr("2060")

	l.ShouldLog(addr, 105, 0x51)
	if l.ShouldLog(addr, 105, 0x51) {
		t.Fatal("second datagram should have been throttled")
	}
	l.Forget(addr)
	if !l.ShouldLog(addr, 105, 0x51) {
		t.Error("Forget() did not make the next datagram traceable again")
	}
}

// An unchanged stream is re-traced periodically, so a path that carries traffic
// forever still shows up in the log without showing up per packet.
func TestRawRecvLoggerRelogsUnchangedStreamPeriodically(t *testing.T) {
	l, clk := newTestLogger()
	addr := recvAddr("2060")

	l.ShouldLog(addr, 105, 0x51)
	clk.add(RawRecvRelogInterval + time.Millisecond)

	if !l.ShouldLog(addr, 105, 0x51) {
		t.Error("an unchanged datagram was never re-traced, so the log would go silent")
	}
}

// fakeClock lets the timing tests move time forward without sleeping and
// without editing the logger's own bookkeeping. NewRawRecvLoggerForTest reads
// the clock through a function, so the test owns time and the logger keeps its
// fields private.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time      { return c.t }
func (c *fakeClock) add(d time.Duration) { c.t = c.t.Add(d) }

func newTestLogger() (*RawRecvLogger, *fakeClock) {
	c := &fakeClock{t: time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)}
	return NewRawRecvLoggerForTest(c.now), c
}
