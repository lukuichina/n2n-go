package edge_test

import (
	"bytes"
	. "n2n-go/pkg/edge"
	"net"
	"sync"
	"testing"

	"n2n-go/pkg/log"
	"n2n-go/pkg/p2p"
)

// --- 2026-09-30: group/broadcast destinations flooded the log ----------------
//
// E1's log carried dozens of identical lines per second:
//
//	[P2P-DEBUG] peer lookup failed for 01:00:5e:7f:ff:fa: ... using supernode
//	[P2P-DEBUG] peer lookup failed for 01:80:c2:00:00:0e: ... using supernode
//
// 01:00:5e:7f:ff:fa is IPv4 multicast 224.0.0.250 (VRRP) and 01:80:c2:00:00:0e
// is IEEE 802.1AB LLDP. Neither can ever be in the peer registry: the registry
// holds edges, and an edge is addressed by the MAC the supernode assigned to
// its tap, which is always unicast. So the lookup was guaranteed to fail and
// the fallback to the supernode was guaranteed to happen -- the line carried no
// information, it only buried the case routines.go:68 exists to talk about (a
// unicast peer that is genuinely missing, i.e. permanent isolation).
//
// The fix is a pre-check in UDPAddrWithStrategy: classify dst before looking
// it up, route group/broadcast straight to the supernode, and stay quiet. The
// test below pins both halves of that -- the right socket is still chosen
// (behaviour unchanged), and the unicast path is untouched.

func TestUDPAddrWithStrategy_RoutesGroupAndBroadcastToSupernode(t *testing.T) {
	supernode := &net.UDPAddr{IP: net.ParseIP("104.21.48.16"), Port: 443}

	cases := []struct {
		name string
		dst  net.HardwareAddr
	}{
		{"IPv4 multicast 224.0.0.250 (VRRP)", net.HardwareAddr{0x01, 0x00, 0x5e, 0x7f, 0xff, 0xfa}},
		{"LLDP 01:80:c2:00:00:0e", net.HardwareAddr{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e}},
		{"IPv4 multicast 224.0.0.251 (mDNS)", net.HardwareAddr{0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb}},
		{"IPv6 multicast 33:33:00:00:00:fb", net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0xfb}},
		{"broadcast", net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// An empty registry: no peer can be found, so a lookup that ran
			// would necessarily take the err branch.
			e := &EdgeClient{Peers: p2p.NewPeerRegistry("myc"), SupernodeAddr: supernode}

			before := NonUnicastRouteCount()
			addr, isP2P, err := e.UDPAddrWithStrategy(c.dst, p2p.UDPBestEffort)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if isP2P {
				t.Errorf("group/broadcast %s must never take the P2P path", c.dst)
			}
			if addr.String() != supernode.String() {
				t.Errorf("got %v, want supernode %v", addr, supernode)
			}
			// The pre-check is what must have made that decision; if the code
			// had reached GetPeer instead, this counter would not have moved.
			if got := NonUnicastRouteCount(); got != before+1 {
				t.Errorf("suppressed counter = %d, want %d: the pre-check did not run, the peer lookup did",
					got, before+1)
			}
		})
	}
}

// The counter above proves the pre-check ran, but not that it was silent --
// and silence is the point of the change. Capture the log around a group and a
// unicast destination and compare.
func TestUDPAddrWithStrategy_GroupAndBroadcastAreSilent(t *testing.T) {
	supernode := &net.UDPAddr{IP: net.ParseIP("104.21.48.16"), Port: 443}
	groupMAC := net.HardwareAddr{0x01, 0x00, 0x5e, 0x7f, 0xff, 0xfa}

	e := &EdgeClient{Peers: p2p.NewPeerRegistry("myc"), SupernodeAddr: supernode}

	groupLog := captureLog(t, func() {
		if _, _, err := e.UDPAddrWithStrategy(groupMAC, p2p.UDPBestEffort); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if groupLog != "" {
		t.Errorf("group destination must not log anything, got:\n%s", groupLog)
	}

	// The unicast path is where the line belongs. An unknown unicast peer is a
	// real condition -- a missed peer-list notification strands the two edges
	// permanently -- so it must still be reported.
	unicastMAC := net.HardwareAddr{0x0a, 0xe3, 0x8f, 0xd6, 0x51, 0xa2}
	unicastLog := captureLog(t, func() {
		if _, _, err := e.UDPAddrWithStrategy(unicastMAC, p2p.UDPBestEffort); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if unicastLog == "" {
		t.Error("an unknown *unicast* peer must still be logged; that is the failure this line exists for")
	}
}

// lockedBuffer collects log output. The logger is global, so the mutex keeps a
// parallel test from interleaving its own lines into this buffer.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureLog redirects the package logger for the duration of fn and returns
// everything written to it.
func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf lockedBuffer
	log.SetOutput(&buf)
	defer log.SetOutput(nil)
	fn()
	return buf.String()
}
