package edge_test

import (
	. "n2n-go/pkg/edge"
	"net"
	"testing"
	"time"

	"github.com/pion/stun/v2"
)

// The refresh must never read the P2P socket.
//
// This is the regression guard for a bug that took the whole edge down on
// 2026-10-01: refreshNatHoleAdvertisedAddr called pubSocketString(), which
// called DiscoverWithClassification(), which called conn.ReadFromUDP on the
// very socket handleP2P is blocked on. The STUN read loop discards anything
// that is not a STUN message, so it swallowed the peer's hole-punch packets
// while handleP2P kept feeding the socket with relay traffic -- each wakeup
// resetting the other's progress.
//
// A goroutine dump from E2 showed the whole handleP2PInfos goroutine parked
// for 75 minutes:
//
//   handleP2PInfos            routines.go:242
//     refreshNatHoleAdvertisedAddr  routines.go:267
//       pubSocketString        setup.go:527
//         DiscoverWithClassification  stun.go:133
//           UDPConn.ReadFromUDP  [blocked]
//
// Because that goroutine also owns the PeerP2PInfos send, the relay stopped
// learning the peer's address at all, which is what made E2 receive zero
// direct packets from E1.
//
// FRP avoids this by construction: nathole.Prepare() runs its single STUN
// transaction before the punch loop starts, so the punch loop is the socket's
// only reader. The periodic refresh here has the same constraint, which is
// why it goes through BeginRefresh/Feed instead of reading.

func TestBeginRefreshDoesNotReadTheSocket(t *testing.T) {
	// A socket that would answer if anyone read from it. If BeginRefresh
	// blocked on a read, this test would hang rather than fail, so the
	// timeout is the assertion.
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("cannot bind loopback UDP: %v", err)
	}
	defer server.Close()

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("cannot bind loopback UDP: %v", err)
	}
	defer client.Close()

	sc := NewSTUNClient(client, []string{server.LocalAddr().String()})

	done := make(chan struct{})
	var probe *PendingProbe
	var err2 error
	go func() {
		defer close(done)
		probe, err2 = sc.BeginRefresh()
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("BeginRefresh blocked: it must send the request and return, " +
			"leaving the socket to handleP2P")
	}

	if err2 != nil {
		t.Fatalf("BeginRefresh: %v", err2)
	}
	if probe == nil {
		t.Fatal("BeginRefresh returned no probe")
	}
}

// A probe that never gets an answer must expire instead of wedging the loop
// that owns it. While one probe is stuck, a later refresh must still be able
// to start -- otherwise one dead STUN server freezes the mapping permanently,
// which is the failure this whole change exists to prevent.
func TestStaleProbeIsSupersededByTheNextRefresh(t *testing.T) {
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("cannot bind loopback UDP: %v", err)
	}
	defer client.Close()

	sc := NewSTUNClient(client, []string{"127.0.0.1:1"}) // nothing listens here

	first, err := sc.BeginRefresh()
	if err != nil {
		t.Fatalf("BeginRefresh: %v", err)
	}

	// The first probe is still unanswered.
	second, err := sc.BeginRefresh()
	if err != nil {
		t.Fatalf("second BeginRefresh: %v", err)
	}
	if first == second {
		t.Fatal("the stuck probe was reused instead of being superseded")
	}

	// Wait on the abandoned probe must return rather than block forever,
	// and the handleP2P-side code that awaits it must be able to move on.
	start := time.Now()
	if _, err := first.Wait(); err == nil {
		t.Error("superseded probe reported success; it should report failure")
	}
	if elapsed := time.Since(start); elapsed > RefreshTimeout+time.Second {
		t.Errorf("Wait on a superseded probe took %v; it must respect "+
			"RefreshTimeout so the caller is never wedged", elapsed)
	}
}

// Feed must consume only the response to the pending transaction.
//
// handleP2P hands every datagram here before dispatching it, so a false
// positive would swallow real P2P traffic -- punch packets included, which is
// precisely how the original bug destroyed the tunnel.
func TestFeedIgnoresNonMatchingTraffic(t *testing.T) {
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("cannot bind loopback UDP: %v", err)
	}
	defer client.Close()

	sc := NewSTUNClient(client, []string{"127.0.0.1:1"})
	probe, err := sc.BeginRefresh()
	if err != nil {
		t.Fatalf("BeginRefresh: %v", err)
	}
	_ = probe

	cases := []struct {
		name string
		data []byte
	}{
		{"relay protoV frame", []byte{0x05, 0x02, 0x00, 0x01, 0x00}},
		{"punch packet", []byte{0xFF, 0xFE, 0xFD, 0xFC}},
		{"empty", []byte{}},
		{"garbage", []byte("not a stun message at all")},
	}
	for _, tc := range cases {
		if sc.Feed(tc.data) {
			t.Errorf("Feed consumed %s; non-STUN traffic must pass through to "+
				"handleP2P untouched", tc.name)
		}
	}

	// A STUN response carrying a different transaction ID is still not ours.
	other, err := stun.Build(stun.TransactionID, stun.BindingSuccess)
	if err != nil {
		t.Fatalf("stun.Build: %v", err)
	}
	if sc.Feed(other.Raw) {
		t.Error("Feed consumed a STUN response for a different transaction")
	}

	// The real one must be consumed.
	// Build a success response that echoes the pending transaction ID.
	ownTxn := sc.PendingTransactionForTest()

	// Hand-build a Binding Success carrying an XOR-MAPPED-ADDRESS.
	//
	// stun.Build cannot express this: it appends attributes to Raw in encoder
	// order, and rewriting the transaction ID in place afterwards desynchronises
	// the header length field from the body. STUN is simple enough to lay out
	// by hand: 20-byte header (type, length, cookie, transaction ID) followed by
	// attributes. Here the transaction ID sits at offset 8 and the single
	// XOR-MAPPED-ADDRESS attribute follows.
	mapped := &stun.XORMappedAddress{IP: net.ParseIP("198.51.100.7"), Port: 41234}
	holder := stun.MustBuild(stun.TransactionID, stun.BindingSuccess)
	holder.WriteHeader()
	if err := mapped.AddTo(holder); err != nil {
		t.Fatalf("add XOR-MAPPED-ADDRESS: %v", err)
	}
	body := holder.Raw[20:]
	body = append(body, 0x00, 0x00, 0x00, 0x00) // pad to a 4-byte boundary
	resp := make([]byte, 0, 20+len(body))
	resp = append(resp, 0x01, 0x01) // Binding Success
	resp = append(resp, byte(len(body)>>8), byte(len(body)))
	resp = append(resp, 0x21, 0x12, 0xa4, 0x42) // magic cookie
	resp = append(resp, ownTxn[:]...)
	resp = append(resp, body...)

	var probeMsg stun.Message
	if err := stun.Decode(resp, &probeMsg); err != nil {
		t.Fatalf("hand-built response does not decode: %v", err)
	}
	if probeMsg.TransactionID != ownTxn {
		t.Fatal("hand-built response does not carry the pending transaction ID")
	}

	if !sc.Feed(resp) {
		t.Error("Feed did not consume the matching STUN response")
	}
}
