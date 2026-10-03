package p2p_test

import (
	. "n2n-go/pkg/p2p"
	"net"
	"testing"
)

// A peer behind a router is only reachable at the router's WAN address. The
// assisted set cannot contain it -- neither side ever advertised it -- so the
// only way L1 can resolve it is by indexing the raddr it observed at the
// moment a packet arrived from it.
//
// Without this, the one-way pair looked exactly like a working tunnel: the
// far side promoted to FullDuplex (its peer's real LAN address *was* in the
// assisted set), while the near side received the data frames and silently
// failed GetPeerBySocket on every one of them, so the direct path stayed at
// strat=1 and all traffic kept riding the relay.
func TestIndexPeerRaddrMakesObservedAddressResolvable(t *testing.T) {
	reg := &PeerRegistry{
		Peers: map[string]*Peer{},
	}
	peer := &Peer{
		Infos: PeerInfo{
			MacAddr:         []byte{0x52, 0xeb, 0x72, 0xed, 0x64, 0x1f},
			PubSocket:       "111.101.5.1:52777",
			AssistedSockets: []string{"192.168.10.13:52777"},
		},
		P2PRaddr: "",
	}
	for _, k := range peer.LookupSockets() {
		reg.SetPeerBySocketForTest(k, peer)
	}

	// The router's WAN address: the only one packets actually arrive from.
	observed := &net.UDPAddr{IP: net.ParseIP("172.22.1.17"), Port: 52777}
	if _, err := reg.GetPeerBySocket(observed); err == nil {
		t.Fatal("precondition: the SNAT address should not resolve before it is observed")
	}

	peer.SetP2PRaddr(observed.String())
	reg.IndexPeerRaddr(peer, observed.String())

	got, err := reg.GetPeerBySocket(observed)
	if err != nil {
		t.Fatalf("observed raddr %s does not resolve: %v", observed, err)
	}
	if got != peer {
		t.Fatalf("resolved to the wrong peer")
	}

	// The advertised addresses must survive -- retiring the old raddr must
	// not evict a pubSocket or assisted key that is still legitimate.
	for _, still := range []string{"111.101.5.1:52777", "192.168.10.13:52777"} {
		ua, _ := net.ResolveUDPAddr("udp", still)
		if _, err := reg.GetPeerBySocket(ua); err != nil {
			t.Errorf("advertised address %s stopped resolving: %v", still, err)
		}
	}

	// A rotated raddr (peer restarted, NAT moved) replaces the old key rather
	// than accumulating them.
	rotated := &net.UDPAddr{IP: net.ParseIP("172.22.1.17"), Port: 41000}
	peer.SetP2PRaddr(rotated.String())
	reg.IndexPeerRaddr(peer, rotated.String())
	if _, err := reg.GetPeerBySocket(rotated); err != nil {
		t.Errorf("rotated raddr does not resolve: %v", err)
	}
	if _, err := reg.GetPeerBySocket(observed); err == nil {
		t.Error("stale raddr still resolves after the NAT mapping moved")
	}
}
