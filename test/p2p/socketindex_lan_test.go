package p2p_test

import (
	. "n2n-go/pkg/p2p"
	"net"
	"testing"
)

// A same-LAN pair is the case assistedAddrs exists for: we ask the peer to
// punch at its LAN address, it does, and the packet arrives sourced from that
// LAN address rather than from the STUN-reflexive pubSocket. The registry must
// resolve it, or the punch is dropped as "unknown peer" even though it landed.
func TestGetPeerBySocketMatchesAssistedLANAddress(t *testing.T) {
	reg := NewPeerRegistry("myc")
	infos := PeerInfo{
		MacAddr:     []byte{0x52, 0xeb, 0x72, 0xed, 0x64, 0x1f},
		VirtualIp:   "100.64.0.3",
		PubSocket:   "111.101.5.1:53675",
		P2PEndpoint: "100.76.83.147:53675",
		AssistedSockets: []string{
			"192.168.10.13:53675",
		},
	}
	if _, err := reg.AddPeer(infos, true); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	lan := &net.UDPAddr{IP: net.ParseIP("192.168.10.13"), Port: 53675}
	p, err := reg.GetPeerBySocket(lan)
	if err != nil {
		t.Fatalf("punch from the assisted LAN address was not resolved: %v", err)
	}
	if got := net.HardwareAddr(p.Infos.MacAddr).String(); got != "52:eb:72:ed:64:1f" {
		t.Fatalf("resolved wrong peer: %s", got)
	}
}

// The pubSocket must still resolve, and a second peer's own addresses must not
// be shadowed by the first peer's stale keys.
func TestAssistedIndexDoesNotShadowAndRekeysOnUpdate(t *testing.T) {
	reg := NewPeerRegistry("myc")
	a := PeerInfo{MacAddr: []byte{1, 1, 1, 1, 1, 1}, PubSocket: "10.0.0.1:1",
		AssistedSockets: []string{"192.168.10.13:53675"}}
	b := PeerInfo{MacAddr: []byte{2, 2, 2, 2, 2, 2}, PubSocket: "10.0.0.2:2",
		AssistedSockets: []string{"192.168.10.7:59708"}}
	reg.AddPeer(a, true)
	reg.AddPeer(b, true)

	if p, err := reg.GetPeerBySocket(&net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1}); err != nil ||
		net.HardwareAddr(p.Infos.MacAddr)[0] != 1 {
		t.Fatalf("pubSocket lookup regressed: %v", err)
	}
	if p, err := reg.GetPeerBySocket(&net.UDPAddr{IP: net.ParseIP("192.168.10.7"), Port: 59708}); err != nil ||
		net.HardwareAddr(p.Infos.MacAddr)[0] != 2 {
		t.Fatalf("second peer assisted lookup wrong: %v", err)
	}

	// A goes away (interface down) -- its key must be released, not kept as a
	// stale claim that would shadow a future peer reusing that LAN address.
	reg.RemovePeer("01:01:01:01:01:01")
	if _, err := reg.GetPeerBySocket(&net.UDPAddr{IP: net.ParseIP("192.168.10.13"), Port: 53675}); err == nil {
		t.Fatal("stale assisted key still resolves after RemovePeer")
	}
	if _, err := reg.GetPeerBySocket(&net.UDPAddr{IP: net.ParseIP("192.168.10.7"), Port: 59708}); err != nil {
		t.Fatalf("removing one peer broke the other: %v", err)
	}
}
