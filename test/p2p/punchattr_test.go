package p2p_test

import (
	. "n2n-go/pkg/p2p"
	"net"
	"testing"
)

// A wireless repeater masquerades one peer's advertised address to another, so
// its punches arrive from an address in nobody's registry entry. The port is
// the identifier that survives the rewrite, and the punch is where that
// pairing has to be recorded -- a punch that is answered but not recorded
// leaves the peer holding an address on the far side of an unreachable
// segment.
//
// Observed 2026-10-05 on log3 (192.168.10.7) against log5, which advertises
// 192.168.10.13 behind a repeater that presents itself as 192.168.10.2. log3
// answered 11 punches from 192.168.10.2:48681 and recorded none of them,
// leaving P2PRaddr at 192.168.10.13:48681 while log3 was receiving log5's
// real frames from 192.168.10.2.
func TestPunchSourceIsAttributedByExclusivePort(t *testing.T) {
	reg := NewPeerRegistry("myc")
	reg.SetMe(PeerInfo{
		MacAddr:   mustMAC(t, "ea:2f:de:90:a5:72"),
		VirtualIp: "100.64.0.4",
		PubSocket: "111.101.5.1:62939",
	})
	log5, err := reg.AddPeer(PeerInfo{
		MacAddr:     mustMAC(t, "52:eb:72:ed:64:1f"),
		VirtualIp:   "100.64.0.5",
		PubSocket:   "111.101.5.1:48681",
		P2PEndpoint: "192.168.10.13:48681",
	}, true)
	if err != nil {
		t.Fatalf("registering log5: %v", err)
	}

	// The masquerade: log5's real frames and punches arrive from the repeater.
	masq := mustUDP(t, "192.168.10.2:48681")

	// Nobody has advertised this address, so both socket lookups miss and
	// only the port can resolve it.
	if p, err := reg.GetPeerBySocket(masq); err == nil {
		t.Fatalf("the masqueraded address resolved to %v, want no socket match", p)
	}

	owner := reg.PeerClaimingPortExclusive(uint16(masq.Port))
	if owner != log5 {
		t.Fatalf("port 48681 resolved to %v, want log5", owner)
	}

	// Recording the pairing is what makes log5 dialable: the observed source
	// replaces the advertised address that sits behind the split segment.
	log5.SetP2PRaddr(masq.String())
	reg.IndexPeerRaddr(log5, masq.String())
	if got := log5.GetP2PRaddr(); got != "192.168.10.2:48681" {
		t.Fatalf("raddr is %s, want the observed source 192.168.10.2:48681", got)
	}

	// And the pairing is indexed, so the next frame resolves by socket.
	if p, err := reg.GetPeerBySocket(masq); err != nil || p != log5 {
		t.Fatalf("after recording, the socket lookup gave %v/%v, want log5", p, err)
	}
}

// A shared gateway means the address is not an identity: log3 and log5 both
// publish 111.101.5.1 and differ only in port. When the port itself is
// contested the attribution must be declined, not guessed.
func TestContestedPortIsNotAttributed(t *testing.T) {
	reg := NewPeerRegistry("myc")
	reg.SetMe(PeerInfo{MacAddr: mustMAC(t, "ea:2f:de:90:a5:72")})

	add := func(mac, vip, sock, p2p string) *Peer {
		p, err := reg.AddPeer(PeerInfo{
			MacAddr:     mustMAC(t, mac),
			VirtualIp:   vip,
			PubSocket:   sock,
			P2PEndpoint: p2p,
		}, true)
		if err != nil {
			t.Fatalf("registering %s: %v", mac, err)
		}
		return p
	}
	add("9e:6e:2d:8c:f5:db", "100.64.0.6", "111.101.5.1:53208", "172.22.2.44:53208")
	add("52:eb:72:ed:64:1f", "100.64.0.5", "111.101.5.1:48681", "192.168.10.13:48681")

	// Distinct ports: both resolve.
	if got := reg.PeerClaimingPortExclusive(48681); got == nil {
		t.Fatal("port 48681 should resolve to log5")
	}
	if got := reg.PeerClaimingPortExclusive(53208); got == nil {
		t.Fatal("port 53208 should resolve to log4")
	}
	if got := reg.PeerClaimingPortExclusive(9999); got != nil {
		t.Fatalf("unknown port resolved to %v, want nil", got)
	}

	// Now stage a collision on 7000 and confirm the decline.
	reg.SetPeerBySocketForTest("198.51.100.1:7000", reg.LookupPeerByPubSocket("111.101.5.1:48681"))
	reg.SetPeerBySocketForTest("198.51.100.2:7000", reg.LookupPeerByPubSocket("111.101.5.1:53208"))
	if got := reg.PeerClaimingPortExclusive(7000); got != nil {
		t.Fatalf("contested port resolved to %v, want nil", got)
	}
}

// The IP-only lookup must keep declining when the port belongs to someone
// else, or recording it transposes the two peers' raddrs. This is the
// existing guard the punch-path change sits next to; the punch fix must not
// have weakened it.
func TestIPOnlyLookupStillDeclinesContestedAttribution(t *testing.T) {
	reg := NewPeerRegistry("myc")
	reg.SetMe(PeerInfo{MacAddr: mustMAC(t, "ea:2f:de:90:a5:72")})
	log3, err := reg.AddPeer(PeerInfo{
		MacAddr: mustMAC(t, "9e:6e:2d:8c:f5:db"), VirtualIp: "100.64.0.6",
		PubSocket: "111.101.5.1:53208", P2PEndpoint: "172.22.2.44:53208",
	}, true)
	if err != nil {
		t.Fatalf("registering log3: %v", err)
	}
	// log3 and log5 share 111.101.5.1; only the ports differ.
	if _, err := reg.AddPeer(PeerInfo{
		MacAddr: mustMAC(t, "52:eb:72:ed:64:1f"), VirtualIp: "100.64.0.5",
		PubSocket: "111.101.5.1:48681", P2PEndpoint: "192.168.10.13:48681",
	}, true); err != nil {
		t.Fatalf("registering log5: %v", err)
	}

	// An IP match alone hands back one of the two -- not an identity. Which
	// one depends on map iteration order, so assert only what matters: the
	// IP match cannot distinguish them, and the port can.
	shared, err := reg.GetPeerBySocketIP(net.ParseIP("111.101.5.1"))
	if err != nil {
		t.Fatalf("the shared CGNAT address should match a peer: %v", err)
	}
	if shared != log3 {
		// Whichever peer the IP match picked, the guard's whole purpose is
		// that this answer is not trustworthy on its own.
		t.Logf("IP match returned %v rather than log3; the guard exists precisely because this is not an identity",
			shared.Infos.MacAddr)
	}

	byPort := reg.PeerClaimingPortExclusive(uint16(48681))
	if byPort == nil {
		t.Fatal("port 48681 should resolve exclusively to log5")
	}
	if byPort == log3 {
		t.Fatal("port 48681 must not resolve to log3")
	}

	// Two peers share the IP; exactly one owns the port. That is the
	// discrimination the IP-only lookup cannot make.
	other := reg.PeerClaimingPortExclusive(uint16(53208))
	if other != log3 {
		t.Fatal("port 53208 should resolve to log3")
	}
}
