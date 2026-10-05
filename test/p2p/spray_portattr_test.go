package p2p_test

import (
	. "n2n-go/pkg/p2p"
	"net/netip"
	"testing"
)

func localPrefixes(pfx ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(pfx))
	for _, p := range pfx {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}

// A masquerading router rewrites the source address to something no peer ever
// advertised. Attribution must survive it on the port, which the SNAT
// preserves, and must decline when two peers claim that same port.
func TestPeerClaimingPortExclusive(t *testing.T) {
	reg := NewPeerRegistry("myc")
	reg.SetMe(PeerInfo{MacAddr: mustMAC(t, "00:00:00:00:00:00")})

	add := func(mac, vip, sock string) *Peer {
		p, err := reg.AddPeer(PeerInfo{
			MacAddr:   mustMAC(t, mac),
			VirtualIp: vip,
			PubSocket: sock,
		}, true)
		if err != nil {
			t.Fatalf("registering %s: %v", mac, err)
		}
		return p
	}
	a := add("aa:bb:cc:00:00:01", "100.0.0.1", "198.51.100.7:58186")
	b := add("aa:bb:cc:00:00:02", "100.0.0.2", "198.51.100.8:49570")

	if got := reg.PeerClaimingPortExclusive(58186); got != a {
		t.Fatalf("port 58186: got %v, want peer a", got)
	}
	if got := reg.PeerClaimingPortExclusive(49570); got != b {
		t.Fatalf("port 49570: got %v, want peer b", got)
	}
	if got := reg.PeerClaimingPortExclusive(65060); got != nil {
		t.Fatalf("unknown port 65060: got %v, want nil", got)
	}

	// Collision: both peers claim 7000. Attribution must decline rather than
	// charge one peer's frames to the other.
	reslot(t, reg, a, "198.51.100.7:7000")
	reslot(t, reg, b, "198.51.100.8:7000")
	if got := reg.PeerClaimingPortExclusive(7000); got != nil {
		t.Fatalf("ambiguous port 7000: got %v, want nil", got)
	}
}

// The receiver must spray at the sender's observed raddr. This is the
// log5/log3 case: the advertised P2PEndpoint sits on a segment a wireless
// repeater has split, and only the observed address is dialable.
func TestRankReceiverCandidatesIncludesObservedRaddr(t *testing.T) {
	reg := NewPeerRegistry("myc")
	reg.SetMe(PeerInfo{
		MacAddr:   mustMAC(t, "52:eb:72:ed:64:1f"),
		VirtualIp: "100.64.0.4",
		PubSocket: "111.101.5.1:45848",
	})
	sender, err := reg.AddPeer(PeerInfo{
		MacAddr:   mustMAC(t, "ea:2f:5f:d5:c2:21"),
		VirtualIp: "100.64.0.2",
		PubSocket: "111.101.5.1:58186",
	}, true)
	if err != nil {
		t.Fatalf("registering the sender: %v", err)
	}

	instr := &NatHoleInstruction{
		Mode: 0,
		SenderAssistedEndpoints: []string{
			"192.168.10.7:58186", // undialable: the repeater split the segment
			"192.168.1.11:58186",
		},
	}
	pubSocket := mustUDP(t, "111.101.5.1:58186")

	// We are on 192.168.10.0/24, so the advertised LAN address ranks first
	// while nothing has been observed yet.
	got := AddrStrings(RankReceiverCandidates(instr, reg, pubSocket,
		localPrefixes("192.168.10.0/24", "100.64.0.0/10")))
	t.Logf("baseline: %v", got)
	if got[0] != "192.168.10.7:58186" {
		t.Fatalf("baseline: got %v, want 192.168.10.7:58186 first", got)
	}

	// Once observed, the measured address leads and the advertised ones are
	// still sprayed -- this widens the round, it does not replace it.
	sender.SetP2PRaddr("192.168.0.1:58186")
	got = AddrStrings(RankReceiverCandidates(instr, reg, pubSocket,
		localPrefixes("192.168.10.0/24", "100.64.0.0/10")))
	t.Logf("with observed raddr: %v", got)
	if got[0] != "192.168.0.1:58186" {
		t.Fatalf("observed not promoted: got %v, want 192.168.0.1:58186 first", got)
	}
	if len(got) < 3 {
		t.Fatalf("spray narrowed: got %v, want the advertised candidates retained", got)
	}
	for _, want := range []string{"192.168.10.7:58186", "111.101.5.1:58186"} {
		if !containsAddr(got, want) {
			t.Fatalf("candidate %s dropped from the spray: %v", want, got)
		}
	}

	// A stale raddr -- one predating the peer's current public mapping -- is a
	// closed socket. It must not return to the front and become the primary.
	// The peer comes back on a new public mapping, so the socket the raddr
	// described is closed and the raddr is now a guess.
	reslot(t, reg, sender, "111.101.5.1:60123")
	got = AddrStrings(RankReceiverCandidates(instr, reg, pubSocket,
		localPrefixes("192.168.10.0/24", "100.64.0.0/10")))
	t.Logf("after pubSocket change: %v", got)
	if got[0] != "192.168.10.7:58186" {
		t.Fatalf("stale raddr promoted: got %v", got)
	}
}

// reslot re-registers p on a new PubSocket, the way the supernode would when
// the peer's public mapping changes.
func reslot(t *testing.T, reg *PeerRegistry, p *Peer, sock string) {
	t.Helper()
	infos := p.Infos
	infos.PubSocket = sock
	if _, err := reg.AddPeer(infos, true); err != nil {
		t.Fatalf("re-registering on %s: %v", sock, err)
	}
}

func containsAddr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
