package p2p_test

import (
	. "n2n-go/pkg/p2p"
	"net"
	"net/netip"
	"testing"
)

// Reproduces the field log for two hosts behind one carrier NAT, both
// reporting the same public address 111.101.5.1.
//
// The receiver used to punch exactly one address -- the sender's pubSocket --
// five times over. Reaching that address from inside the same CGNAT asks the
// NAT to hairpin to itself, which carrier NATs generally refuse. So the case
// that looks easiest, two peers sharing a public address, was the one
// guaranteed to fail, while the sender, using a full candidate list, reached
// the peer over P2P.
//
// The invariant is that the receiver tries the sender's advertised addresses
// at all, and that none of them is an address which cannot help.
func TestReceiverCandidatesUseSenderAdvertisedAddresses(t *testing.T) {
	instr := &NatHoleInstruction{
		Mode: 0,
		// What the sender advertised, in the order it advertised them.
		SenderAssistedEndpoints: []string{
			"100.76.83.147:45848",
			"172.20.160.1:45848",
			"192.168.1.11:45848",
			"192.168.10.13:45848",
		},
	}
	reg := NewPeerRegistry("myc")
	reg.SetMe(PeerInfo{
		MacAddr:   mustMAC(t, "9e:6e:2d:8c:f5:db"),
		VirtualIp: "100.64.0.3",
		PubSocket: "111.101.5.1:50086",
	})
	if _, err := reg.AddPeer(PeerInfo{
		MacAddr:   mustMAC(t, "52:eb:72:ed:64:1f"),
		VirtualIp: "100.64.0.4",
		PubSocket: "111.101.5.1:45848",
	}, true); err != nil {
		t.Fatalf("registering the sender: %v", err)
	}

	// We are on the carrier NAT's internal side, not on 192.168.10.0/24.
	cands := RankReceiverCandidates(instr, reg,
		mustUDP(t, "111.101.5.1:45848"),
		[]netip.Prefix{netip.MustParsePrefix("100.89.25.0/24")})

	got := AddrStrings(cands)
	t.Logf("ranked: %v", got)

	// Every advertised address must be tried. Punching only the pubSocket is
	// the bug this test exists for.
	for _, want := range []string{
		"111.101.5.1:45848", "100.76.83.147:45848",
		"172.20.160.1:45848", "192.168.1.11:45848", "192.168.10.13:45848",
	} {
		if !containsString(got, want) {
			t.Errorf("sender address %s was never tried; got %v", want, got)
		}
	}
}

// When one of the sender's addresses really is on a subnet we share, it must
// outrank the shared public address: direct routing always beats a path that
// depends on the carrier NAT hairpinning.
func TestReceiverCandidatesRankSameSubnetAheadOfPubSocket(t *testing.T) {
	instr := &NatHoleInstruction{
		Mode:                    0,
		SenderAssistedEndpoints: []string{"172.20.160.1:45848", "192.168.10.6:45848"},
	}
	reg := NewPeerRegistry("myc")
	reg.SetMe(PeerInfo{MacAddr: mustMAC(t, "9e:6e:2d:8c:f5:db"), VirtualIp: "100.64.0.3"})
	if _, err := reg.AddPeer(PeerInfo{
		MacAddr: mustMAC(t, "52:eb:72:ed:64:1f"), VirtualIp: "100.64.0.4",
	}, true); err != nil {
		t.Fatalf("registering the sender: %v", err)
	}

	cands := RankReceiverCandidates(instr, reg,
		mustUDP(t, "111.101.5.1:45848"),
		[]netip.Prefix{netip.MustParsePrefix("192.168.10.0/24")})

	if len(cands) == 0 {
		t.Fatal("no candidates")
	}
	if got := cands[0].String(); got != "192.168.10.6:45848" {
		t.Errorf("candidate 0 = %s, want the same-subnet address 192.168.10.6:45848", got)
	}
	pubIdx := -1
	for i, c := range cands {
		if c.String() == "111.101.5.1:45848" {
			pubIdx = i
		}
	}
	if pubIdx < 0 {
		t.Fatal("shared pubSocket was dropped; it may be the only reachable path")
	}
	if pubIdx == 0 {
		t.Error("shared pubSocket still first: a hairpin-dependent path outranks direct routing")
	}
}

// The sender's overlay address is not a punch target. Our registry already
// knows their virtual IP, and an address inside the overlay comes back
// through the tunnel -- which is what let one node log 16779 packets from a
// peer's tap address while believing it was direct.
func TestReceiverCandidatesDropSenderOverlayAndUnusable(t *testing.T) {
	instr := &NatHoleInstruction{
		Mode: 0,
		SenderAssistedEndpoints: []string{
			"100.64.0.4:45848", // the sender's own overlay address
			"127.0.0.1:45848",  // loopback
			"169.254.10.1:45848",
			"192.168.10.13:45848",
		},
	}
	reg := NewPeerRegistry("myc")
	reg.SetMe(PeerInfo{MacAddr: mustMAC(t, "9e:6e:2d:8c:f5:db"), VirtualIp: "100.64.0.3"})
	// The receiver identifies its sender by the pubSocket it was told to
	// punch, so the registry entry has to carry the same one.
	if _, err := reg.AddPeer(PeerInfo{
		MacAddr: mustMAC(t, "52:eb:72:ed:64:1f"), VirtualIp: "100.64.0.4",
		PubSocket: "111.101.5.1:45848",
	}, true); err != nil {
		t.Fatalf("registering the sender: %v", err)
	}

	cands := RankReceiverCandidates(instr, reg,
		mustUDP(t, "111.101.5.1:45848"), nil)

	for _, c := range cands {
		ip := c.IP
		if ip.Equal(net.ParseIP("100.64.0.4")) {
			t.Errorf("sender overlay address %s must not be punched", c)
		}
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			t.Errorf("unreachable address %s must not be punched", c)
		}
	}
	if len(cands) != 2 {
		t.Errorf("expected pubSocket + the one usable LAN address, got %v", AddrStrings(cands))
	}
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func mustMAC(t *testing.T, m string) net.HardwareAddr {
	t.Helper()
	hw, err := net.ParseMAC(m)
	if err != nil {
		t.Fatalf("bad MAC %q: %v", m, err)
	}
	return hw
}

func mustUDP(t *testing.T, a string) *net.UDPAddr {
	t.Helper()
	ep, err := net.ResolveUDPAddr("udp", a)
	if err != nil {
		t.Fatalf("bad address %q: %v", a, err)
	}
	return ep
}
