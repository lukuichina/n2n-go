package p2p_test

import (
	. "n2n-go/pkg/p2p"
	"net"
	"testing"
	"time"
)

// ExecuteNatHolePunch overrides whatever target resolution chose with the
// peer's observed raddr, so the staleness gate has to live here too and not
// only in ResolvePunchTarget. This is the block that actually decided the
// round on 2026-10-03.
//
// Observed: log4 restarted on 111.101.5.1:49570 / 172.22.2.44:49570 at
// 14:38:01 while log3 still held 172.22.2.44:60735 from the previous process.
// Every round from 14:38 to 14:48 logged
//
//	[P2P] Receiver: using observed raddr 172.22.2.44:60735 as punch target
//	                   for 9e:6e:2d:8c:f5:db (ahead of self-reported addresses)
//
// and punched the closed port as candidate 0. The pair only came up at 14:48,
// ten minutes and one ladder's worth of retries later, when the live port
// happened to be reached as candidate 1 and refreshed the raddr.
//
// MAC is derived from the machine id, so it survives a restart and the
// registry keeps exactly one record per host across process lifetimes. The
// raddr in that record has to be re-validated against what the peer
// advertises now, or it outlives the socket it describes.
func punchTargetForTest(t *testing.T, reg *PeerRegistry, peerMAC string) (string, bool) {
	t.Helper()
	p, err := reg.GetPeer(peerMAC)
	if err != nil {
		t.Fatalf("GetPeer(%s): %v", peerMAC, err)
	}
	raddr := p.GetP2PRaddr()
	if raddr == "" || reg.IsOwnEndpoint(raddr) {
		return "", false
	}
	return raddr, p.RaddrCoversCurrentMapping()
}

func TestObservedRaddrIsAdmittedOnlyWhileItCoversTheCurrentMapping(t *testing.T) {
	reg := NewPeerRegistry("myc")
	mac := "9e:6e:2d:8c:f5:db"
	hw, err := net.ParseMAC(mac)
	if err != nil {
		t.Fatal(err)
	}

	// Previous process: :60735 on both the public mapping and the LAN address.
	if _, err := reg.AddPeer(PeerInfo{MacAddr: hw, VirtualIp: "100.64.0.5",
		PubSocket: "111.101.5.1:60735", P2PEndpoint: "172.22.2.44:60735"}, true); err != nil {
		t.Fatal(err)
	}
	p, _ := reg.GetPeer(mac)
	p.SetP2PRaddr("172.22.2.44:60735")

	if _, admitted := punchTargetForTest(t, reg, mac); !admitted {
		t.Fatal("an raddr observed against the announced mapping must be admitted")
	}

	// The peer restarts and announces a new mapping.
	if _, err := reg.AddPeer(PeerInfo{MacAddr: hw, VirtualIp: "100.64.0.5",
		PubSocket: "111.101.5.1:49570", P2PEndpoint: "172.22.2.44:49570"}, true); err != nil {
		t.Fatal(err)
	}
	if got, admitted := punchTargetForTest(t, reg, mac); admitted {
		t.Fatalf("stale raddr %s was admitted as a punch target after the peer announced a new mapping", got)
	}

	// A packet on the new socket restores it -- and only then.
	p, _ = reg.GetPeer(mac)
	p.SetP2PRaddr("172.22.2.44:49570")
	if got, admitted := punchTargetForTest(t, reg, mac); !admitted || got != "172.22.2.44:49570" {
		t.Fatalf("raddr on the current socket not admitted (admitted=%v target=%s)", admitted, got)
	}
}

// The whole reason the observed raddr outranks everything is SNAT: the peer's
// frames arrive from its router's WAN address, which is in neither pubSocket
// nor the assisted set. A NAT that preserves ports keeps the address stable,
// so this stays admitted for the life of the mapping rather than expiring.
func TestObservedRaddrSurvivesRepeatedUnchangedAnnouncements(t *testing.T) {
	reg := NewPeerRegistry("myc")
	mac := "aa:bc:3a:74:37:b1"
	hw, _ := net.ParseMAC(mac)
	infos := PeerInfo{MacAddr: hw, VirtualIp: "100.64.0.2",
		PubSocket: "111.101.5.1:49571", P2PEndpoint: "172.22.1.17:49571"}
	if _, err := reg.AddPeer(infos, true); err != nil {
		t.Fatal(err)
	}
	p, _ := reg.GetPeer(mac)
	p.SetP2PRaddr("172.22.1.17:49571")

	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, err := reg.AddPeer(infos, true); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, admitted := punchTargetForTest(t, reg, mac); !admitted {
		t.Error("unchanged re-announcements expired the observed raddr")
	}
}
