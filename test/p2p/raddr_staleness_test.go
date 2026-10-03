package p2p_test

import (
	. "n2n-go/pkg/p2p"
	"net"
	"testing"
	"time"
)

func testPeerInfo(mac, vip, pub string) PeerInfo {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		panic(err)
	}
	return PeerInfo{
		MacAddr:   hw,
		VirtualIp: vip,
		PubSocket: pub,
	}
}

// A peer's MAC survives its process, because it is derived from the machine id.
// So the registry keeps one record per MAC across restarts, and every piece of
// state in that record has to be re-validated against what the peer announces
// now -- including the observed raddr, which describes a socket that a restart
// has closed.
func TestRaddrIsStaleAfterPeerReannouncesANewMapping(t *testing.T) {
	reg := NewPeerRegistry("myc")
	if _, err := reg.AddPeer(testPeerInfo("ea:2f:de:90:a5:72", "100.64.0.4", "111.101.5.1:63654"), true); err != nil {
		t.Fatalf("first AddPeer: %v", err)
	}
	p, err := reg.GetPeer("ea:2f:de:90:a5:72")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}

	// Nothing observed yet: nothing to trust, nothing to be stale about.
	if p.RaddrCoversCurrentMapping() {
		t.Error("a peer we have never heard from has no covering raddr")
	}

	// A packet arrives during that run, so the raddr is good evidence.
	p.SetP2PRaddr("111.101.5.1:63654")
	if !p.RaddrCoversCurrentMapping() {
		t.Error("an raddr observed after the mapping was announced must be trusted")
	}

	// The same process re-announces the identical mapping, as peers do every
	// few seconds. This must NOT expire the raddr: it says nothing about
	// whether the socket is still open.
	for i := 0; i < 3; i++ {
		if _, err := reg.AddPeer(testPeerInfo("ea:2f:de:90:a5:72", "100.64.0.4", "111.101.5.1:63654"), true); err != nil {
			t.Fatalf("re-announce: %v", err)
		}
		p, _ = reg.GetPeer("ea:2f:de:90:a5:72")
		p.SetP2PRaddr("111.101.5.1:63654")
		if !p.RaddrCoversCurrentMapping() {
			t.Fatalf("an unchanged re-announcement expired the raddr (iteration %d)", i)
		}
	}

	// Now the peer comes back on a different port -- a restart, or a NAT that
	// rotated its mapping. The old raddr describes a socket that is gone.
	if _, err := reg.AddPeer(testPeerInfo("ea:2f:de:90:a5:72", "100.64.0.4", "111.101.5.1:53781"), true); err != nil {
		t.Fatalf("re-register: %v", err)
	}
	p, _ = reg.GetPeer("ea:2f:de:90:a5:72")
	if p.RaddrCoversCurrentMapping() {
		t.Error("an raddr older than the peer's new public mapping still claims to cover it")
	}
	if p.GetP2PRaddr() == "" {
		t.Error("the stale raddr must be kept for inbound matching, not erased")
	}

	// A packet on the new socket restores trust.
	p.SetP2PRaddr("111.101.5.1:53781")
	if !p.RaddrCoversCurrentMapping() {
		t.Error("an raddr observed on the current socket must be trusted again")
	}
}

// The port alone must be enough to catch it: the point of dating the raddr is
// that the previous process's port is closed, whether the move was a restart
// or a NAT remap. Both sides of a NAT port change land in the same place.
func TestRaddrStalenessDoesNotDependOnTheAddressFamily(t *testing.T) {
	reg := NewPeerRegistry("myc")
	if _, err := reg.AddPeer(testPeerInfo("9e:6e:2d:8c:f5:db", "100.64.0.5", "111.101.5.1:60735"), true); err != nil {
		t.Fatalf("first AddPeer: %v", err)
	}
	p, _ := reg.GetPeer("9e:6e:2d:8c:f5:db")
	p.SetP2PRaddr("172.22.2.44:60735") // arrived from the router's WAN side
	if !p.RaddrCoversCurrentMapping() {
		t.Fatal("on-link raddr must be trusted while the mapping holds")
	}
	if _, err := reg.AddPeer(testPeerInfo("9e:6e:2d:8c:f5:db", "100.64.0.5", "111.101.5.1:49570"), true); err != nil {
		t.Fatalf("re-register: %v", err)
	}
	p, _ = reg.GetPeer("9e:6e:2d:8c:f5:db")
	if p.RaddrCoversCurrentMapping() {
		t.Error("stale on-link raddr survived a mapping change")
	}
}

// RaddrAt is stamped only on a change, so a peer that keeps sending from one
// address does not appear to have been heard from continuously.
func TestRaddrAtIsStampedOnlyOnChange(t *testing.T) {
	p := &Peer{}
	first := time.Now()
	time.Sleep(2 * time.Millisecond)
	p.SetP2PRaddr("111.101.5.1:53781")
	stamped := p.RaddrAt()
	if stamped.Before(first) {
		t.Errorf("RaddrAt not stamped on first observation: %v", stamped)
	}
	time.Sleep(2 * time.Millisecond)
	p.SetP2PRaddr("111.101.5.1:53781")
	if !p.RaddrAt().Equal(stamped) {
		t.Error("an identical address re-stamped RaddrAt")
	}
}
