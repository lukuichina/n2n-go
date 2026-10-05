package edge_test

import (
	. "n2n-go/pkg/edge"
	"strings"
	"testing"
)

// Topology under test, exactly as observed 2026-10-04 on log3/log4/log5:
//
//	192.168.10.7  ->  192.168.10.1 (WAN 172.22.2.17)  ->  172.22.2.44
//
// log3 (192.168.10.7) and log4 (172.22.2.44) sit behind the same carrier
// NAT, 111.101.5.1. log4's frames reach log3 from 172.22.2.44 -- its
// router's WAN address, one SNAT hop, port preserved -- which is neither
// address log4 advertises (111.101.5.1:58813 public, 10.x its LAN).
//
// Punching 172.22.2.44:58813 works from the SENDER role and fails from the
// RECEIVER role, and the asymmetry is structural rather than incidental:
//
//   - As sender, log3's packet is SNAT'd to 172.22.2.17 and log4 punches
//     back to 172.22.2.17, which is on log4's own link. Works.
//
//   - As receiver, the hole log3 opens is at 172.22.2.17 -- log3's router's
//     WAN. For log4's return packets to reach 192.168.10.7 that router needs
//     a matching port-forward, which is the exception rather than the rule.
//     Punching log4's advertised public mapping instead routes the return
//     path through the carrier NAT, which is the only place reciprocity is
//     guaranteed.
//
// Observed impact: as receiver, log3 named 172.22.2.44:58813 the punch
// target for 188 rounds across 28 minutes while 111.101.5.1:58813 sat
// unused, and the pair never reached FullDuplex.

// The receiver must not select a private observed raddr that is off-link.
// This is the regression the user spotted: the receiver branch had been
// unified with the sender's ("resolve it exactly as the sender branch
// does"), which promoted the observed raddr above the public mapping in
// both roles.
func TestReceiverRejectsOffLinkPrivateObservedRaddr(t *testing.T) {
	const (
		observed = "172.22.2.44:58813" // log4's router WAN, what frames arrive from
		publicST = "111.101.5.1:58813" // log4's STUN mapping, what it advertises
		lanAddr  = "10.0.10.40:58813"  // log4's own LAN
		peerMAC  = "9e:6e:2d:8c:f5:db"
	)

	got, note := ResolvePunchTarget(observed, publicST, lanAddr, "", peerMAC, true, true)
	if got == observed {
		t.Fatalf("receiver chose the off-link private observed raddr %s; the return "+
			"path needs a port-forward on our router that we cannot count on (note: %s)", got, note)
	}
	if got != publicST {
		t.Fatalf("receiver chose %s, want the public mapping %s (note: %s)", got, publicST, note)
	}
	if !strings.Contains(note, "unusable") && !strings.Contains(note, "public") {
		t.Errorf("note should record why the observed raddr lost: %s", note)
	}
}

// The sender keeps the observed raddr. Punching the peer's router WAN side
// is fine from here: the peer is concurrently punching our public mapping,
// so the hole gets opened from the side that matters.
func TestSenderStillPrefersOffLinkPrivateObservedRaddr(t *testing.T) {
	const observed = "172.22.2.44:58813"
	got, note := ResolvePunchTarget(observed, "111.101.5.1:58813", "10.0.10.40:58813", "", "9e:6e:2d:8c:f5:db", true, false)
	if got != observed {
		t.Fatalf("sender chose %s, want the observed source %s (note: %s)", got, observed, note)
	}
	if !strings.Contains(note, "observed-source") {
		t.Errorf("note %q should mark the choice as observed-source", note)
	}
}

// An on-link private peer involves no NAT at all, so the receiver keeps it
// in both roles. This guards the new receiver restriction from being wider
// than intended -- the 192.168.10.x pairs depend on exactly this.
func TestReceiverStillPrefersOnLinkPrivateObservedRaddr(t *testing.T) {
	onLink := localSubnetPeerForTest(t)
	if onLink == "" {
		t.Skip("no usable on-link peer address to construct")
	}
	got, note := ResolvePunchTarget(onLink, "111.101.5.1:58813", "", "", "52:eb:72:ed:64:1f", true, true)
	if got != onLink {
		t.Fatalf("receiver chose %s, want the on-link %s (note: %s)", got, onLink, note)
	}
}

// A receiver with nothing but an off-link private observation has no usable
// target. Returning empty is correct: punching 172.22.2.44 would spend the
// whole retry budget on an address whose return path we cannot offer, and
// the timeout would read like a network fault rather than a rejected
// candidate.
func TestReceiverWithOnlyOffLinkPrivateObservationPicksNothing(t *testing.T) {
	got, note := ResolvePunchTarget("172.22.2.44:58813", "", "", "", "9e:6e:2d:8c:f5:db", true, true)
	if got != "" {
		t.Fatalf("chose %s, want no target (note: %s)", got, note)
	}
	if !strings.Contains(note, "unusable") {
		t.Errorf("note should name the private address as unusable: %s", note)
	}
}

// A public observed raddr is unaffected by the receiver restriction: it is
// already the address the return path would use.
func TestReceiverKeepsPublicObservedRaddr(t *testing.T) {
	const observed = "111.101.5.1:58813"
	got, note := ResolvePunchTarget(observed, "111.101.5.1:58813", "", "", "9e:6e:2d:8c:f5:db", true, true)
	if got != observed {
		t.Fatalf("chose %s, want %s (note: %s)", got, observed, note)
	}
}
