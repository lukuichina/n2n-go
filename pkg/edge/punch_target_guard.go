package edge

import (
	"fmt"
	"net"
	"strings"

	"n2n-go/pkg/p2p"
)

// Punch-target validation.
//
// The relay assembles the NatHoleInstruction's endpoint fields from whatever
// the target peer most recently reported -- including its *private* interface
// addresses, which the assisted-candidate logic is explicitly meant to offer
// for same-subnet shortcutting. Those addresses are unreachable across the
// public internet, so a sender that trusts the field verbatim punches a black
// hole.
//
// Observed 2026-10-02T22:38:07Z on E1 (2.58.196.38, container eth0
// 10.137.189.93), punching the receiver and finding its OWN private address
// in the instruction:
//
//	NatHoleInstruction: sender using relay-supplied target
//	                   10.137.189.93:37151 (pubSocket 2.58.196.38:37151)
//
// E1 therefore never emitted a single packet toward the peer, which matters
// well beyond the wasted punch: the cloud provider's stateful ingress filter
// only admits return traffic for flows this host originated, so the receiver's
// punches were then dropped as unsolicited. Two independent symptoms, one
// cause -- and the STUN mapping in the same line (2.58.196.38:37151) was the
// address that should have been punched all along.
//
// A private address is not automatically wrong, though: for a genuinely
// on-link peer it is the best possible target, and the 192.168.10.x pairs
// depend on exactly that. So the discriminator is reachability, not
// addressing -- a private candidate is kept only when it shares a subnet with
// one of our own interfaces.

// punchTargetKind classifies a candidate address, returning 0 for "unusable".
// Higher is better.
const (
	PunchTargetUnusable = iota
	PunchTargetPublic
	PunchTargetOnLink
	punchTargetObserved
)

func ClassifyPunchTarget(endpoint string) int {
	host := endpointHost(endpoint)
	if host == "" {
		return PunchTargetUnusable
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// A hostname, or something we cannot parse at all. The punch path
		// only ever deals with literal addresses; refuse rather than guess.
		return PunchTargetUnusable
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() ||
		ip.IsInterfaceLocalMulticast() || !ip.IsGlobalUnicast() {
		return PunchTargetUnusable
	}
	// Punching our own address would come straight back down the same socket,
	// be discarded by IsLocalInterfaceIP as a self-reflection, and burn the
	// whole retry budget against ourselves.
	if IsLocalInterfaceIP(ip) {
		return PunchTargetUnusable
	}
	// 100.64.0.0/10 is the n2n overlay itself, never a punch target.
	if p2p.IsCGNATOverlayAddr(ip) {
		return PunchTargetUnusable
	}
	if ip.IsPrivate() {
		if onLocalLink(ip) {
			return PunchTargetOnLink
		}
		// RFC1918 but off our subnets: unreachable from here -- unless we
		// have actually seen it (classified by the caller as observed).
		return PunchTargetUnusable
	}
	return PunchTargetPublic
}

// onLocalLink reports whether ip falls inside a subnet configured on one of
// this host's own non-loopback IPv4 interfaces.
func onLocalLink(ip net.IP) bool {
	if ip.To4() == nil {
		return false
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP == nil {
			continue
		}
		v4 := ipnet.IP.To4()
		if v4 == nil || v4.IsLoopback() {
			continue
		}
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

// endpointHost extracts the host portion of a "host:port" endpoint without
// requiring the port to be present, so a bare address is handled too.
func endpointHost(endpoint string) string {
	ep := strings.TrimSpace(endpoint)
	if ep == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(ep); err == nil {
		return host
	}
	return ep
}

// ResolvePunchTarget picks the address to punch for peerMAC.
//
// Candidates are ranked, not merely filtered, and the ranking reflects how
// much we actually trust each source:
//
//   - observed raddr: the source address a packet from this peer genuinely
//     arrived from. Nothing can beat that, because it is the one address
//     already proven to reach us. It is also the only entry that can hold the
//     router's own WAN address, which appears in neither pubSocket nor the
//     assisted set -- under SNAT the two sides advertise an address the
//     other's packets never actually come from, so punching the advertised
//     one leaves our NAT tracking a flow that the peer's return traffic
//     cannot match. Observed 2026-10-03 on log3, whose peer 9e:6e advertised
//     111.101.5.1:60735 and 10.0.10.40:60735 while its frames consistently
//     arrived from 172.22.2.44:60735.
//   - on-link private: same-subnet peers, where no NAT is involved at all.
//   - public: the STUN mapping, the only universally advertised address and
//     therefore the safe last resort.
//
// Within a rank the registry beats the relay-supplied value, because the
// registry is assembled from what the peer actually reported and updated as
// it reports, while the relay field lags and may carry a stale or private
// address.
//
// raddrFresh is the peer's RaddrCoversCurrentMapping: whether the observed
// source address still describes the socket the peer is using now. When it is
// false the raddr is dropped rather than demoted. Demoting is not enough --
// an on-link raddr would still outrank the fresh pubSocket, which is exactly
// the case that fails when a peer's address changes while staying on-link.
//
// Returns the chosen address and a note describing the decision, for the
// instruction log line. An empty address means no candidate was usable.
func ResolvePunchTarget(registryRaddr, registryPubSocket, registryEndpoint, relayEndpoint, peerMAC string, raddrFresh bool, isReceiver bool) (string, string) {
	type cand struct {
		addr   string
		source string
		rank   int
	}
	var cands []cand
	add := func(addr, source string) {
		if addr == "" {
			return
		}
		rank := ClassifyPunchTarget(addr)
		// An observed address is trusted even when it is off-link or
		// private: we received a packet from it, which is stronger evidence
		// than any classification rule can produce.
		//
		// The receiver is the exception, and the exception is the whole point
		// of the role. A punch is only useful if the peer can punch back to
		// where it landed, and reciprocity is not symmetric between the two
		// roles:
		//
		//   - Sender punching an off-link private raddr is fine. The peer's
		//     router SNATs it, and the receiver is concurrently punching the
		//     sender's public mapping, so the hole gets opened from the side
		//     that matters.
		//   - Receiver punching an off-link private raddr opens the hole at
		//     its own router's WAN address (192.168.10.7 -> 192.168.10.1,
		//     WAN 172.22.2.17 -> 172.22.2.44). The peer's return packets
		//     arrive at 172.22.2.17 and are only forwarded to 192.168.10.7
		//     if that router happens to hold a matching port-forward, which
		//     is the exception rather than the rule. Under CGNAT the peer's
		//     own public mapping is the only address where the return path
		//     is guaranteed to be walked.
		//
		// So for the receiver an off-link private observed raddr keeps its
		// classified rank (Unusable) instead of being promoted, and the
		// public mapping wins. Observed on log3 against log4: the receiver
		// locked onto 172.22.2.44:58813 for 188 punches across 28 minutes
		// and the two never reached FullDuplex, while the public
		// 111.101.5.1:58813 resolved correctly on the very first attempt.
		// An on-link private raddr is still promoted -- no NAT is involved,
		// and the 192.168.10.x pairs depend on exactly that.
		if source == "observed raddr" && !isSelfOrReservedHost(endpointHost(addr)) &&
			(!isReceiver || rank >= PunchTargetOnLink) {
			rank = punchTargetObserved
		}
		cands = append(cands, cand{addr, source, rank})
	}
	var staleRaddr string
	if registryRaddr != "" && !raddrFresh {
		// Keep it out of the ranking, but say so in the note: a punch round
		// against a closed port should be visible in the log as a decision,
		// not as an unexplained timeout.
		staleRaddr = registryRaddr
	} else {
		add(registryRaddr, "observed raddr")
	}
	add(registryPubSocket, "registry pubSocket")
	add(registryEndpoint, "registry P2PEndpoint")
	add(relayEndpoint, "relay-supplied endpoint")

	best := -1
	var rejected []string
	for i, c := range cands {
		if c.rank == PunchTargetUnusable {
			rejected = append(rejected, fmt.Sprintf("%s=%s unusable", c.source, c.addr))
			continue
		}
		if best < 0 || c.rank > cands[best].rank {
			best = i
		}
	}

	if best < 0 {
		if staleRaddr != "" {
			return "", fmt.Sprintf("no usable endpoint for %s: observed raddr=%s is stale "+
				"(the peer re-announced a different public mapping, so that address belongs to a "+
				"closed socket)", peerMAC, staleRaddr)
		}
		if len(rejected) == 0 {
			return "", fmt.Sprintf("no candidate endpoint for %s", peerMAC)
		}
		return "", fmt.Sprintf("no usable endpoint for %s: %s",
			peerMAC, strings.Join(rejected, ", "))
	}

	kind := "public"
	switch cands[best].rank {
	case PunchTargetOnLink:
		kind = "on-link"
	case punchTargetObserved:
		kind = "observed-source"
	}
	note := fmt.Sprintf("%s for %s (%s)", cands[best].source, peerMAC, kind)
	if staleRaddr != "" {
		note += fmt.Sprintf("; dropped stale observed raddr=%s", staleRaddr)
	}
	if len(rejected) > 0 {
		note += fmt.Sprintf("; rejected %s", strings.Join(rejected, ", "))
	}
	return cands[best].addr, note
}

// isSelfOrReservedHost reports whether a host is one we must never punch
// regardless of having observed it: ourselves, the overlay, or a broadcast /
// unspecified form.
func isSelfOrReservedHost(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() {
		return true
	}
	return p2p.IsCGNATOverlayAddr(ip) || IsLocalInterfaceIP(ip)
}
