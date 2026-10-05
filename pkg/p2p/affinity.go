package p2p

import (
	"bytes"
	"net"
	"net/netip"
	"sort"
	"strconv"
)

// FRP parity note: FRP does not reorder m.AssistedAddrs -- it appends them
// verbatim ahead of the public candidates. That is sufficient for it because
// its receiver replies on the observed raddr, but it is not sufficient here.
//
// n2n-go sends one round of packets per candidate and then blocks on
// waitForPunchSuccess, so a multi-homed host that reports a dozen interfaces
// (docker bridges, CNI ranges, NetBird, WireGuard, the n2n tap itself) puts
// the address that actually matters -- the one sharing a broadcast domain
// with us -- at whatever position InterfaceAddrs happened to yield. The
// packet that could have connected the tunnel in one round is then only
// reached after every guaranteed-to-fail address has been tried.
//
// Ranking by "is this address in a subnet I am also on" is the one signal
// that is both cheap and decisive, and it is decided entirely locally: no
// new information has to cross the control plane for it.

// LocalNATPunchPrefixes returns this host's own IPv4 subnets, most specific
// first. The real interface masks are used, so a /8 on some wide virtual
// interface cannot out-rank a genuine /24 LAN.
//
// selfTapName, when non-empty, excludes this host's own n2n tap. Its address
// must not count as shared-subnet evidence: the peer carries an address in
// the very same overlay subnet, so leaving it in makes the peer's tap address
// score as highly as the real LAN and lets the sort pick it first. The
// resulting "connection" would be delivered *through the overlay*, which is
// the relay by another name, while every log line claimed a direct path.
func LocalNATPunchPrefixes(selfTapName, selfTapIP, selfTapMAC string) []netip.Prefix {
	// The overlay prefix to drop, identified by the address we were assigned
	// on the tap. Deriving it from the address rather than from the interface
	// name is deliberate: the name is config-only on Windows (the tap is an
	// ordinary adapter with a system name, so InterfaceByName fails) and can
	// race with the device being brought up on Linux, so both were observed
	// returning nothing. A name mismatch must not silently disable the guard.
	var dropOverlay netip.Prefix
	haveOverlay := false
	if a, err := netip.ParseAddr(selfTapIP); err == nil && a.Is4() {
		dropOverlay = netip.PrefixFrom(a.Unmap(), overlayPrefixBits)
		haveOverlay = true
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	return CollectLocalPrefixes(ifaces, selfTapName, wantMACOf(selfTapMAC), dropOverlay, haveOverlay)
}

func wantMACOf(s string) net.HardwareAddr {
	if s == "" {
		return nil
	}
	hw, _ := net.ParseMAC(s)
	return hw
}

func CollectLocalPrefixes(ifaces []net.Interface, selfTapName string, wantMAC net.HardwareAddr, dropOverlay netip.Prefix, haveOverlay bool) []netip.Prefix {
	var out []netip.Prefix
	seen := make(map[netip.Prefix]bool)
	for i := range ifaces {
		ifc := &ifaces[i]
		// Identify our tap by MAC as well as by name. n2n assigns the edge
		// MAC to the tap at construction, so this works on Windows (where the
		// adapter has a system-assigned name and InterfaceByName fails) and
		// before registration has told us the virtual IP.
		// Skip interfaces that are down. A down interface cannot carry
		// traffic, and counting its subnet here is worse than ignoring it:
		// it hands a same-subnet bonus to the peer's address on that same
		// dead interface, promoting an unreachable candidate above one
		// that actually works. The field logs showed exactly that -- a
		// disconnected WiFi's address promoted to candidate 0 while a peer
		// address on a live link, provably reachable by ping, was pushed
		// behind it.
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		isTap := (selfTapName != "" && ifc.Name == selfTapName) ||
			(wantMAC != nil && len(ifc.HardwareAddr) > 0 &&
				bytes.Equal(ifc.HardwareAddr, wantMAC))
		if isTap {
			continue
		}
		addrs, aerr := ifc.Addrs()
		if aerr != nil {
			continue
		}
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok || n == nil {
				continue
			}
			ip, ok := netip.AddrFromSlice(n.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			// Drop our own tap's subnet: the peer carries an address in the
			// very same range, so leaving it in would let the peer's tap
			// address score as highly as the real LAN and win the sort.
			if haveOverlay && dropOverlay.Contains(ip) {
				continue
			}
			// Drop any other overlay tunnel's subnet for the same reason, more
			// broadly. NetBird, WireGuard and friends also draw from the CGNAT
			// pool, and a peer behind the same one hands us an address that
			// scores as a perfect same-subnet match while being unreachable
			// from the internet. Promoting it puts a punch target that can only
			// work if that overlay is up -- and even then the traffic is
			// delivered by the overlay, not by a hole we punched. The public
			// candidate is the one that satisfies "public works, use public".
			if IsCGNATOverlay(ip) {
				continue
			}
			ones, bits := n.Mask.Size()
			// A non-canonical mask reports bits==0; skip rather than guess.
			if !ip.Is4() || bits != 32 || ones <= 0 {
				continue
			}
			// Loopback and link-local are useless as affinity evidence:
			// nothing outside this host lives there.
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			p := netip.PrefixFrom(ip, ones)
			if seen[p] {
				continue
			}
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bits() > out[j].Bits() })
	return out
}

// AffinityScore is the length in bits of the longest of our subnets that
// contains addr, or 0 when addr is on no subnet we are on. Longer wins, so
// 192.168.10.7 beats 172.20.160.1 on a host that happens to own both a real
// /24 LAN and a docker /16.
func AffinityScore(addr netip.Addr, local []netip.Prefix) int {
	if !addr.IsValid() {
		return 0
	}
	addr = addr.Unmap()
	// An address in the CGNAT pool is never a shared-LAN signal, whatever
	// prefixes we were handed. NetBird, WireGuard and n2n itself all draw
	// from 100.64.0.0/10, so two hosts behind the same overlay look like
	// neighbours on a /10 -- far more specific than any public candidate --
	// and the sort would then punch the overlay instead of the internet.
	// Scoring it 0 here as well as dropping it in CollectLocalPrefixes keeps
	// the rule true for every caller, including the tests and any future one
	// that assembles `local` some other way.
	if IsCGNATOverlay(addr) {
		return 0
	}
	best := 0
	for _, p := range local {
		if p.Addr().Is4() != addr.Is4() {
			continue
		}
		if p.Contains(addr) && p.Bits() > best {
			best = p.Bits()
		}
	}
	return best
}

// SortAssistedByLocalAffinity orders the peer's reported LAN addresses so
// that those sharing a subnet with this host come first, leaving the rest in
// the order the peer reported them (a stable sort, so a multi-homed peer
// still keeps its own preference among equally-good candidates).
//
// Only the order changes. No address is added or dropped: an unresolvable or
// unrankable entry keeps its place rather than disappearing, because silently
// discarding a peer's claim is how a working candidate goes missing.
func SortAssistedByLocalAffinity(assisted []string, local []netip.Prefix) []string {
	if len(assisted) < 2 || len(local) == 0 {
		return assisted
	}
	scores := make([]int, len(assisted))
	reordered := false
	for i, raw := range assisted {
		host := raw
		if h, _, err := net.SplitHostPort(raw); err == nil {
			host = h
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			addr = netip.Addr{} // invalid -> score 0
		}
		scores[i] = AffinityScore(addr, local)
		if i > 0 && scores[i] > scores[i-1] {
			reordered = true
		}
	}
	if !reordered {
		return assisted
	}
	idx := make([]int, len(assisted))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(i, j int) bool { return scores[idx[i]] > scores[idx[j]] })
	out := make([]string, len(assisted))
	for i, j := range idx {
		out[i] = assisted[j]
	}
	return out
}

// SameOrder reports whether two candidate lists are element-wise identical.
func SameOrder(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// overlayPrefixBits is the width of the n2n overlay network, matching the
// allocator's 100.64.0.0/10 default (supernode.NetworkAllocator).
const overlayPrefixBits = 10

// cgnatPrefix is RFC6598 carrier-grade NAT space, 100.64.0.0/10.
//
// It is also the pool that overlay networks draw from by default -- n2n itself
// (see overlayPrefixBits above) and NetBird among them. A host running one of
// those tunnels therefore owns an address here that a remote peer cannot reach
// over the public internet, yet which looks perfectly "same-subnet" to the
// affinity sort: the /10 the overlay assigns is far more specific than the
// single-address prefix of a genuine public candidate, so AffinityScore rates
// it higher and promotes it to the front of the punch candidate list.
//
// The result is a hole punch that appears to succeed while actually being
// delivered over the overlay -- the relay by another name -- and, because the
// observed raddr then alternates between the overlay and the real public
// address as packets arrive on either path, the peer's P2PRaddr flaps between
// two values. Observed on 2026-09-30 with NetBird on both ends.
var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// IsCGNATOverlay reports whether addr belongs to the shared CGNAT pool that
// overlay tunnels are carved from, i.e. an address that is not reachable from
// the public internet and must not be treated as evidence of a shared LAN.
func IsCGNATOverlay(addr netip.Addr) bool {
	return addr.Is4() && cgnatPrefix.Contains(addr)
}

// IsCGNATOverlayAddr is the net.IP form of IsCGNATOverlay, for callers holding a
// net.IP straight out of net.Interface.Addrs -- the assisted-address collector
// in pkg/edge, which is the entry point that actually put a NetBird address
// into senderAssisted on 2026-09-30. Keeping the single definition of "overlay
// space" here is what stops a third copy of the CGNAT test from drifting the way
// the ones in pkg/edge/natclassify.go and pkg/natclient/client.go already have.
func IsCGNATOverlayAddr(ip net.IP) bool {
	if ip == nil {
		return false
	}
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	return IsCGNATOverlay(netip.AddrFrom4([4]byte(v4)))
}

// raddrPunchableByReceiver reports whether a receiver may make this observed
// source address its primary punch target.
//
// A private address is acceptable only when it sits on a subnet configured on
// one of our own interfaces: that is a genuinely on-link peer, no NAT is
// involved, and it is the best possible target. An off-link private address
// is the peer's router WAN side, which the receiver can reach but cannot
// offer a matching return path for.
//
// This mirrors edge.onLocalLink / edge.ClassifyPunchTarget rather than
// importing them: pkg/edge imports pkg/p2p, so the dependency only runs this
// way. Keep the rule in sync with ResolvePunchTarget's receiver branch.
func raddrPunchableByReceiver(endpoint string) bool {
	host := endpointHostOf(endpoint)
	if host == "" {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if !ip.IsPrivate() {
		// Public, or not ours to judge -- the caller's freshness gate owns it.
		return true
	}
	if ip.IsLoopback() || !ip.IsGlobalUnicast() {
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

// endpointHostOf extracts the host portion of a "host:port" endpoint.
func endpointHostOf(endpoint string) string {
	if h, _, err := net.SplitHostPort(endpoint); err == nil {
		return h
	}
	return endpoint
}

// PeerClaimingPortExclusive returns the peer that owns port, or nil when no
// peer owns it or more than one does.
//
// PeerClaimingPort answers with the first match, which is the wrong shape for
// attribution: if two peers happen to publish the same P2P port, picking one
// silently charges a peer's frames to the other. Returning nil on ambiguity
// costs a single frame of raddr bookkeeping and keeps the mapping honest.
func (reg *PeerRegistry) PeerClaimingPortExclusive(port uint16) *Peer {
	if reg == nil || port == 0 {
		return nil
	}
	reg.peerMu.RLock()
	defer reg.peerMu.RUnlock()

	var found *Peer
	for key, owner := range reg.peerBySocket {
		if owner == nil {
			continue
		}
		_, ps, err := net.SplitHostPort(key)
		if err != nil {
			continue
		}
		pn, err := strconv.Atoi(ps)
		if err != nil || uint16(pn) != port {
			continue
		}
		if found != nil && found != owner {
			return nil // ambiguous: two peers claim this port
		}
		found = owner
	}
	return found
}

// localIPSet returns this host's own IPv4 addresses, as strings, for use as a
// "never this one" filter.
//
// It is built from the same enumeration as LocalNATPunchPrefixes, so it
// inherits that function's exclusions: the n2n tap itself, overlay addresses,
// and the addresses this package already classifies as unacceptable for a
// punch candidate. Reusing it rather than enumerating separately keeps the
// two in step -- a filter that disagreed with the candidate rules would
// either let one of our own addresses through or hide a peer that merely
// resembles us.
//
// Loopback is deliberately absent. Punching ourselves over loopback would
// "succeed" instantly and then verify nothing, which is the failure the
// verified-data-frame gate exists to catch.
func localIPSet(reg *PeerRegistry) map[string]struct{} {
	out := make(map[string]struct{})
	if reg == nil {
		return out
	}
	prefixes := LocalNATPunchPrefixes(reg.SelfTapName, reg.SelfTapIP(), reg.SelfMAC())
	if len(prefixes) == 0 {
		return out
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	overlay := netip.Prefix{}
	if a, err := netip.ParseAddr(reg.SelfTapIP()); err == nil && a.Is4() {
		overlay = netip.PrefixFrom(a.Unmap(), overlayPrefixBits)
	}
	tapMAC := wantMACOf(reg.SelfMAC())
	for _, ifc := range ifaces {
		if tapMAC != nil && ifc.Flags&net.FlagUp == 0 {			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipnet.IP.To4())
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if overlay.IsValid() && overlay.Contains(ip) {
				continue
			}
			if !AddrInLocalPrefix(net.IP(ip.AsSlice()), prefixes) {
				continue
			}
			out[ip.String()] = struct{}{}
		}
	}
	return out
}
