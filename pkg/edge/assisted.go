package edge

import (
	"bytes"
	"n2n-go/pkg/log"
	"n2n-go/pkg/p2p"
	"net"
	"strconv"
)

// FRP parity: pkg/nathole/utils.go ListLocalIPsForNatHole.
//
// Two peers in the same LAN never need to go through a NAT at all -- they
// can address each other directly. FRP exploits that by reporting each
// side's own LAN addresses to the relay, which forwards them to the peer as
// NatHoleResp.AssistedAddrs; the sender then tries those *before* the
// STUN-reflexive (public) addresses, because a direct LAN delivery needs no
// NAT mapping on either side and cannot be blocked by hairpin rules.
//
// That field is separate from CandidateAddrs (the STUN result) rather than
// merged into it, and the order matters:
//
//	detectAddrs = m.AssistedAddrs
//	detectAddrs = append(detectAddrs, m.CandidateAddrs...)
//
// Without it, two nodes on the same LAN are forced to hairpin through the
// local router, which many consumer routers do not support, and a node
// behind an extra layer (a VPN, a cloud MASQUERADE) can be unreachausible
// that way even when the LAN route is wide open.
//
// The addresses are not a hint or a fallback: a peer's LAN address is the
// only address on the list that is guaranteed to be reachable when both
// ends are on the same broadcast domain, and it costs one extra sendto.

const MaxAssistedAddrs = 10 // FRP parity: ListLocalIPsForNatHole(10)

// ListLocalIPsForNatHole returns this host's non-loopback, routable IPv4
// addresses, most-specific first, capped at maxCount.
//
// FRP parity: pkg/nathole/utils.go:65-93, which filters out IPv6, loopback
// and link-local addresses and caps the count. The cap matters -- a host with
// many virtual interfaces (docker, k8s CNIs, WireGuard) can easily produce
// dozens of addresses, and every one of them becomes a sendto target the
// peer has to wait for.
func ListLocalIPsForNatHole(maxCount int) []string {
	return ListLocalIPsForNatHoleExcluding(maxCount, "", "", "")
}

// ListLocalIPsForNatHoleExcluding is ListLocalIPsForNatHole with exclusions
// for this host's own tap.
//
// The tap must never be advertised. Reporting it is not merely wasteful: the
// peer that "punches" it addresses an address inside the overlay, so the
// packet is delivered back through the tunnel rather than by a direct path.
// Those bytes then satisfy the "verified by a real data frame" gate, so the
// tunnel would report FullDuplex and log a direct route while every packet
// still crosses the relay -- the exact failure that verification exists to
// catch, and in the field 89% of one node's packets arrived that way.
//
// FRP has no equivalent exclusion because it has no overlay of its own: a
// match on its LAN list really is a different host.
//
// Three identifiers are accepted, and the MAC is the one that actually works:
//
//   - excludeMAC: the tap is the interface carrying our own edge MAC, since
//     n2n assigns it at construction time (client.go, tap.IfMac). It is known
//     before registration, so it is available on the very first call.
//   - excludeIface: the interface name, when the platform's name matches the
//     config. On Windows it does not -- the TAP is an ordinary adapter with a
//     system-assigned name, so InterfaceByName("n2n_tap0") always fails.
//   - tapIP: our virtual IP. Precise, but it is assigned by the supernode in
//     the registration *response*, and this runs while building the
//     registration *request* -- so it is empty on the first call.
//
// Windows is why all three were needed: the TAP adapter persists across runs
// with its old address still configured, so a stale 100.64.0.4 sat in the
// address list on every start, and the name lookup that was meant to filter it
// could never have worked. Matching the MAC filters it without depending on
// either the name or on having registered yet.
func ListLocalIPsForNatHoleExcluding(maxCount int, excludeIface, tapIP, excludeMAC string) []string {
	if maxCount <= 0 {
		maxCount = MaxAssistedAddrs
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		log.Printf("[P2P] cannot enumerate interfaces for assisted addresses: %v", err)
		return nil
	}
	wantMAC, _ := net.ParseMAC(excludeMAC)

	excluded := make(map[string]bool)
	if tapIP != "" {
		excluded[tapIP] = true
	}
	for i := range ifaces {
		ifc := &ifaces[i]
		isTap := (excludeIface != "" && ifc.Name == excludeIface) ||
			(wantMAC != nil && len(ifc.HardwareAddr) > 0 &&
				bytes.Equal(ifc.HardwareAddr, wantMAC))
		if !isTap {
			continue
		}
		addrs, aerr := ifc.Addrs()
		if aerr != nil {
			continue
		}
		for _, a := range addrs {
			switch v := a.(type) {
			case *net.IPNet:
				if v.IP != nil {
					excluded[v.IP.String()] = true
				}
			case *net.IPAddr:
				if v.IP != nil {
					excluded[v.IP.String()] = true
				}
			}
		}
		log.Printf("[P2P] excluding own tap (name=%q mac=%s ip=%q) from assisted addresses (excluded: %v)",
			ifc.Name, ifc.HardwareAddr, tapIP, excluded)
	}

	return CollectAssistedIPs(ifaces, maxCount, excluded, tapAdapterIfIndexes())
}

// InterfaceAddrs reads one interface's configured addresses.
//
// Indirected so the filtering below can be driven from a recorded interface
// table. sortAndTrimLocalIPs was split out for the same reason and the comment
// there applies unchanged: a build host has no leftover TAP, no ZeroTier and
// no Hyper-V switch, so a test against the live table skips straight past the
// case these filters exist for and proves nothing.
var InterfaceAddrs = func(ifc *net.Interface) ([]net.Addr, error) { return ifc.Addrs() }

// CollectAssistedIPs collects the addresses a peer may be told to punch.
//
// excludedIfIndexes carries the same interface identity natclassify.go uses:
// the indexes the OS attributes to a TAP driver. Without it this path filtered
// on FlagUp, our own tap's IP/MAC/name, and the CGNAT address space -- none of
// which sees a third-party virtual adapter that is up and holds an ordinary
// RFC1918 address. Observed 2026-10-03 on log3, which advertised
//
//	["192.168.10.7:53781", "192.168.192.2:53781", "172.20.80.1:53781"]
//
// where 192.168.192.2 belongs to ZeroTier and 172.20.80.1 to the Hyper-V
// default switch. Neither is reachable from a peer: both terminate in a
// tunnel, or in the host itself. The peer ranks the tunnel one above our
// public address and spends its punch budget there.
//
// The filter is per interface, not per address, which is the point: an
// interface whose name or driver says "virtual network" contributes nothing,
// and one whose only evidence is its address space still gets caught by
// AssistedAddrAcceptable below.
func CollectAssistedIPs(ifaces []net.Interface, maxCount int, excluded map[string]bool, excludedIfIndexes map[uint32]bool) []string {
	var ips []net.IP
	for i := range ifaces {
		ifc := &ifaces[i]
		// An interface that is administratively or carrier-down cannot
		// receive anything, so its address is not merely useless to a peer,
		// it is actively misleading: the peer spends a punch budget on it and
		// can never get an answer.
		//
		// This is not hypothetical. A host with a connected Ethernet link and
		// an out-of-range WiFi (associated to nothing) reported the WiFi's
		// address to its peer, and the peer -- matching prefixes against its
		// own interfaces, which included the same down WiFi -- ranked that
		// address first, ahead of one the field log had just shown working.
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		// A TAP or a VPN/tunnel virtual adapter, by driver identity or by
		// name. FlagUp cannot keep them out: the TAP-Windows driver reports
		// its adapter as up as soon as it has been opened, and a tunnel
		// adapter is up for as long as the tunnel is configured. See
		// IsTapInterface for the recorded evidence on both lab hosts.
		if IsTapInterface(ifc, excludedIfIndexes) {
			log.Printf("[P2P] excluding virtual interface %q (index %d) from assisted addresses",
				ifc.Name, ifc.Index)
			continue
		}
		addrs, aerr := InterfaceAddrs(ifc)
		if aerr != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				continue
			}
			if ip == nil {
				continue
			}
			if excluded[ip.String()] {
				continue
			}
			// IPv4 only: the P2P socket is bound to udp4, so an IPv6 address
			// would never receive anything.
			if ip.To4() == nil {
				continue
			}
			// Skip loopback: the peer cannot reach 127.0.0.1, and including it
			// just makes the peer burn a sendto on a guaranteed ICMP failure.
			if ip.IsLoopback() {
				continue
			}
			// Skip link-local (169.254.0.0/16): those are only valid on the
			// local link and are filtered by most routers, so a peer on
			// another subnet will never get an answer.
			if ip.IsLinkLocalUnicast() {
				continue
			}
			// Skip the CGNAT pool (100.64.0.0/10). This is the other source of
			// addresses that are local, up, and not ours -- an overlay tunnel
			// running on this host. NetBird, WireGuard and friends all draw
			// from it, as does n2n itself, so excluding only our own tap (see
			// ListLocalIPsForNatHoleExcluding) still leaks the tunnel's address
			// into the assisted list.
			//
			// Advertising it is actively harmful, and this is the entry point
			// rather than the scoring path: the address reaches the peer inside
			// senderAssisted and the peer tries it first. When both ends run
			// the same overlay the peer ranks that /10 above our public address
			// (see p2p.AffinityScore), so it punches the overlay and the bytes
			// go over the tunnel -- the relay by another name, reporting as a
			// successful direct path. Observed 2026-09-30 with NetBird on both
			// ends: the punch succeeded, P2PRaddr settled on the overlay
			// address, and 66 of the frames arrived from 100.101.102.21.
			if !AssistedAddrAcceptable(ip) {
				continue
			}
			// Deduplicate: several interfaces can report the same address.
			dup := false
			for _, seen := range ips {
				if seen.Equal(ip) {
					dup = true
					break
				}
			}
			if !dup {
				ips = append(ips, ip)
			}
			if len(ips) >= maxCount {
				break
			}
		}
	}

	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

// AssistedEndpoints builds the assisted-address list to advertise to the
// relay, which forwards it to the peer.
//
// Every address is paired with the *same* port -- the local port of the P2P
// socket. That socket is the one STUN discovery runs on (see
// STUNClient.DiscoverWithClassification: requests are written from the P2P
// socket itself, not a separate dialed socket, precisely so the discovered
// mapping matches the socket peers will punch), and it is a single wildcard
// bind, so one local port really is reachable on every local address. This
// is FRP's behaviour too: nathole.go:145-149 joins each local IP with
// laddr.Port.
func (e *EdgeClient) AssistedEndpoints() []string {
	if e.config != nil && e.config.DisableAssistedAddrs {
		return nil
	}
	// The port has to come from the socket that will actually receive the
	// punch, otherwise the peer addresses a port nobody is listening on.
	var port int
	if e.P2PConn != nil && e.P2PConn.LocalAddr() != nil {
		if _, p, err := net.SplitHostPort(e.P2PConn.LocalAddr().String()); err == nil {
			port, _ = strconv.Atoi(p)
		}
	}
	if port == 0 && e.P2PAddr != nil {
		port = e.P2PAddr.Port
	}
	if port == 0 {
		return nil
	}

	// Never advertise our own tap address: the peer punching it would be
	// talking to us through the overlay, not across a direct path.
	//
	// The virtual IP is the authoritative identifier, not the interface name.
	// Interface-name lookup is unreliable on both target platforms, as
	// observed in the field: on Windows the tap is an ordinary adapter with a
	// system-assigned name, so InterfaceByName("n2n_tap0") fails outright
	// ("no such network interface") and the exclusion silently does nothing;
	// on Linux the interface exists but its Addrs() was empty at this point in
	// startup, yielding an empty exclusion set. Both cases leaked the tap
	// address. Matching the address we ourselves were assigned cannot fail
	// that way.
	ips := ListLocalIPsForNatHoleExcluding(MaxAssistedAddrs, e.tapName(), e.tapIP(), e.edgeMAC())
	if len(ips) == 0 {
		return nil
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, net.JoinHostPort(ip, strconv.Itoa(port)))
	}
	return out
}

// tapName returns the configured tap interface name, or "" when unknown.
func (e *EdgeClient) tapName() string {
	if e == nil || e.config == nil {
		return ""
	}
	return e.config.TapName
}

// tapIP returns this host's own n2n virtual IP, which is the address carried
// on the tap. It is the platform-independent identifier for "the tap address",
// as opposed to the interface name, which is config-only on Windows and not
// the name the OS uses.
func (e *EdgeClient) tapIP() string {
	if e == nil || e.Peers == nil || e.Peers.Me == nil {
		return ""
	}
	return e.Peers.Me.Infos.GetVirtualIp()
}

// edgeMAC returns this host's own n2n MAC, which is also the MAC n2n assigns
// to the tap. That makes the MAC the one tap identifier available before
// registration, unlike the interface name (Windows uses a system name) and
// unlike the virtual IP (assigned in the registration response).
func (e *EdgeClient) edgeMAC() string {
	if e == nil || e.MACAddr == nil {
		return ""
	}
	return e.MACAddr.String()
}

// AssistedAddrAcceptable reports whether an address found on a local interface
// may be advertised to a peer as an assisted endpoint.
//
// Split out so the rule is testable directly. CollectAssistedIPs reads the real
// net.Interface.Addrs(), which on a host without a third-party overlay contains
// no address this rejects -- so a test driving it proves nothing. NetBird on the
// host is the only way the real collector sees the case, and the bug it caused
// shipped precisely because CI had no NetBird.
func AssistedAddrAcceptable(ip net.IP) bool {
	return !p2p.IsCGNATOverlayAddr(ip)
}
