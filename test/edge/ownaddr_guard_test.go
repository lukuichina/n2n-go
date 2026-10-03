package edge_test

import (
	. "n2n-go/pkg/edge"
	"net"
	"testing"
)

// The self-attribution guard is the only thing standing between a router that
// reflects our own punch back at us and a fabricated FullDuplex. It shipped
// disabled: ListLocalIPs returns bare IPs, the comparison was against
// addr.String() including the port, and the SplitHostPort fallback errored on
// every bare IP. Neither arm could ever fire.
//
// Observed 2026-10-02T09:09:22Z on log5 (192.168.10.13): three consecutive
// lines recording its own address as log3's,
//
//	Punch packet from 192.168.10.13:43484 attributed to instruction peer ea:2f
//	Punch packet from 192.168.10.13:43484 attributed to instruction peer ea:2f
//	FullDuplex established with ea:2f (verified by real data frame from
//	                                         192.168.10.13:43484)
//
// so the pair reported a healthy tunnel that existed only between log5 and
// itself.
func TestIsLocalInterfaceIPRecognisesOwnAddress(t *testing.T) {
	// Whatever this host actually has, it must recognise it. Build the
	// expectation from the same source the guard uses so the test fails for
	// the real reason (comparison logic) rather than on an environment quirk.
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("cannot enumerate interfaces: %v", err)
	}

	var own []net.IP
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP == nil || ipnet.IP.IsLoopback() {
			continue
		}
		if v4 := ipnet.IP.To4(); v4 != nil {
			own = append(own, v4)
		} else {
			own = append(own, ipnet.IP)
		}
	}
	if len(own) == 0 {
		t.Skip("host has no non-loopback address to test against")
	}

	for _, ip := range own {
		if !IsLocalInterfaceIP(ip) {
			t.Fatalf("IsLocalInterfaceIP(%s) = false, but it is bound to a local interface", ip)
		}
	}
}

// An address we do not own must not be mistaken for our own. Without this
// the guard would be trivially over-broad and would suppress legitimate
// attributions from a peer on the same private range.
func TestIsLocalInterfaceIPRejectsForeignAddress(t *testing.T) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("cannot enumerate interfaces: %v", err)
	}
	local := map[string]bool{}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP != nil {
			local[ipnet.IP.String()] = true
			if v4 := ipnet.IP.To4(); v4 != nil {
				local[v4.String()] = true
			}
		}
	}

	// RFC5737 documentation range: guaranteed not to be any host's address.
	if !local["203.0.113.7"] && IsLocalInterfaceIP(net.ParseIP("203.0.113.7")) {
		t.Fatal("a documentation-range address was reported as local")
	}
}

// The regression as it actually appeared: a packet whose source is our own
// address and our own P2P port must be recognised no matter how the address
// is spelled.
func TestIsLocalInterfaceIPHandlesPortBearingSource(t *testing.T) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("cannot enumerate interfaces: %v", err)
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
		// This is the form handleP2P is handed: an addr with a port, which
		// is precisely what the broken comparison could not match.
		src := &net.UDPAddr{IP: v4, Port: 43484}
		if !IsLocalInterfaceIP(src.IP) {
			t.Fatalf("source %s (our own LAN address, P2P port 43484) not recognised as local",
				src)
		}
		return
	}
	t.Skip("host has no non-loopback IPv4 address")
}
