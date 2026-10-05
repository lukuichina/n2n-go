package edge_test

import (
	"fmt"
	"net"
	"testing"

	"n2n-go/pkg/edge"
)

// localIPv4s returns every IPv4 address configured on this host, excluding
// loopback. Used to check that whatever P2PEndpointString advertises is
// genuinely an address this machine owns -- the whole point of the fix is that
// the advertised endpoint has to be real, not merely plausible.
func localIPv4s(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("net.Interfaces() failed: %v", err)
	}
	for _, iface := range ifaces {
		addrs, aerr := iface.Addrs()
		if aerr != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ipv4 := ipnet.IP.To4()
			if ipv4 == nil || ipv4.IsLoopback() {
				continue
			}
			out[ipv4.String()] = true
		}
	}
	return out
}

// Regression, observed 2026-10-03 on log5 (52:eb:72:ed:64:1f).
//
// With the P2P socket bound to the wildcard address, P2PEndpointString used to
// name the first entry of ListLocalIPsExcluding. That list ranks globally
// routable above private above link-local but deliberately preserves the OS
// enumeration order *within* a tier, so on a host with two addresses in the
// same tier -- a physical NIC plus a virtual one on the same LAN -- it
// advertised whichever the OS happened to list first, which was not
// necessarily the one the kernel would source from.
//
// log5 advertised 192.168.10.13:33377 while its socket egressed from
// 192.168.10.2. log3 punched the dead address for 42s; every attempt still
// reported "peer punched back" because the reverse punch arrived from the real
// address, so the failure looked like success at the protocol level while the
// data path stayed unverified.
//
// kernelSourceIP must therefore answer with an address this host really owns.
// It may legitimately return nil -- no default route, or every answer a tunnel
// address -- in which case P2PEndpointString falls back to the old ranking and
// nothing is worse than before.
func TestKernelSourceIPReturnsARealLocalAddress(t *testing.T) {
	local := localIPv4s(t)

	ip := edge.KernelSourceIPForTest(0)
	if ip == nil {
		t.Skip("no usable route answer on this host; P2PEndpointString falls back to the ranked list")
	}

	if !local[ip.String()] {
		t.Errorf("kernelSourceIP() = %s, which is not an address configured on this host (%v) -- "+
			"advertising it would send peers to an address that cannot exist here",
			ip, keysOf(local))
	}
	if ip.IsLoopback() {
		t.Errorf("kernelSourceIP() = %s, a loopback address", ip)
	}
	if ip.IsUnspecified() {
		t.Errorf("kernelSourceIP() = %s, an unspecified address", ip)
	}
	if v4 := ip.To4(); v4 == nil {
		t.Errorf("kernelSourceIP() = %s, not IPv4", ip)
	}

	// The routing answer is a property of the route, not of the moment, so a
	// caller that re-reads it per round must not see it wander.
	for i := 0; i < 20; i++ {
		again := edge.KernelSourceIPForTest(0)
		if again == nil || again.String() != ip.String() {
			t.Fatalf("kernelSourceIP() returned %s then %v on an unchanged host; "+
				"the advertised endpoint must be stable", ip, again)
		}
	}
}

// The endpoint peers are told to punch has to be well-formed and has to carry
// the live P2P port. A wildcard-bound socket used to yield ":0" or a bare
// ":port" whenever the local-IP list came back empty; the port in particular is
// what makes the entry routable, and losing it silently downgrades every punch
// to a scan.
func TestP2PEndpointStringWildcardKeepsPortAndNamesARealHost(t *testing.T) {
	const port = 33377

	c := &edge.EdgeClient{
		P2PAddr: &net.UDPAddr{IP: net.IPv4zero, Port: port},
	}

	got := c.P2PEndpointString()
	if got == "" {
		t.Fatal("P2PEndpointString() = \"\" for a configured P2P listener")
	}

	host, p, err := net.SplitHostPort(got)
	if err != nil {
		t.Fatalf("P2PEndpointString() = %q, which is not host:port: %v", got, err)
	}
	if p != fmt.Sprint(port) {
		t.Errorf("P2PEndpointString() = %q, lost the P2P port %d", got, port)
	}
	if host == "" {
		t.Fatalf("P2PEndpointString() = %q, no host part for a wildcard-bound socket", got)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		t.Fatalf("P2PEndpointString() = %q, host part %q is not an IP", got, host)
	}
	if ip.IsUnspecified() {
		t.Errorf("P2PEndpointString() = %q, still the unspecified address", got)
	}
	// Either a real local address, or the ranked-list fallback -- but never
	// an address outside both sets.
	local := localIPv4s(t)
	if !local[ip.String()] {
		t.Errorf("P2PEndpointString() = %q, host %s is not configured on this host (%v)",
			got, ip, keysOf(local))
	}
}

// A socket bound to a specific address must be reported verbatim. The route
// lookup only substitutes an address for the *wildcard* case; overriding an
// explicit bind would advertise something the socket is not listening on.
func TestP2PEndpointStringExplicitBindIsVerbatim(t *testing.T) {
	bound := &net.UDPAddr{IP: net.ParseIP("192.0.2.7"), Port: 4242}
	c := &edge.EdgeClient{P2PAddr: bound}

	if got, want := c.P2PEndpointString(), "192.0.2.7:4242"; got != want {
		t.Errorf("P2PEndpointString() = %q, want %q", got, want)
	}
}

func TestP2PEndpointStringNoListenerIsEmpty(t *testing.T) {
	c := &edge.EdgeClient{}
	if got := c.P2PEndpointString(); got != "" {
		t.Errorf("P2PEndpointString() = %q, want \"\" with no P2P listener", got)
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
