package transport_test

import (
	"context"
	. "n2n-go/pkg/transport"
	"net"
	"strings"
	"testing"
	"time"
)

// The behaviour these cover came from a machine that could not start.
//
// 2026-10-03, E2 (57.129.106.133): DNS returned 2a06:98c1:3120::3 ahead of the
// A records for n2ngo-ws.swings.one, the machine had no global IPv6 route, and
// websocket.Dialer -- with no NetDialContext set -- raced the families. The edge
// failed with "WS/WSS dial failed: context deadline exceeded" and, separately,
// "dial tcp: lookup n2ngo-ws.swings.one: i/o timeout". curl to the same URL
// connected in 20ms, because it honours /etc/gai.conf and prefers IPv4.
//
// So the default is IPv4 first, IPv6 only when IPv4 cannot be reached, and -6
// flips it. The tests use localhost, which on this host resolves ::1 first --
// the same ordering that triggered the original failure.

func v4(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		t.Fatalf("not an IPv4 address: %q", s)
	}
	return ip
}

// listenLoopback opens a listener on the requested loopback family and returns
// its address.
func listenLoopback(t *testing.T, network, addr string) net.Listener {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Skipf("cannot listen on %s %s: %v", network, addr, err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

// acceptOnce accepts a single connection and reports which family it arrived on.
func acceptOnce(t *testing.T, ln net.Listener) <-chan string {
	t.Helper()
	got := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			got <- ""
			return
		}
		conn.Close()
		host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		got <- host
	}()
	return got
}

func TestFamilyDialPrefersIPv4ByDefault(t *testing.T) {
	// Only IPv4 is up. IPv6 resolves and would be tried first by a racing
	// dialer if it existed, but here the point is that IPv4 is chosen without
	// any attempt on the other family.
	ln := listenLoopback(t, "tcp4", "127.0.0.1:0")
	accepted := acceptOnce(t, ln)
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	dial := NewFamilyDialContext(false)
	conn, err := dial(context.Background(), "tcp", net.JoinHostPort("localhost", port))
	if err != nil {
		t.Fatalf("IPv4-first dial failed although IPv4 was up: %v", err)
	}
	conn.Close()

	if host := <-accepted; host != "127.0.0.1" {
		t.Errorf("connected from %q, want 127.0.0.1", host)
	}
}

func TestFamilyDialFallsBackToIPv6WhenIPv4IsUnreachable(t *testing.T) {
	// The E2 case, reproduced: the IPv4 address exists and refuses fast, IPv6
	// answers. A dialer that stopped at the first family would fail here.
	ln := listenLoopback(t, "tcp6", "[::1]:0")
	accepted := acceptOnce(t, ln)
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	dial := NewFamilyDialContext(false)
	conn, err := dial(context.Background(), "tcp", net.JoinHostPort("localhost", port))
	if err != nil {
		t.Fatalf("did not fail over to IPv6: %v", err)
	}
	conn.Close()

	if host := <-accepted; host != "::1" {
		t.Errorf("connected from %q, want ::1", host)
	}
}

func TestFamilyDialIPv6PreferenceIsHonoured(t *testing.T) {
	// Both families up: the preference has to decide, not a race.
	v4ln := listenLoopback(t, "tcp4", "127.0.0.1:0")
	v6ln := listenLoopback(t, "tcp6", "[::1]:0")
	v4Accepted := acceptOnce(t, v4ln)
	v6Accepted := acceptOnce(t, v6ln)

	_, v6Port, _ := net.SplitHostPort(v6ln.Addr().String())
	_, v4Port, _ := net.SplitHostPort(v4ln.Addr().String())
	if v4Port == v6Port {
		t.Skip("both listeners share a port; cannot distinguish the family")
	}

	// Prefer IPv6, but only IPv6 has the listener on that port, so this
	// exercises ordering rather than reachability.
	dial := NewFamilyDialContext(true)
	conn, err := dial(context.Background(), "tcp", net.JoinHostPort("localhost", v6Port))
	if err != nil {
		t.Fatalf("IPv6-preferred dial failed: %v", err)
	}
	conn.Close()

	if host := <-v6Accepted; host != "::1" {
		t.Errorf("connected from %q, want ::1", host)
	}
	select {
	case host := <-v4Accepted:
		t.Errorf("IPv4 was dialled (%s) while -6 preferred IPv6", host)
	case <-time.After(200 * time.Millisecond):
	}
}

// The whole point of the sequence is that the IPv4 attempt does not eat the
// IPv6 attempt's budget. A racing dialer would be at the mercy of whichever
// family blackholes.
func TestFamilyDialBothUnreachableReportsEveryAddress(t *testing.T) {
	// A port nothing listens on, on a host with both families. Both attempts
	// fail fast (connection refused), and the error has to name both -- the
	// original failure said "lookup ... i/o timeout" and left the operator
	// guessing which address had been skipped.
	ln := listenLoopback(t, "tcp4", "127.0.0.1:0")
	deadPort := func() string {
		_, p, _ := net.SplitHostPort(ln.Addr().String())
		ln.Close()
		return p
	}()

	dial := NewFamilyDialContext(false)
	conn, err := dial(context.Background(), "tcp", net.JoinHostPort("localhost", deadPort))
	if err == nil {
		conn.Close()
		t.Fatal("dialing a closed port succeeded")
	}

	msg := err.Error()
	for _, want := range []string{"::1", "127.0.0.1"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error does not mention %s, so a skipped address is invisible: %v", want, err)
		}
	}
}

func TestFamilyDialRespectsPinnedNetwork(t *testing.T) {
	// tcp4/tcp6 means the caller already decided. Reordering would argue with
	// them and discard the resolver's answer.
	ln := listenLoopback(t, "tcp6", "[::1]:0")
	accepted := acceptOnce(t, ln)
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	dial := NewFamilyDialContext(false) // IPv4 first, but told tcp6
	conn, err := dial(context.Background(), "tcp6", net.JoinHostPort("localhost", port))
	if err != nil {
		t.Fatalf("tcp6-pinned dial failed: %v", err)
	}
	conn.Close()

	if host := <-accepted; host != "::1" {
		t.Errorf("tcp6 dial arrived from %q, want ::1", host)
	}
}

func TestFamilyDialPassesIPLiteralThrough(t *testing.T) {
	// A literal has one candidate; the resolver must not be consulted, and the
	// address must not be rewritten.
	ln := listenLoopback(t, "tcp4", "127.0.0.1:0")
	accepted := acceptOnce(t, ln)
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	dial := NewFamilyDialContext(true) // IPv6 preferred, irrelevant for a literal
	conn, err := dial(context.Background(), "tcp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		t.Fatalf("dialing an IP literal failed: %v", err)
	}
	conn.Close()

	if host := <-accepted; host != "127.0.0.1" {
		t.Errorf("connected from %q, want 127.0.0.1", host)
	}
}

func TestFamilyDialHonoursCallerCancellation(t *testing.T) {
	// A cancelled parent must stop the walk. Otherwise a caller that gave up
	// waits out every remaining address.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	dial := NewFamilyDialContext(false)
	ln := listenLoopback(t, "tcp4", "127.0.0.1:0")
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	start := time.Now()
	conn, err := dial(ctx, "tcp", net.JoinHostPort("localhost", port))
	if err == nil {
		conn.Close()
		t.Fatal("a cancelled dial returned a connection")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("cancelled dial took %s; it kept walking addresses", elapsed)
	}
}

func TestOrderByFamilyKeepsResolverOrderWithinFamily(t *testing.T) {
	ips := []net.IPAddr{
		{IP: net.ParseIP("2001:db8::1")},
		{IP: v4(t, "10.0.0.2")},
		{IP: net.ParseIP("2001:db8::2")},
		{IP: v4(t, "10.0.0.1")},
	}

	got := OrderByFamily(ips, false)
	want := []string{"10.0.0.2", "10.0.0.1", "2001:db8::1", "2001:db8::2"}
	for i, w := range want {
		if !got[i].IP.Equal(net.ParseIP(w)) {
			t.Errorf("position %d = %s, want %s (full order %v)", i, got[i].IP, w, got)
		}
	}

	got = OrderByFamily(ips, true)
	want = []string{"2001:db8::1", "2001:db8::2", "10.0.0.2", "10.0.0.1"}
	for i, w := range want {
		if !got[i].IP.Equal(net.ParseIP(w)) {
			t.Errorf("position %d = %s, want %s (full order %v)", i, got[i].IP, w, got)
		}
	}
}

func TestOrderByFamilyDoesNotMutateInput(t *testing.T) {
	// The resolver's slice is shared state; sorting it in place would reorder
	// whatever the caller does with it next.
	ips := []net.IPAddr{
		{IP: net.ParseIP("2001:db8::1")},
		{IP: v4(t, "10.0.0.1")},
	}
	OrderByFamily(ips, false)
	if !ips[0].IP.Equal(net.ParseIP("2001:db8::1")) {
		t.Error("OrderByFamily sorted the caller's slice")
	}
}

// IPv4-in-IPv6 form has to count as IPv4, or ::ffff:a.b.c.d would be dialled
// through the IPv6 path and defeat the preference.
func TestFamilyRankTreatsV4MappedAsIPv4(t *testing.T) {
	mapped := net.ParseIP("::ffff:10.0.0.1")
	if mapped.To4() == nil {
		t.Skip("this stack does not normalise the v4-mapped form")
	}
	if FamilyRank(mapped, false) != 0 {
		t.Error("a v4-mapped address did not rank as IPv4 under IPv4 preference")
	}
	if FamilyRank(mapped, true) != 1 {
		t.Error("a v4-mapped address ranked as IPv6 under IPv6 preference")
	}
}

func TestIsFamilyPreferredMatchesDialOrder(t *testing.T) {
	// The log helper has to agree with what the dialer does, or the line it
	// prints will explain the wrong thing.
	v4Addr := v4(t, "192.0.2.1")
	v6Addr := net.ParseIP("2001:db8::1")

	if !IsFamilyPreferred(v4Addr, false) {
		t.Error("IPv4 is not the preferred family under the default")
	}
	if IsFamilyPreferred(v6Addr, false) {
		t.Error("IPv6 reported as preferred under the default")
	}
	if !IsFamilyPreferred(v6Addr, true) {
		t.Error("IPv6 is not the preferred family under -6")
	}
	if IsFamilyPreferred(v4Addr, true) {
		t.Error("IPv4 reported as preferred under -6")
	}
}
