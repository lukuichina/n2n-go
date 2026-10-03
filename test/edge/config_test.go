package edge_test

import (
	. "n2n-go/pkg/edge"
	"testing"
)

func TestParseListenAddr(t *testing.T) {
	const defAddr, defPort = "127.0.0.1", "7778"

	cases := []struct {
		in   string
		addr string
		port string
	}{
		{"", "127.0.0.1", "7778"},
		{":9000", "127.0.0.1", "9000"},
		{"9000", "127.0.0.1", "9000"},
		{"0.0.0.0:9000", "0.0.0.0", "9000"},
		{"10.0.0.5:1194", "10.0.0.5", "1194"},
		{"example.internal:1194", "example.internal", "1194"},
		{"  :9000  ", "127.0.0.1", "9000"},
		{"example.internal", "example.internal", "7778"},
		// Port 0 must survive: it is the "let the kernel choose" sentinel for
		// the P2P socket, so it must not be treated as "unset".
		{":0", "127.0.0.1", "0"},
		{"0", "127.0.0.1", "0"},
		{"0.0.0.0:0", "0.0.0.0", "0"},
		// Bracketed IPv6.
		{"[::1]:9000", "[::1]", "9000"},
		{"[::1]", "[::1]", "7778"},
		// Bare IPv6 literal: multiple colons, no brackets.
		{"::1", "::1", "7778"},
	}

	for _, c := range cases {
		got, err := ParseListenAddr(c.in, defAddr, defPort)
		if err != nil {
			t.Errorf("ParseListenAddr(%q) returned error: %v", c.in, err)
			continue
		}
		want := c.addr + ":" + c.port
		if got != want {
			t.Errorf("ParseListenAddr(%q) = %q, want %q", c.in, got, want)
		}
	}
}

func TestParseListenAddrErrors(t *testing.T) {
	bad := []string{
		"host:port", // non-numeric port
		":99999",    // out of range
		":-1",       // negative
		"[::1]9000", // missing ':' after the IPv6 literal
		"[::1",      // unterminated bracket
	}
	for _, in := range bad {
		if got, err := ParseListenAddr(in, "127.0.0.1", "7778"); err == nil {
			t.Errorf("ParseListenAddr(%q) = %q, want an error", in, got)
		}
	}
}
