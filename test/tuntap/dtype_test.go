package tuntap_test

import (
	"fmt"
	"testing"

	"n2n-go/pkg/tuntap"
)

// DeviceType is a bare `int` with no String method of its own, and the
// CreateTunTapDevice error path formats it with %s. Without a String method
// that argument is swallowed and the error reads
//
//	failed to create %!s(tuntap.DeviceType=1) interface
//
// which hides the one fact worth knowing on a TUNSETIFF EPERM: whether you
// were being asked for a TAP or a TUN.
func TestDeviceTypeString(t *testing.T) {
	cases := []struct {
		device tuntap.DeviceType
		want   string
	}{
		{tuntap.TUN, "TUN"},
		{tuntap.TAP, "TAP"},
		// Out of range renders as DeviceType(N) rather than a bare number,
		// so a bad cast stays visible instead of silently aliasing TUN.
		{tuntap.DeviceType(7), "DeviceType(7)"},
	}

	for _, c := range cases {
		if got := c.device.String(); got != c.want {
			t.Errorf("DeviceType(%d).String() = %q, want %q", int(c.device), got, c.want)
		}
		// Also check the fmt verbs that showed the bug.
		if got := sprintfS(c.device); got != c.want {
			t.Errorf("%%s on DeviceType(%d) = %q, want %q", int(c.device), got, c.want)
		}
	}
}

func sprintfS(d tuntap.DeviceType) string { return fmt.Sprintf("%s", d) }
