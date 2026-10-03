package edge_test

import (
	"net"
	"testing"
)

// Helpers shared by the punch-target tests. They build their expectations
// from the running host's own interfaces so the tests assert on comparison
// logic rather than on whatever addresses the CI box happens to have.

func localIPv4AddrsForTest() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP == nil {
			continue
		}
		if v4 := ipnet.IP.To4(); v4 != nil && !v4.IsLoopback() {
			out = append(out, v4.String())
		}
	}
	return out
}

// localSubnetPeerForTest returns another host address inside one of our own
// subnets, i.e. what an on-link peer looks like.
func localSubnetPeerForTest(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP == nil || ipnet.IP.To4() == nil || ipnet.IP.IsLoopback() {
			continue
		}
		ones, bits := ipnet.Mask.Size()
		if bits != 32 || ones >= 31 {
			continue
		}
		peer := ipnet.IP.To4().Mask(ipnet.Mask)
		peer[len(peer)-1]++
		if peer.Equal(ipnet.IP.To4()) {
			continue
		}
		return peer.String() + ":56436"
	}
	return ""
}
