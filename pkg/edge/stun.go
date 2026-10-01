package edge

import (
	"errors"
	"net"
)

// STUNClient performs STUN binding requests to discover the public-facing
// UDP address as seen by an external STUN server. The discovered address is
// used to populate the pub_socket field in RegisterRequest so the relay
// server can display a routable address for P2P hole-punching coordination.
//
// The caller must pass the same *net.UDPConn that is used for P2P traffic,
// so the NAT-mapped public address corresponds to the same socket that
// will later receive hole-punch packets from peers.
//
// The implementation, including why the periodic refresh must not read the
// socket itself, lives in stun_probe.go.
// Discover sends a STUN Binding Request to each configured server and
// returns the first successful external address (IP:port). Returns nil
// if all servers fail or no routable address is discovered.
//
// Registration-time only. While handleP2P is running the socket has a
// reader already, and reading it from here would race with it -- use
// BeginRefresh/Feed instead.
func (s *STUNClient) Discover() (*net.UDPAddr, error) {
	result, err := s.DiscoverWithClassification()
	if err != nil {
		return nil, err
	}
	return result.Addr, nil
}

// errNotEnoughAddrs is returned when classification needs at least two
// reflexive addresses and only one was observed.
var errNotEnoughAddrs = errors.New("STUN: not enough addresses for NAT classification")
