package edge

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/pion/stun/v2"
	"n2n-go/pkg/log"
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
// # Reading the socket
//
// DiscoverWithClassification does NOT read the socket itself. The P2P socket
// has exactly one reader -- the handleP2P loop -- and STUN goes through it.
//
// The previous design called conn.ReadFromUDP directly, which raced with
// handleP2P for the same socket. It was worse than a benign race: the STUN
// read loop discarded anything that did not decode as a STUN message
// ("continue" on a decode failure or a transaction-ID mismatch), so it
// silently swallowed the peer's hole-punch packets, while handleP2P
// simultaneously kept feeding the socket with relay traffic. Observed
// 2026-10-01 on E2: the whole handleP2PInfos goroutine blocked 75 minutes
// inside ReadFromUDP, which also stopped sending pending PeerP2PInfos, so
// the relay never learned the peer had moved. routines.go's punch loop
// already documented this hazard and worked around it by never refreshing
// STUN after registration -- at the cost of a permanently frozen mapping,
// which is the bug this replaces.
//
// Instead, refreshNatHoleAdvertisedAddr calls BeginRefresh to write the
// request, and handleP2P calls Feed on every datagram it reads. Only
// handleP2P touches the socket; the transaction ID keeps a response matched
// to the request that asked for it.
type STUNClient struct {
	servers []string
	conn    *net.UDPConn

	// ownTapIfIndex is the interface index of the tap n2n opened, or 0.
	// The STUN classification compares each discovered address against the
	// host's own addresses, so a tap showing up in that list can turn an
	// open NAT into a symmetric one. See ListLocalIPsExcluding.
	ownTapIfIndex uint32

	mu sync.Mutex
	// serverIdx is where the next refresh starts its scan, so successive
	// refreshes do not all go to the same server.
	serverIdx int

	// pending is the transaction awaiting a response, nil when no refresh is
	// in flight. Only one is tracked at a time: the servers are walked in
	// order and a refresh that has not answered within its window is
	// abandoned rather than overlapped.
	pending *PendingProbe
}

// PendingProbe is one in-flight BindingRequest.
type PendingProbe struct {
	// done is closed once the probe is finished with, so a caller waiting on
	// a refresh can wake up. Closing it is what makes BeginRefresh followed
	// by a bounded wait safe -- the wait never depends on the probe landing.
	done chan struct{}
	// transaction identifies the response. Zero transaction means the
	// request could not be built, and result carries that error.
	transaction [stun.TransactionIDSize]byte
	server      string
	sentAt      time.Time
	// result is filled in by Feed before done is closed.
	result *STUNResult
	err    error
	// resolved is closed when result is final.
	resolved bool
}

// NewSTUNClient creates a STUN client bound to the P2P socket.
//
// The socket must be the same one handleP2P reads, so the reflexive address
// corresponds to the mapping the P2P traffic actually uses -- that shared
// mapping is the reason this cannot live on a private socket.
func NewSTUNClient(conn *net.UDPConn, servers []string) *STUNClient {
	return &STUNClient{
		servers: servers,
		conn:    conn,
	}
}

// RefreshTimeout bounds how long a probe may stay pending. A STUN server
// that never answers must not keep the next probe from starting.
const RefreshTimeout = 2 * time.Second

// BeginRefresh writes a BindingRequest to the next configured server and
// returns a handle the caller can wait on. It does not block on the response:
// handleP2P delivers the answer through Feed.
//
// The request is sent from the P2P socket itself so the NAT mapping the
// server observes is the one the P2P socket actually uses -- that is the
// whole point of sharing the socket, and why this cannot simply be moved to
// a private socket of its own.
func (s *STUNClient) BeginRefresh() (*PendingProbe, error) {
	if s == nil || s.conn == nil {
		return nil, fmt.Errorf("STUN: nil connection")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Abandon anything still pending so a slow or dead server cannot keep
	// every later refresh from running.
	if s.pending != nil && !s.pending.resolved {
		s.pending.err = fmt.Errorf("STUN: superseded by a newer probe")
		s.pending.resolved = true
		close(s.pending.done)
	}

	msg, err := stun.Build(stun.TransactionID, stun.BindingRequest)
	if err != nil {
		return nil, fmt.Errorf("STUN: build request: %w", err)
	}

	// Rotate through the configured servers rather than always probing the
	// first resolvable one. The registration path walks them all, so a single
	// unreachable entry is harmless there; a one-shot probe would make the
	// same dead entry silently disable every later refresh.
	s.serverIdx = (s.serverIdx + 1) % max(1, len(s.servers))
	server, serverAddr, err := s.nextServerFrom(s.serverIdx)
	if err != nil {
		return nil, err
	}

	if _, err := s.conn.WriteToUDP(msg.Raw, serverAddr); err != nil {
		return nil, fmt.Errorf("STUN: write to %s: %w", server, err)
	}

	p := &PendingProbe{
		done:        make(chan struct{}),
		transaction: msg.TransactionID,
		server:      server,
		sentAt:      time.Now(),
	}
	s.pending = p
	return p, nil
}

// nextServerFrom returns the first configured server at or after start that
// resolves, wrapping around the list.
func (s *STUNClient) nextServerFrom(start int) (string, *net.UDPAddr, error) {
	var lastErr error
	n := len(s.servers)
	for i := 0; i < n; i++ {
		server := s.servers[(start+i)%n]
		server = strings.TrimSpace(server)
		if server == "" {
			continue
		}
		if !strings.Contains(server, ":") {
			server = server + ":19302"
		}
		addr, err := net.ResolveUDPAddr("udp4", server)
		if err != nil {
			lastErr = fmt.Errorf("STUN: resolve %s: %w", server, err)
			continue
		}
		return server, addr, nil
	}
	if lastErr != nil {
		return "", nil, lastErr
	}
	return "", nil, fmt.Errorf("STUN: no servers configured")
}

// Feed offers one datagram read by handleP2P to the pending probe. It
// returns true when the datagram was consumed.
//
// A datagram that does not belong to the pending transaction belongs to the
// P2P path and must be left alone -- that is exactly how the peer traffic
// and the relay traffic this loop already handles keep flowing.
func (s *STUNClient) Feed(payload []byte) bool {
	s.mu.Lock()
	p := s.pending
	if p == nil || p.resolved {
		s.mu.Unlock()
		return false
	}
	if time.Since(p.sentAt) > RefreshTimeout {
		p.err = fmt.Errorf("STUN: %s: timeout", p.server)
		p.resolved = true
		close(p.done)
		s.mu.Unlock()
		return false
	}
	transaction := p.transaction
	s.mu.Unlock()

	var respMsg stun.Message
	if err := stun.Decode(payload, &respMsg); err != nil {
		return false
	}
	if respMsg.TransactionID != transaction {
		return false
	}

	result := &STUNResult{}
	if err := classifySTUNResponse(&respMsg, result); err != nil {
		return false
	}
	result.AllAddrs = []string{result.Addr.String()}
	// A refresh sees one server's answer, so classification (which needs at
	// least two to compare) cannot run here -- exactly as it cannot on the
	// single-address registration path. The NatFeature learned at startup is
	// kept; re-deriving it from one probe would report "not enough
	// addresses" and clear a value that is still valid.

	s.mu.Lock()
	if s.pending != p {
		s.mu.Unlock()
		return false
	}
	p.result = result
	p.err = nil
	p.resolved = true
	close(p.done)
	s.mu.Unlock()
	return true
}

// classifySTUNResponse pulls the mapped address out of a binding response.
func classifySTUNResponse(respMsg *stun.Message, result *STUNResult) error {
	var xorAddr stun.XORMappedAddress
	if err := xorAddr.GetFrom(respMsg); err == nil && xorAddr.IP != nil {
		result.Addr = &net.UDPAddr{IP: xorAddr.IP, Port: xorAddr.Port}
		return nil
	}
	var mappedAddr stun.MappedAddress
	if err := mappedAddr.GetFrom(respMsg); err == nil && mappedAddr.IP != nil {
		result.Addr = &net.UDPAddr{IP: mappedAddr.IP, Port: mappedAddr.Port}
		return nil
	}
	return fmt.Errorf("STUN: no XOR-MAPPED-ADDRESS or MAPPED-ADDRESS in response")
}

// Wait blocks until the probe resolves or the refresh window expires,
// whichever comes first, and returns whatever Feed produced.
func (p *PendingProbe) Wait() (*STUNResult, error) {
	if p == nil {
		return nil, fmt.Errorf("STUN: no probe")
	}
	select {
	case <-p.done:
		return p.result, p.err
	case <-time.After(RefreshTimeout):
		return nil, fmt.Errorf("STUN: %s: timeout", p.server)
	}
}

func (p *PendingProbe) String() string {
	if p == nil {
		return "<nil probe>"
	}
	return fmt.Sprintf("probe{server=%s age=%s}", p.server, time.Since(p.sentAt).Round(time.Millisecond))
}

// DiscoverWithClassification keeps the original blocking signature for the
// registration path, where no other goroutine is reading the socket yet
// (handleP2P starts after InitialSetup returns).
//
// It is deliberately NOT used by the periodic refresh: see the type comment.
func (s *STUNClient) DiscoverWithClassification() (*STUNResult, error) {
	if s == nil || s.conn == nil {
		return nil, fmt.Errorf("STUN: nil connection")
	}
	if len(s.servers) == 0 {
		return nil, fmt.Errorf("STUN: no servers configured")
	}

	var firstAddr *net.UDPAddr
	var allAddrs []string
	var lastErr error

	for _, server := range s.servers {
		server = strings.TrimSpace(server)
		if server == "" {
			continue
		}
		if !strings.Contains(server, ":") {
			server = server + ":19302"
		}
		serverAddr, err := net.ResolveUDPAddr("udp4", server)
		if err != nil {
			lastErr = fmt.Errorf("STUN: resolve %s: %w", server, err)
			continue
		}

		msg, err := stun.Build(stun.TransactionID, stun.BindingRequest)
		if err != nil {
			lastErr = fmt.Errorf("STUN: build request for %s: %w", server, err)
			continue
		}
		if _, err := s.conn.WriteToUDP(msg.Raw, serverAddr); err != nil {
			lastErr = fmt.Errorf("STUN: write to %s: %w", server, err)
			continue
		}

		buf := make([]byte, 2048)
		s.conn.SetReadDeadline(time.Now().Add(RefreshTimeout))

		discovered, matched := s.readUntilMatched(buf, msg.TransactionID)
		s.conn.SetReadDeadline(time.Time{})

		if matched && discovered != nil && !discovered.IP.IsLoopback() {
			if firstAddr == nil {
				firstAddr = discovered
			}
			allAddrs = append(allAddrs, discovered.String())
			lastErr = nil
			// No early break here. ClassifyNATFeature compares the mapped
			// address across *different* STUN destinations to tell a cone NAT
			// from a symmetric one, and it rejects fewer than two addresses
			// outright (natclassify.go:53). Breaking on the first success
			// left allAddrs with exactly one entry, so classification failed
			// on every run, NatFeature stayed nil, and the edge advertised
			// natType="unknown" forever -- which made the Worker's
			// isCoordEligible reject it and hole punching never start. Each
			// extra server costs one STUN round trip, paid on the same
			// socket; firstAddr still decides the advertised pubSocket.
			continue
		}
		if !matched {
			lastErr = fmt.Errorf("STUN: %s: timeout", server)
		}
	}

	if firstAddr == nil {
		if lastErr == nil {
			lastErr = fmt.Errorf("STUN: no address discovered")
		}
		return nil, lastErr
	}

	result := &STUNResult{Addr: firstAddr, AllAddrs: allAddrs}
	if nf, err := ClassifyNATFeature(allAddrs, ListLocalIPsExcluding(5, s.ownTapIfIndex)); err == nil {
		result.NatFeature = nf
		log.Printf("STUN discovery succeeded: addr=%s NAT=%s Behavior=%s Public=%v",
			result.Addr.String(), nf.NatType, nf.Behavior, nf.PublicNetwork)
	} else {
		log.Printf("STUN discovery succeeded: addr=%s (NAT classification skipped)", result.Addr.String())
	}
	return result, nil
}

// readUntilMatched reads until the transaction ID matches or the deadline
// expires. Anything else is discarded -- safe only because this runs before
// handleP2P exists.
func (s *STUNClient) readUntilMatched(buf []byte, transaction [stun.TransactionIDSize]byte) (*net.UDPAddr, bool) {
	for {
		n, _, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return nil, false
		}
		var respMsg stun.Message
		if err := stun.Decode(buf[:n], &respMsg); err != nil {
			continue
		}
		if respMsg.TransactionID != transaction {
			continue
		}
		result := &STUNResult{}
		if err := classifySTUNResponse(&respMsg, result); err != nil {
			return nil, true
		}
		return result.Addr, true
	}
}

// PendingTransactionForTest returns the transaction ID of the in-flight probe,
// or the zero ID when nothing is pending.
//
// It reads under the client's own lock, which is what the hand-built STUN
// response test needs: the alternative was reaching for the mutex and the
// pending field from outside. Exported for test/edge; not part of the
// supported API.
func (sc *STUNClient) PendingTransactionForTest() [stun.TransactionIDSize]byte {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.pending == nil {
		return [stun.TransactionIDSize]byte{}
	}
	return sc.pending.transaction
}
