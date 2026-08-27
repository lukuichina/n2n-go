package supernode

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"n2n-go/pkg/buffers"
	"n2n-go/pkg/crypto"
	"n2n-go/pkg/log"
	"n2n-go/pkg/protocol"
	"n2n-go/pkg/protocol/spec"
	"n2n-go/pkg/transport"
)

// Supernode holds registered edges, VIP pools, and a MAC-to-edge mapping.
type Supernode struct {
	netAllocator *NetworkAllocator

	comMu       sync.RWMutex
	communities map[uint32]*Community

	edgeMu        sync.RWMutex
	edgesByMAC    map[string]*Edge
	edgesBySocket map[string]*Edge // UDP.Addr(String)

	edgeCacheMu     sync.RWMutex
	edgeCachedInfos map[string]*EdgeCachedInfos // keyed by MacADDR, only overwrites

	Conn       *net.UDPConn
	config     *Config
	shutdownCh chan struct{}
	shutdownWg sync.WaitGroup

	// Buffer pool for packet processing
	packetBufPool *buffers.BufferPool

	// Statistics
	stats SupernodeStats

	// Handlers
	SnMessageHandlers protocol.MessageHandlerMap

	SNSecrets *crypto.SNSecrets

	// WSS support
	wssConnections    map[string]*transport.WSSTransport
	wssConnectionsMu  sync.RWMutex
}

func (s *Supernode) MacADDR() net.HardwareAddr {
	return protocol.SupernodeMACAddr()
}

// NewSupernode creates a new Supernode instance with default config
func NewSupernode(conn *net.UDPConn, expiry time.Duration, cleanupInterval time.Duration) *Supernode {
	config := DefaultConfig()
	config.ExpiryDuration = expiry
	config.CleanupInterval = cleanupInterval

	return NewSupernodeWithConfig(conn, config)
}

// NewSupernodeWithConfig creates a new Supernode with the specified configuration
func NewSupernodeWithConfig(conn *net.UDPConn, config *Config) *Supernode {
	// Set UDP buffer sizes
	if err := conn.SetReadBuffer(config.UDPBufferSize); err != nil {
		log.Printf("Warning: couldn't set UDP read buffer size: %v", err)
	}
	if err := conn.SetWriteBuffer(config.UDPBufferSize); err != nil {
		log.Printf("Warning: couldn't set UDP write buffer size: %v", err)
	}

	netAllocator := NewNetworkAllocator(net.ParseIP(config.CommunitySubnet), net.CIDRMask(config.CommunitySubnetCIDR, 32))

	log.Printf("Generating secrets...")
	secrets, err := crypto.GenSNSecrets()
	if err != nil {
		log.Fatalf("could not generate secrets: %v", err)
	}

	sn := &Supernode{
		netAllocator:      netAllocator,
		communities:       make(map[uint32]*Community),
		edgesByMAC:        map[string]*Edge{},
		edgesBySocket:     map[string]*Edge{},
		edgeCachedInfos:   make(map[string]*EdgeCachedInfos),
		Conn:              conn,
		config:            config,
		shutdownCh:        make(chan struct{}),
		packetBufPool:     buffers.PacketBufferPool,
		SnMessageHandlers: make(protocol.MessageHandlerMap),
		SNSecrets:         secrets,

		// WSS support
		wssConnections: make(map[string]*transport.WSSTransport),
	}

	sn.SnMessageHandlers[spec.TypeRegisterRequest] = sn.handleRegisterMessage
	sn.SnMessageHandlers[spec.TypeUnregisterRequest] = sn.handleUnregisterMessage
	sn.SnMessageHandlers[spec.TypeHeartbeat] = sn.handleHeartbeatMessage
	sn.SnMessageHandlers[spec.TypeData] = sn.handleDataMessage
	sn.SnMessageHandlers[spec.TypePeerListRequest] = sn.handlePeerRequestMessage
	sn.SnMessageHandlers[spec.TypePing] = sn.handlePingMessage
	sn.SnMessageHandlers[spec.TypeP2PStateInfo] = sn.handleP2PStateInfoMessage
	sn.SnMessageHandlers[spec.TypeP2PFullState] = sn.handleP2PFullStateMessage
	sn.SnMessageHandlers[spec.TypeLeasesInfos] = sn.handleLeasesInfosMessage
	sn.SnMessageHandlers[spec.TypeSNPublicSecret] = sn.handleSNPublicSecretMessage

	sn.shutdownWg.Add(1)
	go func() {
		defer sn.shutdownWg.Done()
		sn.cleanupRoutine()
	}()

	return sn
}

// debugLog logs a message if debug mode is enabled
func (s *Supernode) debugLog(format string, args ...interface{}) {
	if s.config.Debug {
		log.Printf("Supernode DEBUG: "+format, args...)
	}
}

// ProcessPacket processes an incoming packet
func (s *Supernode) ProcessPacket(packet []byte, addr net.Addr) {

	s.stats.PacketsProcessed.Add(1)
	if packet[0] == protocol.VersionVFuze {
		s.handleVFuze(packet, addr)
		return
	}

	rawMsg, err := protocol.NewRawMessage(packet, addr)
	if err != nil {
		log.Printf("Supernode: ProcessPacket error: %v", err)
		return
	}

	err = s.SnMessageHandlers.Handle(rawMsg)
	if err != nil {
		if errors.Is(err, ErrUnicastForwardFail) {
			s.debugLog("Supernode: Error from SnMessageHandler[%s]: %v", rawMsg.Header.PacketType.String(), err)
		} else {
			log.Printf("Supernode: Error from SnMessageHandler[%s]: %v", rawMsg.Header.PacketType.String(), err)
		}
		if errors.Is(err, ErrCommunityUnknownEdge) || errors.Is(err, ErrCommunityNotFound) {
			log.Printf("Supernode: sending RetryRegisterRequest to addr:%s", addr.String())
			if udpAddr, ok := addr.(*net.UDPAddr); ok {
		s.WritePacket(spec.TypeRetryRegisterRequest, "", nil, nil, udpAddr)
	} else {
		log.Printf("Supernode: cannot send packet to non-UDP address: %T", addr)
	}
		}
	}
}

// Listen begins processing incoming packets
func (s *Supernode) Listen() {
	// Create a worker pool to process packets
	const numWorkers = 8
	packetChan := make(chan packetData, 100)

	// Start worker goroutines
	for i := 0; i < numWorkers; i++ {
		s.shutdownWg.Add(1)
		go func() {
			defer s.shutdownWg.Done()
			for pkt := range packetChan {
				s.ProcessPacket(pkt.data[:pkt.size], pkt.addr)
				s.packetBufPool.Put(pkt.data)
			}
		}()
	}

	// Main receive loop
	go func() {
		defer close(packetChan)

		for {
			select {
			case <-s.shutdownCh:
				return
			default:
				// Get a buffer from the pool
				buf := s.packetBufPool.Get()

				// Read a packet
				n, addr, err := s.Conn.ReadFromUDP(buf)
				if err != nil {
					log.Printf("Supernode: UDP read error: %v", err)
					s.packetBufPool.Put(buf)

					if strings.Contains(err.Error(), "use of closed network connection") {
						return
					}
					continue
				}

				s.debugLog("Received %d bytes from %v", n, addr)

				// Send to worker pool
				packetChan <- packetData{
					data: buf,
					size: n,
					addr: addr,
				}
			}
		}
	}()

	// Start WS listener if enabled
	if s.config.WSEnabled {
		go s.startWSListener()
	}

	// Start WSS listener if enabled
	if s.config.WSSEnabled {
		go s.startWSSListener()
	}

	// Block until shutdown
	<-s.shutdownCh
}

// packetData represents a received packet and its metadata
type packetData struct {
	data []byte
	size int
	addr *net.UDPAddr
}

// startWSSListener starts the WSS listener
func (s *Supernode) startWSSListener() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.handleWSSUpgrade(w, r)
	})

	server := &http.Server{
		Addr:    s.config.WSSListenAddr,
		Handler: mux,
	}

	log.Printf("Supernode: Starting WSS listener on %s", s.config.WSSListenAddr)
	if err := server.ListenAndServeTLS(s.config.WSSCert, s.config.WSSKey); err != nil {
		log.Printf("Supernode: WSS listener error: %v", err)
	}
}

// startWSListener starts the WS (plain text) listener
func (s *Supernode) startWSListener() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.handleWSUpgrade(w, r)
	})

	server := &http.Server{
		Addr:    s.config.WSListenAddr,
		Handler: mux,
	}

	log.Printf("Supernode: Starting WS listener on %s", s.config.WSListenAddr)
	if err := server.ListenAndServe(); err != nil {
		log.Printf("Supernode: WS listener error: %v", err)
	}
}

// handleWSUpgrade handles WebSocket upgrade requests (plain text)
func (s *Supernode) handleWSUpgrade(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all origins
		},
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Supernode: WS upgrade failed: %v", err)
		return
	}

	// Create WSS transport (same as TLS, just different listener)
	transport := transport.NewWSSTransportFromConn(conn)
	connID := fmt.Sprintf("ws-%s", conn.RemoteAddr().String())

	// Store connection
	s.wssConnectionsMu.Lock()
	s.wssConnections[connID] = transport
	s.wssConnectionsMu.Unlock()

	log.Printf("Supernode: New WS connection from %s (ID: %s)", conn.RemoteAddr(), connID)

	// Handle the WS connection
	go s.handleWSSConnection(transport, connID)
}

// handleWSSUpgrade handles WebSocket upgrade requests
func (s *Supernode) handleWSSUpgrade(w http.ResponseWriter, r *http.Request) {
	log.Printf("Supernode: WSS upgrade request from %s, path: %s", r.RemoteAddr, r.URL.Path)
	log.Printf("Supernode: WSS headers: Connection=%s, Upgrade=%s, Sec-WebSocket-Version=%s, Sec-WebSocket-Key=%s",
		r.Header.Get("Connection"),
		r.Header.Get("Upgrade"),
		r.Header.Get("Sec-WebSocket-Version"),
		r.Header.Get("Sec-WebSocket-Key"))
	
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all origins
		},
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Supernode: WSS upgrade failed: %v", err)
		return
	}

	// Create WSS transport
	transport := transport.NewWSSTransportFromConn(conn)
	connID := fmt.Sprintf("wss-%s", conn.RemoteAddr().String())

	// Store connection
	s.wssConnectionsMu.Lock()
	s.wssConnections[connID] = transport
	s.wssConnectionsMu.Unlock()

	log.Printf("Supernode: New WSS connection from %s (ID: %s)", conn.RemoteAddr(), connID)

	// Handle the WSS connection
	go s.handleWSSConnection(transport, connID)
}

// handleWSSConnection handles a single WSS connection
func (s *Supernode) handleWSSConnection(transport *transport.WSSTransport, connID string) {
	defer func() {
		transport.Close()
		s.wssConnectionsMu.Lock()
		delete(s.wssConnections, connID)
		s.wssConnectionsMu.Unlock()
		log.Printf("Supernode: WSS connection closed: %s", connID)
	}()

	// Main receive loop for this WSS connection
	for {
		buf := s.packetBufPool.Get()
		n, _, err := transport.Read(buf)
		if err != nil {
			log.Printf("Supernode: WSS read error from %s: %v", connID, err)
			s.packetBufPool.Put(buf)
			return
		}

		// Create a WSS address for the connection
		addr := &wssAddr{connID: connID}

		s.debugLog("WSS received %d bytes from %s", n, connID)

		// Process the packet
		s.ProcessPacket(buf[:n], addr)
		s.packetBufPool.Put(buf)
	}
}

// Shutdown performs a clean shutdown of the supernode
func (s *Supernode) Shutdown() {
	close(s.shutdownCh)
	s.shutdownWg.Wait()
	log.Printf("Supernode: Shutdown complete")
}

// wssAddr is a custom net.Addr implementation for WSS connections
type wssAddr struct {
	connID string
}

func (a *wssAddr) Network() string {
	return "wss"
}

func (a *wssAddr) String() string {
	return a.connID
}
