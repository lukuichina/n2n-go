package edge

import (
	"context"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"n2n-go/pkg/buffers"
	"n2n-go/pkg/crypto"
	"n2n-go/pkg/log"
	"n2n-go/pkg/machine"
	"n2n-go/pkg/management"
	"n2n-go/pkg/natclient"
	"n2n-go/pkg/p2p"
	"n2n-go/pkg/protocol"
	"n2n-go/pkg/protocol/spec"
	"n2n-go/pkg/syshosts"
	transform "n2n-go/pkg/tranform"
	"n2n-go/pkg/transport"
	"n2n-go/pkg/tuntap"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/compress/zstd"
)

// EdgeClient encapsulates the state and configuration of an edge.
type EdgeClient struct {
	Peers *p2p.PeerRegistry

	ID            string
	Community     string
	SupernodeAddr *net.UDPAddr
	Conn          *net.UDPConn
	P2PConn       *net.UDPConn
	P2PAddr       *net.UDPAddr
	// natHolePunching guards against overlapping NAT hole punch rounds.
	// A round ends with a long wait (FRP's ReadTimeoutMs), and the punch is
	// driven from a short ticker, so without this a pending instruction
	// would spawn a new goroutine every tick while the previous one is still
	// waiting.
	natHolePunching atomic.Bool
	// unknownPunchAck tracks the last time we answered a punch from a source
	// that matches no known peer. The punch magic is four public bytes, so
	// without a throttle any host that learns the socket address could use it
	// to make us emit a reply per datagram — the amplification the ACK echo
	// loop already demonstrated, just driven from outside.
	unknownPunchAckMu sync.Mutex
	unknownPunchAck   map[string]time.Time
	wssConfig         *transport.WSSTransportConfig
	WSSTransport      *transport.WSSTransport
	TAP               *tuntap.Interface
	seq               uint32

	//EncryptionKey     []byte
	//encryptionEnabled bool

	protocolVersion   uint8
	heartbeatInterval time.Duration
	keepAliveInterval time.Duration
	keepAliveTimeout  time.Duration
	verifyHash        bool
	enableVFuze       bool
	communityHash     uint32

	ctx    context.Context
	cancel context.CancelFunc

	wg sync.WaitGroup

	NatClient natclient.NATClient

	VirtualIP       string
	ParsedVirtualIP net.IP
	MACAddr         net.HardwareAddr

	machineId      []byte
	predictableMac net.HardwareAddr

	fragMu sync.RWMutex
	frag   map[string]map[uint8][]byte

	unregisterOnce sync.Once
	running        atomic.Bool

	// Buffer pools
	packetBufPool *buffers.BufferPool
	headerBufPool *buffers.BufferPool

	// Stats
	PacketsSent atomic.Uint64
	PacketsRecv atomic.Uint64

	EAPI *EdgeClientApi
	Mgmt *management.ManagementServer

	// Socks5 is the optional SOCKS5 / HTTP-CONNECT ingress. Nil unless
	// socks5_listen_address is set.
	Socks5 *Socks5Server

	// STUN
	STUNClient *STUNClient

	// refreshProbe is the STUN refresh currently awaiting a response, if
	// any. Owned by handleP2P (the P2P socket's only reader): handleP2PInfos
	// starts it and must not wait on it, and handleP2P resolves it by
	// handing each datagram to STUNClient.Feed.
	refreshProbe *PendingProbe
	NatFeature   *NatFeature

	// cachedPubSocket caches the STUN-discovered public socket address
	// so that subsequent calls to pubSocketString() (e.g. during retry
	// registration) reuse the cached value if STUN discovery fails.
	cachedPubSocket string

	SNPubKey *rsa.PublicKey

	//hosts file management
	//ensure having peer.community with assigned address in hosts file
	Hosts *syshosts.Hosts

	//state
	registered bool
	config     *Config
	// Handlers
	messageHandlers protocol.MessageHandlerMap

	isWaitingForSNPubKeyUpdate          bool
	isWaitingForSNRetryRegisterResponse bool

	// expectedPunchPeerMAC is the peer MAC the supernode named in the
	// NatHoleInstruction we are currently executing, valid only for the
	// duration of that instruction. It exists because a source address is
	// not always an address the peer published: a router between the two
	// that forwards and rewrites the source (SNAT) turns it into an
	// address neither side ever advertised, and every lookup by socket or
	// by IP then misses. The field logs showed exactly that -- a peer
	// reached by the supernode as 52:eb:72:ed:64:1f arriving as
	// 172.22.1.17:49585, answered once and then discarded 18 times, so the
	// path was never recorded and never completed.
	//
	// Naming the peer in advance is not the same as inventing one: the
	// pairing was already authorised by the supernode, so attributing an
	// arriving punch to that MAC during this window records a fact about a
	// peer that is known to exist, and it expires with the instruction.
	expectedPunchPeerMACMu sync.RWMutex
	expectedPunchPeerMAC   string

	payloadProcessor *transform.PayloadProcessor
}

func EnsureEdgeLogger() {
	log.MustInit("edge")
}

func NewEdgeManagementClient() (*management.ManagementClient, error) {
	cfg, err := LoadConfig(false) // Load config using Viper
	if err != nil {
		return nil, fmt.Errorf("Failed to load configuration: %w", err)
	}
	client := management.NewManagementClient("edge", cfg.Community)
	if isStarted := client.IsManagementServerStarted(); !isStarted {
		return nil, fmt.Errorf("Unable to connect to edge management (is edge up and running ?)")
	}
	return client, nil
}

// NewEdgeClient creates a new EdgeClient with a cancellable context.
func NewEdgeClient(cfg Config) (*EdgeClient, error) {

	machineId, err := machine.GetMachineID()
	if err != nil {
		return nil, err
	}
	log.Printf("got machine-id: %s", hex.EncodeToString(machineId))
	predictableMac, err := machine.GenerateMac(cfg.Community)
	if err != nil {
		return nil, err
	}
	log.Printf("%s TAP ifName machine-id based Community %s MAC Address: %s", cfg.TapName, cfg.Community, predictableMac.String())

	tapcfg := tuntap.Config{
		Name:       cfg.TapName,
		DevType:    tuntap.TAP,
		MACAddress: predictableMac.String(), // Windows: Set via registry
	}

	log.Printf("checking hosts file manageability")
	hosts, err := syshosts.NewHosts()
	if err != nil {
		log.Fatalf("err: %v", err)
	}
	if !hosts.IsWritable() {
		log.Fatalf("hosts file: access-denied for writing into hostsfile (community entries)")
	}

	conn, wssTransport, tap, snAddr, wssConfig, p2pAddr, err := setupNetworkComponents(cfg, tapcfg)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	communityHash := protocol.HashCommunity(cfg.Community)

	natClient := natclient.SetupNAT(conn, cfg.EdgeID, cfg.SupernodeAddr)

	err = tap.IfMac(predictableMac.String())
	if err != nil {
		if runtime.GOOS == "windows" {
			log.Printf("warn: %v", err)
			// If MAC modification failed, use the actual TAP MAC to avoid mismatch
			if actualMac := tap.HardwareAddr(); actualMac != nil {
				log.Printf("Using actual TAP MAC %s instead of predictable MAC %s", actualMac.String(), predictableMac.String())
				predictableMac = actualMac
			}
		} else {
			log.Fatalf("err: %v", err)
		}
	}

	processorTransforms := []transform.Transform{}
	if cfg.CompressPayload {
		zstdTransform, err := transform.NewZstdTransform(zstd.SpeedDefault)
		if err != nil {
			log.Fatalf(" unable to create zstdTransform for payloadProcessor (requested by compress-payload): %v", err)
		}
		log.Printf("added zstdTransform to payload Processor (compress-payload is true)")
		log.Printf("ensure all connected edges also uses compress-payload settings !")
		processorTransforms = append(processorTransforms, zstdTransform)
	}
	if cfg.EncryptionPassphrase != "" {
		aesGCMTransform, err := transform.NewAESGCMTransform(cfg.EncryptionPassphrase)
		if err != nil {
			log.Fatalf("cannot instanciate aesGCMTransform for payloadProcessor: %v", err)
		}
		log.Printf("added AESGCMTransform to payload Processor (encryption-passphrase is set)")
		log.Printf("Attention! Encryption of data packets payload is enabled. Ensure all edge for the community uses same passphrase !")
		processorTransforms = append(processorTransforms, aesGCMTransform)
	}

	if len(processorTransforms) < 1 {
		log.Printf("added NoOpTransform to payload Processor since none have been enabled")
		processorTransforms = append(processorTransforms, transform.NewNoOpTransform())
	}

	payloadProcessor, err := transform.NewPayloadProcessor(processorTransforms)
	if err != nil {
		log.Fatalf("cannot instanciate payloadProcessor: %v", err)
	}

	mgmtServer := management.NewManagementServer("edge", cfg.Community)
	err = mgmtServer.Start()
	if err != nil {
		log.Fatalf("Failed to start management server: %v", err)
	}

	// In WS/WSS mode, conn is the dedicated P2P UDP socket, not a supernode
	// socket. Set Conn to nil so handleP2P doesn't early-return (it checks
	// e.P2PConn == e.Conn), and supernode traffic goes through WSSTransport.
	var connField *net.UDPConn
	if wssTransport == nil {
		connField = conn // UDP mode: shared supernode/P2P socket
	}

	peers := p2p.NewPeerRegistry(cfg.Community)
	// The registry needs our own tap name to keep the overlay subnet out of
	// same-subnet scoring -- see PeerRegistry.SelfTapName.
	peers.SelfTapName = cfg.TapName

	edge := &EdgeClient{
		Peers:             peers,
		ID:                cfg.EdgeID,
		Community:         cfg.Community,
		SupernodeAddr:     snAddr,
		Conn:              connField,
		P2PConn:           conn,
		P2PAddr:           p2pAddr,
		WSSTransport:      wssTransport,
		wssConfig:         wssConfig,
		TAP:               tap,
		Mgmt:              mgmtServer,
		seq:               0,
		NatClient:         natClient,
		MACAddr:           predictableMac,
		predictableMac:    predictableMac,
		machineId:         machineId,
		protocolVersion:   cfg.ProtocolVersion,
		heartbeatInterval: cfg.HeartbeatInterval,
		keepAliveInterval: cfg.KeepAliveInterval,
		keepAliveTimeout:  cfg.KeepAliveTimeout,
		verifyHash:        cfg.VerifyHash,
		enableVFuze:       cfg.EnableVFuze,
		communityHash:     communityHash,
		ctx:               ctx,
		cancel:            cancel,
		packetBufPool:     buffers.PacketBufferPool,
		headerBufPool:     buffers.HeaderBufferPool,
		messageHandlers:   make(protocol.MessageHandlerMap),
		config:            &cfg,
		payloadProcessor:  payloadProcessor,
		Hosts:             hosts,
		STUNClient:        NewSTUNClient(conn, cfg.STUNServers),
	}
	edge.messageHandlers[spec.TypeData] = edge.handleDataMessage
	edge.messageHandlers[spec.TypePeerInfo] = edge.handlePeerInfoMessage
	edge.messageHandlers[spec.TypePing] = edge.handlePingMessage
	edge.messageHandlers[spec.TypeP2PFullState] = edge.handleP2PFullStateMessage
	edge.messageHandlers[spec.TypeLeasesInfos] = edge.handleLeasesInfosMessage
	edge.messageHandlers[spec.TypeRetryRegisterRequest] = edge.handleRetryRegisterRequest
	edge.messageHandlers[spec.TypeRegisterResponse] = edge.handleRegisterResponseMessage
	edge.messageHandlers[spec.TypeSNPublicSecret] = edge.handleSNPublicSecretMessage
	edge.messageHandlers[spec.TypeHeartbeat] = edge.handleHeartbeatMessage
	edge.messageHandlers[spec.TypeUnregisterRequest] = edge.handleUnregisterRequestMessage
	edge.messageHandlers[spec.TypeAck] = edge.handleAckMessage
	edge.messageHandlers[spec.TypePeerListRequest] = edge.handlePeerListRequestMessage
	edge.messageHandlers[spec.TypeP2PStateInfo] = edge.handleP2PStateInfoMessage
	edge.messageHandlers[spec.TypeOnlineCheck] = edge.handleOnlineCheckMessage
	edge.messageHandlers[spec.TypeICECandidate] = edge.handleICECandidateMessage
	edge.messageHandlers[spec.TypeTURNCredentials] = edge.handleTURNCredentialsMessage
	log.Printf("edge %s: enableVFuze = %v", edge.ID, edge.enableVFuze)
	return edge, nil
}

// Run launches heartbeat, TAP-to-supernode, and UDP-to-TAP goroutines.
func (e *EdgeClient) Run() {
	if !e.running.CompareAndSwap(false, true) {
		log.Printf("Already running, ignoring Run() call")
		return
	}
	if !e.registered {
		log.Printf("Cannot run an unregistered edge, ignoring Run() call")
	}

	go e.handleHeartbeat()
	go e.handleTAP()
	go e.handleUDP()
	go e.handleP2P()

	log.Printf("sending preliminary Peer List Request")
	err := e.sendPeerListRequest()
	if err != nil {
		log.Printf("(warn) failed sending preliminary Peer List Request: %v", err)
	}

	log.Printf("starting P2PUpdate routines...")
	go e.handleP2PUpdates()
	go e.handleP2PInfos()
	if e.keepAliveInterval > 0 {
		log.Printf("starting P2P keepalive (interval=%v timeout=%v)", e.keepAliveInterval, e.keepAliveTimeout)
		go e.handleP2PKeepAlive()
	} else {
		log.Printf("P2P keepalive disabled (p2p_keepalive_interval=0)")
	}

	log.Printf("starting management api...")
	eapi := NewEdgeApi(e)
	e.EAPI = eapi
	go eapi.Run()

	// The SOCKS5 listener is started after the TAP exists, because the
	// overlay policy reads the TAP's subnet to decide what it may forward.
	// A bind failure here is fatal for the same reason it is not started in
	// NewEdgeClient: a port clash the operator asked for should stop the edge,
	// not disappear into a goroutine.
	if e.config.Socks5ListenAddr != "" {
		s, err := NewSocks5Server(e, Socks5Options{
			ListenAddr:  e.config.Socks5ListenAddr,
			Policy:      e.config.Socks5Policy,
			Auth:        e.config.Socks5Auth,
			IdleTimeout: e.config.Socks5IdleTimeout,
		})
		if err != nil {
			log.Fatalf("socks5: cannot start listener: %v", err)
		}
		e.Socks5 = s
		go s.Serve()
	}

	<-e.ctx.Done() // Block until context is cancelled
}

// Close initiates a clean shutdown.
func (e *EdgeClient) Close() {
	if e.Socks5 != nil {
		e.Socks5.Close()
	}
	if err := e.Unregister(); err != nil {
		log.Printf("Unregister failed: %v", err)
	}
	if e.NatClient != nil {
		log.Printf("nat: Cleaning up all portMappings...")
		natclient.Cleanup(e.NatClient)
	}
	e.Mgmt.Stop()
	e.cancel()

	// Force read operations to unblock
	if e.WSSTransport != nil {
		if err := e.WSSTransport.Close(); err != nil {
			log.Printf("Error closing WSS transport: %v", err)
		}
	}

	if e.Conn != nil {
		e.Conn.SetReadDeadline(time.Now())
	}

	// Wait for all goroutines to finish
	e.wg.Wait()

	// Close resources
	if e.TAP != nil {
		if err := e.TAP.Close(); err != nil {
			log.Printf("Error closing TAP interface: %v", err)
		}
	}

	if e.WSSTransport != nil {
		if err := e.WSSTransport.Close(); err != nil {
			log.Printf("Error closing WSS transport: %v", err)
		}
	}

	if e.Conn != nil {
		if err := e.Conn.Close(); err != nil {
			log.Printf("Error closing UDP connection: %v", err)
		}
	}

	e.running.Store(false)
	log.Printf("Shutdown complete")
}

func (e *EdgeClient) IsKnownPeerSocket(addr *net.UDPAddr) bool {
	peer, err := e.Peers.GetPeerBySocket(addr)
	if err != nil || peer == nil {
		return false
	}
	return true
}

func (e *EdgeClient) IsSupernodeUDPAddr(addr *net.UDPAddr) bool {
	return (addr.IP.Equal(e.SupernodeAddr.IP)) && (addr.Port == e.SupernodeAddr.Port)
}

// ProtocolVersion returns the protocol version being used
func (e *EdgeClient) ProtocolVersion() uint8 {
	return protocol.VersionV
}

func (e *EdgeClient) EncryptedMachineID() ([]byte, error) {
	encMachineID, err := crypto.EncryptSequence(e.machineId, e.SNPubKey)
	if err != nil {
		return nil, err
	}
	return encMachineID, nil
}

func (e *EdgeClient) ProcessOutgoingPayload(payload []byte) ([]byte, error) {
	return e.payloadProcessor.PrepareOutput(payload)
}

func (e *EdgeClient) ProcessIncomingPayload(payload []byte) ([]byte, error) {
	return e.payloadProcessor.ParseInput(payload)
}

// EdgeClient helper methods for WSS/UDP compatibility

func (e *EdgeClient) setReadDeadline(t time.Time) error {
	if e.WSSTransport != nil {
		return e.WSSTransport.SetReadDeadline(t)
	}
	if e.Conn != nil {
		return e.Conn.SetReadDeadline(t)
	}
	return fmt.Errorf("no transport available")
}

func (e *EdgeClient) readPacket(buf []byte) (int, net.Addr, error) {
	if e.WSSTransport != nil {
		return e.WSSTransport.Read(buf)
	}
	if e.Conn != nil {
		return e.Conn.ReadFromUDP(buf)
	}
	return 0, nil, fmt.Errorf("no transport available")
}
