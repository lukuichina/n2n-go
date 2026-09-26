package edge

import (
	"fmt"
	"n2n-go/pkg/crypto"
	"n2n-go/pkg/log"
	"n2n-go/pkg/p2p"
	"n2n-go/pkg/protocol"
	"n2n-go/pkg/protocol/netstruct"
	"n2n-go/pkg/transport"
	"n2n-go/pkg/tuntap"
	"net"
	"strconv"
	"strings"
	"time"
)

// setupNetworkComponents initializes the network connection and TAP interface
func setupNetworkComponents(cfg Config, tapcfg tuntap.Config) (*net.UDPConn, *transport.WSSTransport, *tuntap.Interface, *net.UDPAddr, *transport.WSSTransportConfig, *net.UDPAddr, error) {
	var snAddr *net.UDPAddr
	var conn *net.UDPConn
	var wsTransport *transport.WSSTransport
	var wssTransport *transport.WSSTransport
	var tap *tuntap.Interface
	var err error

	log.Printf("DEBUG: entering setupNetworkComponents, WSEnabled=%v, WSSEnabled=%v, SupernodeURL=%q, SupernodeAddr=%q", cfg.WSEnabled, cfg.WSSEnabled, cfg.SupernodeURL, cfg.SupernodeAddr)

	// Check if WS is enabled
	if (cfg.WSEnabled || strings.HasPrefix(cfg.SupernodeURL, "ws://")) && cfg.SupernodeURL != "" {
		log.Printf("DEBUG: taking WS branch")

		wsConfig := &transport.WSSTransportConfig{
			ProxyURL:     cfg.ProxyURL,
			URL:          cfg.SupernodeURL,
			SkipVerify:   true, // TODO: Make this configurable
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
		}

		wsTransport, err = transport.NewWSSTransport(wsConfig)
		if err != nil {
			return nil, nil, nil, nil, nil, nil, fmt.Errorf("failed to establish WS connection: %w", err)
		}

		log.Printf("WS connection established to %s", cfg.SupernodeURL)

		// For WS, we need a UDP address for the supernode for registration/communication
		// Use SupernodeAddr if available, otherwise derive from SupernodeURL
		var host string
		if cfg.SupernodeAddr != "" {
			host = cfg.SupernodeAddr
		} else {
			host = cfg.SupernodeURL
			if strings.HasPrefix(host, "ws://") {
				host = strings.TrimPrefix(host, "ws://")
			}
			if idx := strings.Index(host, "/"); idx >= 0 {
				host = host[:idx]
			}
			if !strings.Contains(host, ":") {
				host = host + ":8080"
			}
		}

		log.Printf("DEBUG: resolving UDP address for host: %q", host)
		snAddr, err = net.ResolveUDPAddr("udp4", host)
		if err != nil {
			wsTransport.Close()
			return nil, nil, nil, nil, nil, nil, fmt.Errorf("failed to resolve supernode address: %w", err)
		}

		// For WS, we still need TAP interface
		tap, err = tuntap.NewInterface(tapcfg)
		if err != nil {
			wsTransport.Close()
			return nil, nil, nil, nil, nil, nil, fmt.Errorf("failed to create TAP interface: %w", err)
		}

		// P2P UDP listener for peer-to-peer hole-punching (separate socket)
		p2pConn, p2pAddr, err := setupP2PConnection(cfg.P2PListenAddr, cfg.P2PListenPort, cfg.UDPBufferSize)
		if err != nil {
			wsTransport.Close()
			tap.Close()
			return nil, nil, nil, nil, nil, nil, fmt.Errorf(" failed to setup P2P UDP connection: %w", err)
		}

		return p2pConn, wsTransport, tap, snAddr, nil, p2pAddr, nil
	}

	// Check if WSS is enabled
	if (cfg.WSSEnabled || strings.HasPrefix(cfg.SupernodeURL, "wss://")) && cfg.SupernodeURL != "" {
		// log.Printf("DEBUG: taking WSS branch")

		wssConfig := &transport.WSSTransportConfig{
			ProxyURL:     cfg.ProxyURL,
			URL:          cfg.SupernodeURL,
			SkipVerify:   true, // TODO: Make this configurable
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
		}

		if cfg.WSSCert != "" && cfg.WSSKey != "" {
			wssConfig.CertFile = cfg.WSSCert
			wssConfig.KeyFile = cfg.WSSKey
		}

		wssTransport, err = transport.NewWSSTransport(wssConfig)
		if err != nil {
			return nil, nil, nil, nil, nil, nil, fmt.Errorf("failed to establish WSS connection: %w", err)
		}

		log.Printf("WSS connection established to %s", cfg.SupernodeURL)

		// For WSS, we need a UDP address for the supernode for registration/communication
		// Use SupernodeAddr if available, otherwise derive from SupernodeURL
		var host string
		if cfg.SupernodeAddr != "" {
			host = cfg.SupernodeAddr
		} else {
			host = cfg.SupernodeURL
			if strings.HasPrefix(host, "wss://") {
				host = strings.TrimPrefix(host, "wss://")
			}
			if idx := strings.Index(host, "/"); idx >= 0 {
				host = host[:idx]
			}
			if !strings.Contains(host, ":") {
				host = host + ":443"
			}
		}

		log.Printf("DEBUG: resolving UDP address for host: %q", host)
		snAddr, err = net.ResolveUDPAddr("udp4", host)
		if err != nil {
			wssTransport.Close()
			return nil, nil, nil, nil, nil, nil, fmt.Errorf("failed to resolve supernode address: %w", err)
		}

		// For WSS, we still need TAP interface
		tap, err = tuntap.NewInterface(tapcfg)
		if err != nil {
			wssTransport.Close()
			return nil, nil, nil, nil, nil, nil, fmt.Errorf("failed to create TAP interface: %w", err)
		}

		// P2P UDP listener for peer-to-peer hole-punching (separate socket)
		p2pConn, p2pAddr, err := setupP2PConnection(cfg.P2PListenAddr, cfg.P2PListenPort, cfg.UDPBufferSize)
		if err != nil {
			wssTransport.Close()
			tap.Close()
			return nil, nil, nil, nil, nil, nil, fmt.Errorf(" failed to setup P2P UDP connection: %w", err)
		}

		return p2pConn, wssTransport, tap, snAddr, wssConfig, p2pAddr, nil
	}

	// log.Printf("DEBUG: taking UDP branch, SupernodeAddr=%q", cfg.SupernodeAddr)

	// Traditional UDP mode
	snAddr, err = net.ResolveUDPAddr("udp4", cfg.SupernodeAddr)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf(" failed to resolve supernode address: %w", err)
	}

	conn, err = setupUDPConnection(cfg.LocalPort, cfg.UDPBufferSize)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf(" %w", err)
	}

	tap, err = tuntap.NewInterface(tapcfg)
	if err != nil {
		conn.Close() // Clean up on error
		return nil, nil, nil, nil, nil, nil, fmt.Errorf(" failed to create TAP interface: %w", err)
	}

	// In UDP mode, the P2P connection is the same as the supernode connection.
	// Reuse the existing conn to avoid opening a second socket.
	p2pAddr, _ := conn.LocalAddr().(*net.UDPAddr)
	return conn, nil, tap, snAddr, nil, p2pAddr, nil
}

// setupP2PConnection creates a dedicated UDP listener for P2P hole-punching.
// In WSS mode this is a separate socket from the WSS transport.
// Returns the connection and its local address (or nil if P2P is disabled).
func setupP2PConnection(listenAddr string, listenPort int, bufferSize int) (*net.UDPConn, *net.UDPAddr, error) {
	// Port 0 asks the kernel for an ephemeral port, which is the default for
	// the WSS-mode P2P socket. An explicit --p2p-listen-port overrides it.
	//
	// This block used to read as if the port were forced to 0 here, which is
	// why --p2p-listen-port appeared to be ignored: the "override" assigned 0
	// to a value that was already 0, and the real reason it had no effect was
	// that the `up` command never copied the flag into the config.
	if listenPort == 0 {
		log.Printf("P2P socket: no --p2p-listen-port given, requesting a system-assigned UDP port")
	} else {
		log.Printf("P2P socket: binding the requested UDP port %d (hole-punch peers will learn this as our pubSocket port)", listenPort)
	}

	addrStr := fmt.Sprintf("%s:%d", listenAddr, listenPort)
	localAddr, err := net.ResolveUDPAddr("udp4", addrStr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve P2P UDP address %q: %w", addrStr, err)
	}

	conn, err := net.ListenUDP("udp4", localAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open P2P UDP connection: %w", err)
	}

	if err := conn.SetReadBuffer(bufferSize); err != nil {
		log.Printf("Warning: couldn't increase P2P UDP read buffer size: %v", err)
	}
	if err := conn.SetWriteBuffer(bufferSize); err != nil {
		log.Printf("Warning: couldn't increase P2P UDP write buffer size: %v", err)
	}

	return conn, conn.LocalAddr().(*net.UDPAddr), nil
}

// setupUDPConnection creates and configures a UDP connection with the specified parameters
func setupUDPConnection(localPort int, bufferSize int) (*net.UDPConn, error) {
	localAddr, err := net.ResolveUDPAddr("udp4", ":"+strconv.Itoa(localPort))
	if err != nil {
		return nil, fmt.Errorf("failed to resolve local UDP address: %w", err)
	}

	// Set larger buffer sizes for UDP
	conn, err := net.ListenUDP("udp4", localAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to open UDP connection: %w", err)
	}

	// Set UDP buffer sizes to reduce latency
	if err := conn.SetReadBuffer(bufferSize); err != nil {
		log.Printf("Warning: couldn't increase UDP read buffer size: %v", err)
	}
	if err := conn.SetWriteBuffer(bufferSize); err != nil {
		log.Printf("Warning: couldn't increase UDP write buffer size: %v", err)
	}

	return conn, nil
}

func (e *EdgeClient) InitialSetup() error {
	if err := e.InitialGetSNPublicKey(); err != nil {
		return err
	}

	if err := e.InitialRegister(); err != nil {
		return err
	}

	if err := e.TunUp(); err != nil {
		return err
	}

	log.Printf("sending preliminary gratuitous ARP")
	if err := e.sendGratuitousARP(); err != nil {
		return err
	}

	return nil
}

// Register sends a registration packet to the supernode.
func (e *EdgeClient) InitialGetSNPublicKey() error {
	err := e.RequestSNPublicKey()
	if err != nil {
		return err
	}
	// Set a timeout for the response
	if err := e.setReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return fmt.Errorf(" failed to set read deadline: %w", err)
	}

	// Read the response
	respBuf := e.packetBufPool.Get()
	defer e.packetBufPool.Put(respBuf)

	n, addr, err := e.readPacket(respBuf)
	if err != nil {
		return fmt.Errorf(" pubkey ACK timeout: %w", err)
	}

	// Reset deadline
	if err := e.setReadDeadline(time.Time{}); err != nil {
		return fmt.Errorf(" failed to reset read deadline: %w", err)
	}

	if n < protocol.ProtoVHeaderSize {
		return fmt.Errorf(" short packet while waiting for initial SnSecretsPub")
	}

	rresp, err := protocol.MessageFromPacket[*netstruct.SnPublicSecret](respBuf[:n], addr)
	if err != nil {
		return err
	}

	log.Printf("DEBUG setup.go: received PemData length=%d, first 200 bytes=%q", len(rresp.Msg.PemData), string(rresp.Msg.PemData[:min(200, len(rresp.Msg.PemData))]))
	pubkey, err := crypto.PublicKeyFromPEMData(rresp.Msg.PemData)
	if err != nil {
		return err
	}
	e.SNPubKey = pubkey
	log.Printf("sucessfull supernode public key retrieval")

	return nil
}

// InitialRegister sends a registration packet to the supernode.
func (e *EdgeClient) InitialRegister() error {
	err := e.RequestRegister()
	if err != nil {
		return err
	}

	// Set a timeout for the response
	if err := e.setReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return fmt.Errorf(" failed to set read deadline: %w", err)
	}

	// Read the response
	respBuf := e.packetBufPool.Get()
	defer e.packetBufPool.Put(respBuf)

	n, addr, err := e.readPacket(respBuf)
	if err != nil {
		return fmt.Errorf(" registration ACK timeout: %w", err)
	}

	// Reset deadline
	if err := e.setReadDeadline(time.Time{}); err != nil {
		return fmt.Errorf(" failed to reset read deadline: %w", err)
	}

	if n < protocol.ProtoVHeaderSize {
		return fmt.Errorf(" short packet while waiting for initial RegisterResponse")
	}

	rresp, err := protocol.MessageFromPacket[*netstruct.RegisterResponse](respBuf[:n], addr)

	if err != nil {
		return err
	}

	if !rresp.Msg.IsRegisterOk {
		return ErrNACKRegister
	}
	e.VirtualIP = fmt.Sprintf("%s/%d", rresp.Msg.VirtualIp, rresp.Msg.Masklen)
	e.ParsedVirtualIP = net.ParseIP(strings.Split(e.VirtualIP, "/")[0])
	if e.ParsedVirtualIP == nil {
		return fmt.Errorf("invalid virtual IP in configuration: %s", e.VirtualIP)
	}
	log.Printf("Assigned virtual IP %s", e.VirtualIP)
	log.Printf("Registration successful (ACK from %v)", addr)
	e.registered = true

	// FRP-style fix: set our own PeerInfo (reg.Me) locally so that
	// sendP2PInfos can immediately broadcast our pubSocket and NAT info
	// to the Worker. Without this, reg.Me remains nil until the Worker
	// echoes our info back as Origin in a PeerInfoList — which never
	// happens in the current Worker deployment (Origin is only sent on
	// broadcastNatHoleInstructions, creating a circular dependency).
	//
	// This mirrors FRP's client-side self-registration: the edge knows
	// its own identity and proactively advertises its NAT-reachability.
	natType := "unknown"
	if e.NatFeature != nil {
		natType = e.NatFeature.NatType
	} else if e.NatClient != nil {
		natType = e.NatClient.GetType()
	}
	p2pEndpoint := e.P2PEndpointString()
	p2pCaps := []string{"p2p", "relay"}
	if e.WSSTransport != nil {
		p2pCaps = append(p2pCaps, "wss")
	}
	macBytes := make([]byte, len(e.MACAddr))
	copy(macBytes, e.MACAddr)
	meInfo := p2p.PeerInfo{
		VirtualIp:       e.ParsedVirtualIP.String(),
		MacAddr:         macBytes,
		PubSocket:       e.pubSocketString(),
		Community:       e.Community,
		P2PEndpoint:     p2pEndpoint,
		P2PCapabilities: p2pCaps,
		NatType:         natType,
		LastSeen:        uint64(time.Now().Unix()),
	}
	e.Peers.SetMe(meInfo)
	e.Peers.SetPendingChanges()
	log.Printf("set local reg.Me: MAC=%s VirtualIP=%s PubSocket=%s NatType=%s P2PEndpoint=%s",
		net.HardwareAddr(macBytes).String(),
		meInfo.VirtualIp, meInfo.PubSocket, meInfo.NatType, meInfo.P2PEndpoint)

	return nil
}

func (e *EdgeClient) sendGratuitousARP() error {
	if e.TAP == nil {
		return fmt.Errorf("cannot send gratuitous ARP: EdgeClient's TAP interface is not initialized")
	}
	if e.ParsedVirtualIP == nil {
		return fmt.Errorf("cannot send gratuitous ARP: EdgeClient's ParsedVirtualIP is nil (original IP string: %q)", e.VirtualIP)
	}
	return e.TAP.SendGratuitousARP(e.ParsedVirtualIP)
}

func (e *EdgeClient) TunUp() error {
	if e.VirtualIP == "" {
		return fmt.Errorf("cannot configure TAP link before VirtualIP is not set")
	}
	return e.TAP.IfUp(e.VirtualIP)
}

func (e *EdgeClient) RequestSNPublicKey() error {
	log.Printf("Trying to get Supernode publickey with supernode at %s...", e.SupernodeAddr)

	reqPub := &netstruct.SnPublicSecret{
		IsRequest: true,
	}

	return e.SendStruct(reqPub, nil, p2p.UDPEnforceSupernode)
}

func (e *EdgeClient) RequestRegister() error {
	log.Printf("Registering with supernode at %s...", e.SupernodeAddr)

	encMachineID, err := e.EncryptedMachineID()
	if err != nil {
		return err
	}

	// 构建能力列表
	p2pCapabilities := []string{"p2p", "relay"}
	if e.WSSTransport != nil {
		p2pCapabilities = append(p2pCapabilities, "wss")
	}

	// pubSocketString() has the side effect of populating e.NatFeature
	// via STUN discovery. It MUST be called before the natType check below.
	pubSocket := e.pubSocketString()

	// 获取 NAT 类型
	// Priority: STUN classification (EasyNAT/HardNAT) is more useful for
	// hole-punching decisions than the UPnP/NAT-PMP client type string.
	natType := "unknown"
	if e.NatFeature != nil {
		natType = e.NatFeature.NatType
	} else if e.NatClient != nil {
		natType = e.NatClient.GetType()
	}

	regReq := &netstruct.RegisterRequest{
		EdgeMacAddr:        e.MACAddr.String(),
		EdgeDesc:           e.ID,
		CommunityName:      e.Community,
		EncryptedMachineId: encMachineID,
		P2PEndpoint:        e.P2PEndpointString(),
		P2PCapabilities:    p2pCapabilities,
		NatType:            natType,
		PubSocket:          pubSocket,
	}

	return e.SendStruct(regReq, nil, p2p.UDPEnforceSupernode)
}

// P2PEndpointString returns the P2P endpoint (IP:port) that this Edge advertises
// to the supernode for peer-to-peer hole-punching. Returns an empty string when
// no P2P listener is configured.
//
// When the P2P socket is bound to 0.0.0.0 (wildcard), the local address is
// replaced with the actual local IP so the remote peer can route packets.
func (e *EdgeClient) P2PEndpointString() string {
	if e.P2PAddr == nil {
		return ""
	}
	if e.P2PAddr.IP != nil && e.P2PAddr.IP.IsUnspecified() {
		// Use the first non-loopback local IP as the routable address.
		localIPs := ListLocalIPs(1)
		if len(localIPs) > 0 {
			if ip := net.ParseIP(localIPs[0]); ip != nil {
				return fmt.Sprintf("%s:%d", ip.String(), e.P2PAddr.Port)
			}
		}
	}
	return e.P2PAddr.String()
}

// pubSocketString returns the public-facing socket address (IP:port) for this Edge.
//
// Priority order:
//  1. STUN-discovered external address (if available) — the only address
//     that is actually routable from outside the local network.
//  2. P2P UDP listener address — useful for direct-udp mode.
//  3. Empty string — no usable public address.
//
// Side effect: also populates e.NatFeature with the classified NAT type
// (EasyNAT/HardNAT + behavior), which is then used by RequestRegister.
func (e *EdgeClient) pubSocketString() string {
	// Try STUN discovery first — this gives us the real external address
	// as seen by a public STUN server, which is what P2P hole-punching needs.
	if e.STUNClient != nil {
		result, err := e.STUNClient.DiscoverWithClassification()
		if err == nil && result != nil && result.Addr != nil && result.Addr.IP != nil && !result.Addr.IP.IsLoopback() {
			e.NatFeature = result.NatFeature
			if result.NatFeature != nil {
				log.Printf("STUN discovery succeeded: addr=%s NAT=%s Behavior=%s Public=%v",
					result.Addr.String(), result.NatFeature.NatType, result.NatFeature.Behavior, result.NatFeature.PublicNetwork)
			} else {
				log.Printf("STUN discovery succeeded: addr=%s (NAT classification skipped)", result.Addr.String())
			}
			// STUN discovery uses the P2P socket itself (WriteToUDP/ReadFromUDP
			// on s.conn), so the STUN server sees the P2P socket's public
			// endpoint (IP:port). For cone NAT, the public port equals the
			// local port (e.P2PAddr.Port). For symmetric NAT (HardNAT), the
			// STUN-discovered port may differ because the NAT assigns different
			// ports per destination. In that case, use the STUN-discovered port
			// so the pubSocket is the correct public endpoint for hole-punching.
			var result_str string
			if e.P2PAddr != nil {
				// FRP-style fix: always use the STUN-discovered port
				// (result.Addr.Port). The STUN server sees the same P2P
				// socket, so its observed port is the public port peers
				// must send to. For Full Cone NAT, result.Addr.Port ==
				// e.P2PAddr.Port (equal, no harm). For Symmetric NAT,
				// result.Addr.Port != e.P2PAddr.Port and we MUST use
				// the STUN-discovered port.
				result_str = net.JoinHostPort(result.Addr.IP.String(), strconv.Itoa(result.Addr.Port))
			} else {
				result_str = result.Addr.String()
			}
			e.cachedPubSocket = result_str
			return result_str
		}
		log.Printf("STUN discovery failed: %v", err)
		// If STUN fails on a subsequent call but we have a cached result
		// from a previous successful discovery, reuse it so that retry
		// registrations don't overwrite the correct pubSocket with 0.0.0.0.
		if e.cachedPubSocket != "" {
			log.Printf("Reusing cached pubSocket: %s", e.cachedPubSocket)
			return e.cachedPubSocket
		}
	}

	// Fall back to P2P UDP listener address
	if e.P2PAddr != nil {
		return e.P2PAddr.String()
	}

	return ""
}

// refreshPubSocketFromSTUN updates the cached pubSocket from a fresh STUN
// discovery result, bypassing the cache check. This is called before NAT
// hole punching (in executeNatHolePunchLoop) to ensure the pubSocket is
// current — mirroring FRP's MakeHole→Prepare flow which always does fresh
// STUN right before sending hole-punch packets.
//
// Key difference from pubSocketString(): this method ALWAYS uses the
// STUN-discovered port (result.Addr.Port) rather than the local P2PAddr.Port.
// This is correct because the STUN server sees the public endpoint that
// peers must send to. For Full Cone NAT, the STUN port equals the local port,
// so there is no difference. For Symmetric NAT, the STUN port may differ,
// and using the STUN-discovered port is essential.
func (e *EdgeClient) refreshPubSocketFromSTUN(result *STUNResult) string {
	if result == nil || result.Addr == nil || result.Addr.IP == nil {
		return e.cachedPubSocket
	}

	e.NatFeature = result.NatFeature

	var result_str string
	if e.P2PAddr != nil {
		// Always use the STUN-discovered port (not the local port).
		// For Full Cone NAT: STUN port == local port (no difference).
		// For Symmetric NAT: STUN port != local port (must use STUN port).
		result_str = net.JoinHostPort(result.Addr.IP.String(), strconv.Itoa(result.Addr.Port))
	} else {
		result_str = result.Addr.String()
	}

	// Update the PubSocket on the edge's own peer info (reg.Me.Infos) so
	// that the next sendP2PInfos broadcast sends the refreshed address to
	// the Worker. The Worker stores this as the peer's pubSocket and uses
	// it for NatHoleInstruction coordination.
	if e.Peers.Me != nil {
		e.Peers.Me.Infos.PubSocket = result_str
		e.Peers.SetPendingChanges()
		log.Printf("[P2P] Updated Me.Infos.PubSocket to %s after STUN refresh", result_str)
	}

	e.cachedPubSocket = result_str
	return result_str
}
