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
			PreferIPv6:   cfg.PreferIPv6,
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
			PreferIPv6:   cfg.PreferIPv6,
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

	// Ask for a hole-punch instruction now rather than waiting for the
	// handleP2PInfos ticker. The Worker drives coordination entirely off
	// inbound P2PStateInfo (coordinateNatHole is only called from
	// handleP2PStateInfoMessage), so the interval between registering and
	// the first P2PStateInfo is dead time during which the peer cannot
	// punch and cannot be punched.
	//
	// reg.Me is fully populated by now -- STUN finished before the
	// registration ACK, so NatType and P2PEndpoint are real values, not
	// placeholders -- so this first report is immediately actionable and the
	// Worker can schedule the pair on this very pass.
	//
	// One announce is not enough on its own: if the Worker's stagger gate
	// defers the pair it relies on a Durable Object alarm to come back, and
	// the burst below re-announces while that window is open.
	e.requestNatHoleAfterRegister()

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
		// Our own LAN addresses, so a peer sharing this broadcast domain
		// can address us directly. Reported separately from PubSocket
		// because the punching side tries them first -- FRP parity, see
		// AssistedEndpoints.
		AssistedSockets: e.AssistedEndpoints(),
	}

	return e.SendStruct(regReq, nil, p2p.UDPEnforceSupernode)
}

// KernelSourceIPForTest exposes kernelSourceIP so the advertised-endpoint
// selection can be asserted against the host the test actually runs on, rather
// than against a synthetic interface table that would not exercise the route
// lookup at all.
func KernelSourceIPForTest(excludeIfIndex uint32) net.IP {
	return kernelSourceIP(excludeIfIndex)
}

// P2PEndpointString returns the P2P endpoint (IP:port) that this Edge advertises
// to the supernode for peer-to-peer hole-punching. Returns an empty string when
// no P2P listener is configured.
//
// When the P2P socket is bound to 0.0.0.0 (wildcard), the local address is
// replaced with the actual local IP so the remote peer can route packets.
//
// With a wildcard bind the kernel -- not this function -- chooses the source
// address at send time, so the endpoint advertised here has to be the one the
// kernel will pick, or peers punch an address nothing answers on. See
// kernelSourceIP for why enumerating local IPs is the wrong way to find it.
func (e *EdgeClient) P2PEndpointString() string {
	if e.P2PAddr == nil {
		return ""
	}
	if e.P2PAddr.IP != nil && e.P2PAddr.IP.IsUnspecified() {
		// Ask the routing table first: this is the address a remote peer
		// will actually see arrive from.
		if ip := kernelSourceIP(e.ownTapIfIndex()); ip != nil {
			return fmt.Sprintf("%s:%d", ip.String(), e.P2PAddr.Port)
		}
		// Fall back to the first non-loopback local IP. The tap is excluded
		// by index so a non-default --net cannot make it win this single
		// slot.
		localIPs := ListLocalIPsExcluding(1, e.ownTapIfIndex())
		if len(localIPs) > 0 {
			if ip := net.ParseIP(localIPs[0]); ip != nil {
				return fmt.Sprintf("%s:%d", ip.String(), e.P2PAddr.Port)
			}
		}
	}
	return e.P2PAddr.String()
}

// kernelSourceIP returns the local IPv4 address the kernel would use as the
// source address for traffic leaving this host toward the public internet, or
// nil when that cannot be established.
//
// This exists because P2PEndpointString has to name one concrete address for a
// socket bound to 0.0.0.0, and the only address that is genuinely correct is
// the one the routing table selects. Taking the first entry of
// ListLocalIPsExcluding instead answers a different question -- "which address
// did the OS enumerate first" -- and those two disagree on any host with more
// than one address in the same reachability tier. ListLocalIPsExcluding ranks
// globally routable above private above link-local, but explicitly preserves
// enumeration order *within* a tier, so a machine with a physical NIC and a
// virtual one on the same LAN gets whichever the OS listed first. That
// advertised a dead address for the whole punch.
//
// Scope, stated precisely because it is narrow. This fixes the address *this*
// host picks for itself. It does not address a peer whose packets arrive from
// an address neither side advertised because a NAT in the path rewrote the
// source. That rewriting happens in a router, outside the sending host's
// protocol stack: on 2026-10-03, log5 (52:eb:72:ed:64:1f) advertised
// 192.168.10.13:33377, which `ip a` confirms was its real eth0 address, and
// an OpenWrt in the path still delivered every packet to log3 with source
// 192.168.10.2:33377. No self-address choice can predict or prevent that, and
// kernelSourceIP returns 192.168.10.13 on that host just as the old code did.
//
// A peer advertised at an address it cannot be reached at is a receiving-side
// problem, fixed where the observed address is learned: ExpectedPunchPeerMAC
// and the attribution path in handleP2P. Do not expect a change here to make
// such a punch work.
//
// What this does cover is the case the old code got wrong on its own terms: a
// host with two addresses in the same reachability tier, where enumeration
// order decided which one got advertised. The advertised address then names
// an interface the kernel will not source from, and punches go to an address
// this host never sends from in the first place.
//
// The probe connects a throwaway UDP socket to an off-subnet address. Connect
// on a datagram socket performs the route lookup and sends nothing, so this
// costs no packets on the wire and cannot be mistaken for traffic.
//
// excludeIfIndex is the tap's interface index, so a result that routes back
// into our own overlay is rejected rather than advertised.
func kernelSourceIP(excludeIfIndex uint32) net.IP {
	// Public resolvers: off-subnet for every deployment, and parsed as IP
	// literals so this never blocks on DNS.
	probes := []string{"8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53"}

	// Only ever advertise an address this host already offers as a normal
	// local IP. That keeps the tap adapter out, and keeps the answer
	// consistent with the ranking that ClassifyNATFeature and the assisted
	// candidate list also rely on.
	allowed := make(map[string]bool)
	for _, ip := range ListLocalIPsExcluding(16, excludeIfIndex) {
		allowed[ip] = true
	}
	if len(allowed) == 0 {
		return nil
	}

	for _, p := range probes {
		dst, err := net.ResolveUDPAddr("udp4", p)
		if err != nil {
			continue
		}
		c, err := net.DialUDP("udp4", nil, dst)
		if err != nil {
			continue
		}
		local, ok := c.LocalAddr().(*net.UDPAddr)
		var ip net.IP
		if ok && local != nil && local.IP != nil {
			ip = local.IP.To4()
		}
		c.Close()
		if ip == nil {
			continue
		}
		// A tunnel address can legitimately be the kernel's choice when the
		// VPN owns the default route, but it is never the answer to "what
		// will a remote peer see", so leave those hosts to the existing
		// ranking rather than advertising them from a route lookup.
		if !allowed[ip.String()] || p2p.IsCGNATOverlayAddr(ip) {
			continue
		}
		return ip
	}
	return nil
}

// ownTapIfIndex returns the interface index of the tap n2n opened, or 0 when
// it is not open yet. Used to keep the overlay adapter out of the address list
// that is advertised to peers, independently of what --net happens to be.
func (e *EdgeClient) ownTapIfIndex() uint32 {
	if e.TAP == nil || e.TAP.Iface == nil {
		return 0
	}
	return e.TAP.Iface.GetIfIndex()
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
		// The classification below compares discovered addresses against the
		// host's own, so keep the overlay adapter out of that list by index
		// rather than relying on its address being in overlay space.
		e.STUNClient.ownTapIfIndex = e.ownTapIfIndex()
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
		// NAT type has the same registration-timing trap as PubSocket, and
		// it gates hole punching outright. Both the RegisterRequest and the
		// first PeerP2PInfos broadcast read NatType from NatFeature, which
		// is nil until STUN classification finishes -- so an edge registered
		// early advertised "unknown" and never corrected it. The Worker's
		// isCoordEligible rejects any peer that is neither HardNAT nor
		// EasyNAT, so both edges stayed ineligible forever and
		// coordinateNatHole reported eligible=0 with both peers online.
		// Refresh it here, next to PubSocket, so the next broadcast carries
		// the classified type.
		if result.NatFeature != nil && result.NatFeature.NatType != "" &&
			result.NatFeature.NatType != e.Peers.Me.Infos.NatType {
			prev := e.Peers.Me.Infos.NatType
			e.Peers.Me.Infos.NatType = result.NatFeature.NatType
			log.Printf("[P2P] Updated Me.Infos.NatType %s -> %s after STUN refresh",
				prev, result.NatFeature.NatType)
		}
		e.Peers.SetPendingChanges()
		log.Printf("[P2P] Updated Me.Infos.PubSocket to %s after STUN refresh", result_str)
	}

	e.cachedPubSocket = result_str
	return result_str
}
