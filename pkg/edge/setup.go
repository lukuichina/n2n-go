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
func setupNetworkComponents(cfg Config, tapcfg tuntap.Config) (*net.UDPConn, *transport.WSSTransport, *tuntap.Interface, *net.UDPAddr, *transport.WSSTransportConfig, error) {
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
			URL:         cfg.SupernodeURL,
			SkipVerify:  true, // TODO: Make this configurable
			ReadTimeout: 30 * time.Second,
			WriteTimeout: 30 * time.Second,
		}

		wsTransport, err = transport.NewWSSTransport(wsConfig)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("failed to establish WS connection: %w", err)
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
			return nil, nil, nil, nil, nil, fmt.Errorf("failed to resolve supernode address: %w", err)
		}

		// For WS, we still need TAP interface
		tap, err = tuntap.NewInterface(tapcfg)
		if err != nil {
			wsTransport.Close()
			return nil, nil, nil, nil, nil, fmt.Errorf("failed to create TAP interface: %w", err)
		}

		return nil, wsTransport, tap, snAddr, nil, nil
	}

	// Check if WSS is enabled
	if (cfg.WSSEnabled || strings.HasPrefix(cfg.SupernodeURL, "wss://")) && cfg.SupernodeURL != "" {
		// log.Printf("DEBUG: taking WSS branch")
		
		wssConfig := &transport.WSSTransportConfig{
			ProxyURL:     cfg.ProxyURL,
			URL:         cfg.SupernodeURL,
			SkipVerify:  true, // TODO: Make this configurable
			ReadTimeout: 30 * time.Second,
			WriteTimeout: 30 * time.Second,
		}

		if cfg.WSSCert != "" && cfg.WSSKey != "" {
			wssConfig.CertFile = cfg.WSSCert
			wssConfig.KeyFile = cfg.WSSKey
		}

		wssTransport, err = transport.NewWSSTransport(wssConfig)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("failed to establish WSS connection: %w", err)
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
			return nil, nil, nil, nil, nil, fmt.Errorf("failed to resolve supernode address: %w", err)
		}

		// For WSS, we still need TAP interface
		tap, err = tuntap.NewInterface(tapcfg)
		if err != nil {
			wssTransport.Close()
			return nil, nil, nil, nil, nil, fmt.Errorf("failed to create TAP interface: %w", err)
		}

		return nil, wssTransport, tap, snAddr, wssConfig, nil
	}

	// log.Printf("DEBUG: taking UDP branch, SupernodeAddr=%q", cfg.SupernodeAddr)

	// Traditional UDP mode
	snAddr, err = net.ResolveUDPAddr("udp4", cfg.SupernodeAddr)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf(" failed to resolve supernode address: %w", err)
	}

	conn, err = setupUDPConnection(cfg.LocalPort, cfg.UDPBufferSize)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf(" %w", err)
	}

	tap, err = tuntap.NewInterface(tapcfg)
	if err != nil {
		conn.Close() // Clean up on error
		return nil, nil, nil, nil, nil, fmt.Errorf(" failed to create TAP interface: %w", err)
	}

	return conn, nil, tap, snAddr, nil, nil
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

	rresp, err := protocol.MessageFromPacket[*netstruct.SNPublicSecret](respBuf, addr)
	if err != nil {
		return err
	}

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

	rresp, err := protocol.MessageFromPacket[*netstruct.RegisterResponse](respBuf, addr)

	if err != nil {
		return err
	}

	if !rresp.Msg.IsRegisterOk {
		return ErrNACKRegister
	}
	e.VirtualIP = fmt.Sprintf("%s/%d", rresp.Msg.VirtualIP, rresp.Msg.Masklen)
	e.ParsedVirtualIP = net.ParseIP(strings.Split(e.VirtualIP, "/")[0])
	if e.ParsedVirtualIP == nil {
		return fmt.Errorf("invalid virtual IP in configuration: %s", e.VirtualIP)
	}
	log.Printf("Assigned virtual IP %s", e.VirtualIP)
	log.Printf("Registration successful (ACK from %v)", addr)
	e.registered = true
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

	reqPub := &netstruct.SNPublicSecret{
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

	regReq := &netstruct.RegisterRequest{
		EdgeMACAddr:        e.MACAddr.String(),
		EdgeDesc:           e.ID,
		CommunityName:      e.Community,
		EncryptedMachineID: encMachineID,
	}

	return e.SendStruct(regReq, nil, p2p.UDPEnforceSupernode)
}
