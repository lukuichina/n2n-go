// Package transport provides WebSocket Secure (WSS) transport implementation
package transport

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/net/proxy"
)

// WSSTransport WebSocket Secure transport implementation
type WSSTransport struct {
	conn      *websocket.Conn
	addr      net.Addr
	isServer  bool
	closeCh   chan struct{}
	closeOnce sync.Once
	writeMu   sync.Mutex
}

// WSSTransportConfig WSS transport configuration
type WSSTransportConfig struct {
	URL         string
	CertFile    string
	KeyFile     string
	SkipVerify  bool
	ReadTimeout time.Duration
	WriteTimeout time.Duration
	ProxyURL    string // http://, https://, socks5://, or socks5s://
}

// NewWSSTransport creates a WS/WSS client transport (for edge)
func NewWSSTransport(config *WSSTransportConfig) (*WSSTransport, error) {
	if !strings.HasPrefix(config.URL, "ws://") && !strings.HasPrefix(config.URL, "wss://") {
		return nil, fmt.Errorf("invalid WS/WSS URL: %s", config.URL)
	}

	var dialer *websocket.Dialer

	if strings.HasPrefix(config.URL, "wss://") {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: config.SkipVerify,
			MinVersion:         tls.VersionTLS12,
		}

		if config.CertFile != "" && config.KeyFile != "" {
			cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("failed to load cert/key: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}

		dialer = &websocket.Dialer{
			HandshakeTimeout: 10 * time.Second,
			TLSClientConfig:  tlsConfig,
		}
	} else {
		// WS (plain text)
		dialer = &websocket.Dialer{
			HandshakeTimeout: 10 * time.Second,
		}
	}

	// Configure proxy if specified
	if config.ProxyURL != "" {
		if err := configureProxy(dialer, config.ProxyURL); err != nil {
			return nil, fmt.Errorf("failed to configure proxy: %w", err)
		}
	}

	conn, resp, err := dialer.Dial(config.URL, nil)
	if err != nil {
		errMsg := fmt.Sprintf("WS/WSS dial failed: %v", err)
		if resp != nil {
			errMsg += fmt.Sprintf(" (status: %s)", resp.Status)
			for k, v := range resp.Header {
				errMsg += fmt.Sprintf(" [%s: %v]", k, v)
			}
		}
		return nil, fmt.Errorf(errMsg)
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("unexpected status: %s", resp.Status)
	}

	transport := &WSSTransport{
		conn:     conn,
		addr:     conn.RemoteAddr(),
		isServer: false,
		closeCh:  make(chan struct{}),
	}

	return transport, nil
}

// configureProxy configures the websocket dialer to use the specified proxy
func configureProxy(dialer *websocket.Dialer, proxyURL string) error {
	if strings.HasPrefix(proxyURL, "socks5://") {
		// SOCKS5 proxy (plain text)
		addr := strings.TrimPrefix(proxyURL, "socks5://")
		socksDialer, err := proxy.SOCKS5("tcp", addr, nil, &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		})
		if err != nil {
			return fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
		}
		dialer.NetDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return socksDialer.Dial(network, addr)
		}
	} else if strings.HasPrefix(proxyURL, "socks5s://") {
		// SOCKS5 proxy over TLS
		proxyHost := strings.TrimPrefix(proxyURL, "socks5s://")
		dialer.NetDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Connect to proxy via TLS
			tlsConn, err := tls.Dial("tcp", proxyHost, &tls.Config{
				InsecureSkipVerify: true,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to connect to SOCKS5 TLS proxy %s: %w", proxyHost, err)
			}

			// Perform SOCKS5 handshake over TLS
			if err := socks5Handshake(tlsConn, addr); err != nil {
				tlsConn.Close()
				return nil, fmt.Errorf("SOCKS5 TLS handshake failed: %w", err)
			}

			return tlsConn, nil
		}
	} else if strings.HasPrefix(proxyURL, "http://") {
		// HTTP proxy - use standard HTTP proxy configuration
		if proxyURL != "" {
			dialer.Proxy = func(req *http.Request) (*url.URL, error) {
				return url.Parse(proxyURL)
			}
		}
	} else if strings.HasPrefix(proxyURL, "https://") {
		// HTTPS proxy (proxy server uses TLS) - need custom handling
		// because gorilla/websocket's proxy_FromURL doesn't support https scheme
		proxyHost := strings.TrimPrefix(proxyURL, "https://")
		dialer.NetDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Connect to proxy via TLS
			conn, err := tls.Dial("tcp", proxyHost, &tls.Config{
				InsecureSkipVerify: true,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to connect to HTTPS proxy %s: %w", proxyHost, err)
			}
			
			// Send CONNECT request
			connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: Keep-Alive\r\n\r\n", addr, addr)
			if _, err := conn.Write([]byte(connectReq)); err != nil {
				conn.Close()
				return nil, fmt.Errorf("failed to send CONNECT request to proxy: %w", err)
			}
			
			// Read proxy response
			conn.SetReadDeadline(time.Now().Add(15 * time.Second))
			scanner := bufio.NewScanner(conn)
			var statusLine string
			firstLine := true
			for scanner.Scan() {
				line := scanner.Text()
				if line == "" {
					break
				}
				if firstLine {
					statusLine = line
					firstLine = false
				}
			}
			
			if err := scanner.Err(); err != nil {
				conn.Close()
				return nil, fmt.Errorf("failed to read proxy response: %w", err)
			}
			
			// Check if response is 2xx
			if !strings.HasPrefix(statusLine, "HTTP/1.1 2") {
				conn.Close()
				return nil, fmt.Errorf("proxy returned non-200 status: %s", statusLine)
			}
			
			return conn, nil
		}
	} else if proxyURL != "" {
		// Default to HTTP proxy for unknown schemes
		dialer.Proxy = func(req *http.Request) (*url.URL, error) {
			return url.Parse(proxyURL)
		}
	}

	return nil
}

// NewWSSTransportFromConn creates a WSS server transport from an existing WebSocket connection
func NewWSSTransportFromConn(conn *websocket.Conn) *WSSTransport {
	return &WSSTransport{
		conn:     conn,
		addr:     conn.RemoteAddr(),
		isServer: true,
		closeCh:  make(chan struct{}),
	}
}

// Read reads a binary WebSocket message
func (t *WSSTransport) Read(pkt []byte) (n int, addr net.Addr, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("websocket panic: %v", r)
		}
	}()

	msgType, data, err := t.conn.ReadMessage()
	if err != nil {
		return 0, nil, err
	}

	if msgType != websocket.BinaryMessage {
		return 0, nil, fmt.Errorf("unexpected message type: %d (expected binary)", msgType)
	}

	n = copy(pkt, data)
	addr = t.addr
	return n, addr, nil
}

// Write writes a binary WebSocket message
func (t *WSSTransport) Write(pkt []byte, addr net.Addr) (int, error) {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	if err := t.conn.WriteMessage(websocket.BinaryMessage, pkt); err != nil {
		return 0, err
	}
	return len(pkt), nil
}

// Close closes the WebSocket connection
func (t *WSSTransport) Close() error {
	t.closeOnce.Do(func() {
		close(t.closeCh)
	})
	return t.conn.Close()
}

// LocalAddr returns the local address
func (t *WSSTransport) LocalAddr() net.Addr {
	return t.conn.LocalAddr()
}

// SetReadDeadline sets the read deadline
func (t *WSSTransport) SetReadDeadline(deadline time.Time) error {
	return t.conn.SetReadDeadline(deadline)
}

// SetWriteDeadline sets the write deadline
func (t *WSSTransport) SetWriteDeadline(deadline time.Time) error {
	return t.conn.SetWriteDeadline(deadline)
}

// socks5Handshake performs a SOCKS5 handshake over an existing connection
func socks5Handshake(conn net.Conn, targetAddr string) error {
	// SOCKS5 version and authentication methods
	// Version 5, 1 authentication method (No authentication: 0x00)
	_, err := conn.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		return fmt.Errorf("failed to send SOCKS5 version/methods: %w", err)
	}

	// Read server's choice of authentication method
	response := make([]byte, 2)
	if _, err := conn.Read(response); err != nil {
		return fmt.Errorf("failed to read SOCKS5 method selection: %w", err)
	}

	if response[0] != 0x05 {
		return fmt.Errorf("invalid SOCKS5 version: %d", response[0])
	}
	if response[1] == 0xFF {
		return fmt.Errorf("no acceptable authentication methods")
	}

	// Send connection request (CONNECT command)
	// Parse target address
	addr, err := net.ResolveTCPAddr("tcp", targetAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve target address %s: %w", targetAddr, err)
	}

	var req []byte
	if ip4 := addr.IP.To4(); ip4 != nil {
		// IPv4
		req = []byte{0x05, 0x01, 0x00, 0x01}
		req = append(req, ip4...)
	} else if ip6 := addr.IP.To16(); ip6 != nil {
		// IPv6
		req = []byte{0x05, 0x01, 0x00, 0x04}
		req = append(req, ip6...)
	} else {
		// Domain name
		hostBytes := []byte(addr.IP.String())
		req = []byte{0x05, 0x01, 0x00, 0x03, byte(len(hostBytes))}
		req = append(req, hostBytes...)
	}

	// Port
	req = append(req, byte(addr.Port>>8), byte(addr.Port&0xFF))

	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("failed to send SOCKS5 connect request: %w", err)
	}

	// Read connection response
	resp := make([]byte, 10)
	if _, err := conn.Read(resp); err != nil {
		return fmt.Errorf("failed to read SOCKS5 connect response: %w", err)
	}

	if resp[0] != 0x05 {
		return fmt.Errorf("invalid SOCKS5 version in response: %d", resp[0])
	}

	if resp[1] != 0x00 {
		return fmt.Errorf("SOCKS5 connection failed with code: %d", resp[1])
	}

	return nil
}
