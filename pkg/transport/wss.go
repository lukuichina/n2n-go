// Package transport provides WebSocket Secure (WSS) transport implementation
package transport

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
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

	conn, resp, err := dialer.Dial(config.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("WS/WSS dial failed: %w", err)
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
func (t *WSSTransport) Read(pkt []byte) (int, net.Addr, error) {
	msgType, data, err := t.conn.ReadMessage()
	if err != nil {
		return 0, nil, err
	}

	if msgType != websocket.BinaryMessage {
		return 0, nil, fmt.Errorf("unexpected message type: %d (expected binary)", msgType)
	}

	n := copy(pkt, data)
	return n, t.addr, nil
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
