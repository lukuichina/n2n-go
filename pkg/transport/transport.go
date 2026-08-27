// Package transport provides abstract network transport interfaces
package transport

import (
	"net"
	"time"
)

// Transport defines the interface for network transport layers
type Transport interface {
	// Read reads a packet from the transport
	Read(pkt []byte) (n int, addr net.Addr, err error)
	
	// Write writes a packet to the transport
	Write(pkt []byte, addr net.Addr) (n int, err error)
	
	// Close closes the transport
	Close() error
	
	// LocalAddr returns the local address
	LocalAddr() net.Addr
	
	// SetReadDeadline sets the read deadline
	SetReadDeadline(t time.Time) error
	
	// SetWriteDeadline sets the write deadline
	SetWriteDeadline(t time.Time) error
}
