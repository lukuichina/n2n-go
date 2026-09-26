//go:build linux

package tuntap

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// --- Linux IOCTL/Flags Constants ---
const (
	TUNSETIFF     = 0x400454ca
	TUNSETPERSIST = 0x400454cb
	TUNSETOWNER   = 0x400454cc
	TUNSETGROUP   = 0x400454ce
)
const (
	IFF_TUN   = 0x0001
	IFF_TAP   = 0x0002
	IFF_NO_PI = 0x1000 // No packet information
)

// NOTE: DeviceType, Config, Device structs are now defined in types.go

// --- ioctl helper ---
func ioctl(f int, request uintptr, argp uintptr) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(f), request, argp)
	if errno != 0 {
		return fmt.Errorf("ioctl failed with '%s'", errno)
	}
	return nil
}

// --- Linux Create function (Unchanged) ---
// ... (Creates and returns *Device, handle/ifIndex/macAddr fields are zero/nil) ...
func Create(config Config) (*Device, error) {
	// ... (implementation as before) ...
	if config.DevType != TAP {
		return nil, fmt.Errorf("only TAP supported")
	}
	/*if config.MACAddress != "" {
		fmt.Fprintf(os.Stderr, "Warning: Config MACAddress (%s) ignored on Linux.\n", config.MACAddress)
	}*/
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("linux: open /dev/net/tun: %w", err)
	}
	ifr, err := unix.NewIfreq(config.Name)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("linux: create ifreq: %w", err)
	}
	flags := uint16(unix.IFF_TAP | IFF_NO_PI)
	ifr.SetUint16(flags)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("linux: ioctl TUNSETIFF: %w", err)
	}
	actualName := ifr.Name()
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("linux: set nonblock: %w", err)
	}
	// ... (Owner/Group/Persist logic) ...
	// Use a custom DeviceIO that calls unix.Poll + unix.Read directly,
	// bypassing Go's internal/poll which returns "not pollable" for
	// TUN/TAP character devices after a process restart.
	devIo := &linuxDeviceIO{fd: fd, name: actualName}
	dev := &Device{devIo: devIo, Name: actualName, DevType: config.DevType, Config: config}
	return dev, nil
}

// linuxDeviceIO implements DeviceIO for Linux using direct unix syscalls.
// This bypasses Go's internal/poll which can return "not pollable" for
// TUN/TAP character devices, especially after a process restart.
type linuxDeviceIO struct {
	fd   int
	name string
}

func (io *linuxDeviceIO) Read(b []byte) (int, error) {
	// Use unix.Poll to wait for data (handles EINTR by retrying)
	// On some kernels, TUN/TAP character devices return POLLNVAL
	// ("not pollable") after a process restart. When that happens,
	// we fall back to a direct blocking unix.Read by temporarily
	// switching the fd to blocking mode.
	for {
		pfds := []unix.PollFd{{
			Fd:     int32(io.fd),
			Events: unix.POLLIN,
		}}
		nEvents, err := unix.Poll(pfds, 100)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			fmt.Printf("linuxDeviceIO.Read: Poll error on fd %d: %v\n", io.fd, err)
			return 0, err
		}
		if nEvents == 0 {
			// Timeout with no data — return nil so handleTAP can
			// check for shutdown.
			return 0, nil
		}
		revents := pfds[0].Revents
		// POLLNVAL: fd is not pollable (e.g. after process restart).
		// Fall back to a blocking read by temporarily setting the fd
		// to blocking mode.
		if revents&unix.POLLNVAL != 0 {
			fmt.Printf("linuxDeviceIO.Read: POLLNVAL on fd %d, falling back to blocking read\n", io.fd)
			unix.SetNonblock(io.fd, false)
			n, readErr := unix.Read(io.fd, b)
			unix.SetNonblock(io.fd, true)
			return n, readErr
		}
		if revents&(unix.POLLIN|unix.POLLERR|unix.POLLHUP) != 0 {
			n, readErr := unix.Read(io.fd, b)
			if readErr == unix.EAGAIN || readErr == unix.EWOULDBLOCK {
				continue
			}
			if readErr != nil {
				fmt.Printf("linuxDeviceIO.Read: unix.Read error on fd %d: %v\n", io.fd, readErr)
			}
			return n, readErr
		}
		// Other revents bits set (e.g., only POLLOUT) — retry
	}
}

func (io *linuxDeviceIO) Write(b []byte) (int, error) {
	return unix.Write(io.fd, b)
}

func (io *linuxDeviceIO) Close() error {
	return unix.Close(io.fd)
}

func (io *linuxDeviceIO) Fd() uintptr {
	return uintptr(io.fd)
}

func (io *linuxDeviceIO) SetReadDeadline(t time.Time) error {
	return nil // Not supported with direct unix calls
}

func (io *linuxDeviceIO) SetWriteDeadline(t time.Time) error {
	return nil
}

// --- Platform-specific implementations for Device methods ---

// GetIfIndex looks up dynamically on Linux.
func (d *Device) GetIfIndex() uint32 {
	if d == nil || d.Name == "" {
		return 0
	}
	iface, err := net.InterfaceByName(d.Name)
	if err != nil {
		return 0
	}
	return uint32(iface.Index)
}

// GetMACAddress looks up dynamically on Linux.
func (d *Device) GetMACAddress() net.HardwareAddr {
	if d == nil || d.Name == "" {
		return nil
	}
	iface, err := net.InterfaceByName(d.Name)
	if err != nil {
		return nil
	}
	if len(iface.HardwareAddr) >= 6 {
		macCopy := make(net.HardwareAddr, 6)
		copy(macCopy, iface.HardwareAddr[:6])
		return macCopy
	}
	if len(iface.HardwareAddr) == 0 {
		return nil
	}
	macCopy := make(net.HardwareAddr, len(iface.HardwareAddr))
	copy(macCopy, iface.HardwareAddr)
	return macCopy
}
