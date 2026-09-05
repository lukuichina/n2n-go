//go:build windows

package tuntap

import (
	"n2n-go/pkg/log"
)

// closePlatform performs Windows-specific cleanup before closing the device.
// It deletes the configured IP address from the TAP interface.
func (i *Interface) closePlatform() error {
	if i.configuredIP == "" {
		return nil
	}
	if i.Iface == nil {
		i.configuredIP = ""
		return nil
	}
	ifIndex := i.GetIfIndex()
	if ifIndex == 0 {
		i.configuredIP = ""
		return nil
	}
	log.Printf("Deleting IP address %s from IfIndex %d on close", i.configuredIP, ifIndex)
	if err := deleteIPAddress(ifIndex, i.configuredIP); err != nil {
		log.Printf("Warning: failed to delete IP %s on close: %v", i.configuredIP, err)
	}
	i.configuredIP = ""
	return nil
}
