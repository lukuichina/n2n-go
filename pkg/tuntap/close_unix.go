//go:build !windows

package tuntap

// closePlatform performs platform-specific cleanup before closing the device.
// On non-Windows platforms, no special cleanup is needed.
func (i *Interface) closePlatform() error {
	return nil
}