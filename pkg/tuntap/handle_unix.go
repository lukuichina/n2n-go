//go:build !windows

package tuntap

// GetHandle returns the raw file descriptor for Unix platforms.
func (d *Device) GetHandle() uintptr {
	if d == nil || d.devIo == nil {
		return 0
	}
	return d.devIo.Fd()
}
