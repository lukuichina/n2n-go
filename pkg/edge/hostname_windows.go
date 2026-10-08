//go:build windows

package edge

import (
	"golang.org/x/sys/windows"
)

func getWindowsHostname() string {
	// Try GetComputerNameEx with ComputerNameDnsHostname first (FQDN)
	var n uint32 = 256
	buf := make([]uint16, n)
	err := windows.GetComputerNameEx(windows.ComputerNameDnsHostname, &buf[0], &n)
	if err == nil && n > 0 {
		return windows.UTF16ToString(buf[:n])
	}
	// Fallback to NetBIOS name
	n = 256
	buf = make([]uint16, n)
	err = windows.GetComputerNameEx(windows.ComputerNameNetBIOS, &buf[0], &n)
	if err == nil && n > 0 {
		return windows.UTF16ToString(buf[:n])
	}
	// Final fallback to GetComputerName (deprecated but always works)
	n = 256
	buf = make([]uint16, n)
	err = windows.GetComputerName(&buf[0], &n)
	if err == nil && n > 0 {
		return windows.UTF16ToString(buf[:n])
	}
	return ""
}
