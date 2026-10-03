//go:build !windows

package tuntap

// TapWindowsIfIndexes is the Windows stub: outside Windows there is no
// TAP-Windows driver to identify, and the equivalent exclusion is made by the
// adapter's own name, its address, or -- for the interface n2n itself opened
// -- its index. See device_windows.go for the real implementation and for why
// the Windows answer has to come from the registry rather than the name.
func TapWindowsIfIndexes() ([]uint32, error) {
	return nil, nil
}
