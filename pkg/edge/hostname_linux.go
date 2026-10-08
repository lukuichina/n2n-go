//go:build !windows

package edge

func getWindowsHostname() string {
	return ""
}
