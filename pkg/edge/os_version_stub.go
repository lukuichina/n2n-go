//go:build !windows

package edge

func getWindowsVersion() string {
	return "Windows"
}
