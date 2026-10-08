//go:build windows

package edge

import (
	"fmt"

	"golang.org/x/sys/windows/registry"
)

func getWindowsVersion() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return "Windows"
	}
	defer k.Close()

	productName, _, err := k.GetStringValue("ProductName")
	if err != nil {
		return "Windows"
	}
	releaseId, _, err := k.GetStringValue("ReleaseId")
	if err != nil {
		releaseId = ""
	}
	displayVersion, _, err := k.GetStringValue("DisplayVersion")
	if err != nil {
		displayVersion = ""
	}

	if releaseId != "" {
		return fmt.Sprintf("%s %s", productName, releaseId)
	}
	if displayVersion != "" {
		return fmt.Sprintf("%s %s", productName, displayVersion)
	}
	return productName
}
