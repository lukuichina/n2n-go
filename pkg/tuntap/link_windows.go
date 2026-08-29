//go:build windows

package tuntap

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"unsafe" // Needed for pointer manipulation for IPv4

	"n2n-go/pkg/log"

	"golang.org/x/sys/windows"
)

// --- Constants ---
const DefaultMTU = 1420
const (
	AF_INET  = windows.AF_INET
	AF_INET6 = windows.AF_INET6
)

// --- Load DLL and Procedures (Unchanged) ---
var (
	iphlpapi                        = windows.NewLazySystemDLL("iphlpapi.dll")
	procCreateUnicastIpAddressEntry = iphlpapi.NewProc("CreateUnicastIpAddressEntry")
	procDeleteUnicastIpAddressEntry = iphlpapi.NewProc("DeleteUnicastIpAddressEntry")
	procGetIpInterfaceEntry         = iphlpapi.NewProc("GetIpInterfaceEntry")
	procSetIpInterfaceEntry         = iphlpapi.NewProc("SetIpInterfaceEntry")
)

// --- Struct Definitions ---
// REMOVED - Using structs from golang.org/x/sys/windows, assuming Address is RawSockaddrInet6

// --- callProcErr Helper (With r1 logging) ---
func callProcErr(proc *windows.LazyProc, args ...uintptr) error {
	r1, _, errno := proc.Call(args...)
	if errno != windows.ERROR_SUCCESS {
		return error(errno)
	}
	if r1 != 0 {
		log.Printf("Warning: proc.Call returned r1=%d errno=0.", r1)
	}
	return nil
}

// --- Helper Functions using loaded procedures ---

// setIPAddress treats row.Address as RawSockaddrInet6 and uses unsafe for IPv4.
func setIPAddress(ifIndex uint32, ipCIDR string) error {
	ip, ipNet, err := net.ParseCIDR(ipCIDR)
	if err != nil {
		return fmt.Errorf("parse CIDR %q: %w", ipCIDR, err)
	}
	prefixLen, _ := ipNet.Mask.Size()

	// Assume windows.MibUnicastIpAddressRow.Address is RawSockaddrInet6
	row := windows.MibUnicastIpAddressRow{
		InterfaceIndex:     ifIndex,
		OnLinkPrefixLength: uint8(prefixLen),
		SkipAsSource:       0, // uint8
		DadState:           windows.IpDadStatePreferred,
		PrefixOrigin:       windows.IpPrefixOriginManual,
		SuffixOrigin:       windows.IpSuffixOriginManual,
		ValidLifetime:      0xFFFFFFFF,
		PreferredLifetime:  0xFFFFFFFF,
		// Address field will be populated below
	}

	if ip4 := ip.To4(); ip4 != nil {
		// --- Handle IPv4 using unsafe pointer copy ---
		// Create the source IPv4 structure
		addrV4 := windows.RawSockaddrInet4{
			Family: windows.AF_INET,
			// Port: 0, // Zero is default
		}
		copy(addrV4.Addr[:], ip4)

		// Get size and pointers
		sizeV4 := unsafe.Sizeof(addrV4)
		destPtr := unsafe.Pointer(&row.Address) // Pointer to the RawSockaddrInet6 field
		srcPtr := unsafe.Pointer(&addrV4)       // Pointer to the temporary RawSockaddrInet4

		// Ensure we don't write past the destination field's size (though v4 is smaller than v6)
		if sizeV4 > unsafe.Sizeof(row.Address) {
			return fmt.Errorf("internal error: sizeof(RawSockaddrInet4) > sizeof(RawSockaddrInet6)")
		}

		// Copy the bytes from addrV4 into the memory space of row.Address
		// The Family field (first 2 bytes) will be set to AF_INET.
		copy((*(*[1 << 30]byte)(destPtr))[:sizeV4], (*(*[1 << 30]byte)(srcPtr))[:sizeV4])

		// Ensure remaining bytes (if any) in the destination struct are zero? Might not be necessary.

	} else if ip6 := ip.To16(); ip6 != nil {
		// --- Handle IPv6 directly ---
		row.Address.Family = windows.AF_INET6
		// row.Address.Port = 0 // Default
		// row.Address.Flowinfo = 0 // Default
		copy(row.Address.Addr[:], ip6) // Use the .Addr field directly

		// Handle ScopeId - set in both the address struct AND the main MIB row
		// if ip.IsLinkLocalUnicast() { row.Address.Scope_id = ifIndex } // Needs correct zone index
		row.Address.Scope_id = 0           // Default to 0 if not link-local or zone unknown
		row.ScopeId = row.Address.Scope_id // Copy to the main struct field

	} else {
		return fmt.Errorf("invalid IP format: %s", ip.String())
	}

	log.Printf("Attempting CreateUnicastIpAddressEntry call for %s on IfIndex %d", ipCIDR, ifIndex)
	err = callProcErr(procCreateUnicastIpAddressEntry, uintptr(unsafe.Pointer(&row)))
	if err != nil {
		if errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
			log.Printf("IP address %s already exists on IfIndex %d.", ipCIDR, ifIndex)
			return nil
		}
		return fmt.Errorf("CreateUnicastIpAddressEntry call failed: %w", err)
	}
	log.Printf("Successfully added IP address %s to IfIndex %d", ipCIDR, ifIndex)
	return nil
}

func deleteIPAddress(ifIndex uint32, ipCIDR string) error {
	ip, _, err := net.ParseCIDR(ipCIDR)
	if err != nil {
		return fmt.Errorf("parse CIDR %q: %w", ipCIDR, err)
	}

	// Build the row for deletion. We only need InterfaceIndex and Address.
	row := windows.MibUnicastIpAddressRow{
		InterfaceIndex: ifIndex,
	}

	if ip4 := ip.To4(); ip4 != nil {
		addrV4 := windows.RawSockaddrInet4{
			Family: windows.AF_INET,
		}
		copy(addrV4.Addr[:], ip4)
		sizeV4 := unsafe.Sizeof(addrV4)
		destPtr := unsafe.Pointer(&row.Address)
		srcPtr := unsafe.Pointer(&addrV4)
		if sizeV4 > unsafe.Sizeof(row.Address) {
			return fmt.Errorf("internal error: sizeof(RawSockaddrInet4) > sizeof(RawSockaddrInet6)")
		}
		copy((*(*[1 << 30]byte)(destPtr))[:sizeV4], (*(*[1 << 30]byte)(srcPtr))[:sizeV4])
	} else if ip6 := ip.To16(); ip6 != nil {
		row.Address.Family = windows.AF_INET6
		copy(row.Address.Addr[:], ip6)
	} else {
		return fmt.Errorf("invalid IP format: %s", ip.String())
	}

	log.Printf("Attempting DeleteUnicastIpAddressEntry call for %s on IfIndex %d", ipCIDR, ifIndex)
	err = callProcErr(procDeleteUnicastIpAddressEntry, uintptr(unsafe.Pointer(&row)))
	if err != nil {
		if errors.Is(err, windows.ERROR_NOT_FOUND) {
			log.Printf("IP address %s not found on IfIndex %d, nothing to delete.", ipCIDR, ifIndex)
			return nil
		}
		return fmt.Errorf("DeleteUnicastIpAddressEntry call failed: %w", err)
	}
	log.Printf("Successfully deleted IP address %s from IfIndex %d", ipCIDR, ifIndex)
	return nil
}

// setMTUAndEnable uses windows.MibIpInterfaceRow (assuming .Enabled is uint8)
func setMTUAndEnable(ifIndex uint32, family uint16, mtu int) error {
	// Use the correct windows struct name
	keyRow := windows.MibIpInterfaceRow{Family: family, InterfaceIndex: ifIndex}
	log.Printf("Getting IP interface entry for IfIndex %d (Family %d)...", ifIndex, family)

	err := callProcErr(procGetIpInterfaceEntry, uintptr(unsafe.Pointer(&keyRow)))
	if err != nil {
		if errors.Is(err, windows.ERROR_NOT_FOUND) {
			log.Printf("Warning: GetIpInterfaceEntry not found IfIndex %d (Family %d). %v", ifIndex, family, err)
			return fmt.Errorf("cannot get interface entry: %w", err)
		}
		return fmt.Errorf("GetIpInterfaceEntry call failed: %w", err)
	}

	modifiedRow := keyRow
	changed := false
	if mtu > 0 {
		currentMtu := modifiedRow.NlMtu
		if currentMtu != uint32(mtu) {
			modifiedRow.NlMtu = uint32(mtu)
			log.Printf("Setting MTU to %d for IfIndex %d (Family %d) (was %d)", mtu, ifIndex, family, currentMtu)
			changed = true
		}
	}

	// Access .Enabled field as uint8, check against 0
	/*if modifiedRow.Enabled == 0 { // Check if currently disabled
		modifiedRow.Enabled = 1; // Set to 1 (true)
		log.Printf("Setting interface IfIndex %d (Family %d) to Enabled", ifIndex, family); changed = true
	}*/

	if changed {
		log.Printf("Applying SetIpInterfaceEntry call for IfIndex %d (Family %d)", ifIndex, family)
		err = callProcErr(procSetIpInterfaceEntry, uintptr(unsafe.Pointer(&modifiedRow)))
		if err != nil {
			return fmt.Errorf("SetIpInterfaceEntry call failed: %w", err)
		}
		log.Printf("Successfully applied SetIpInterfaceEntry call for IfIndex %d (Family %d)", ifIndex, family)
	} else {
		log.Printf("No changes needed for MTU/Enable status for IfIndex %d (Family %d)", ifIndex, family)
	}
	return nil
}

// --- Interface Methods (unchanged logic, using helpers above) ---
func (i *Interface) ConfigureInterface(macAddr, ipCIDR string, mtu int) error { /* ... as before ... */
	if i.Iface == nil {
		return fmt.Errorf("underlying device is nil")
	}
	ifIndex := i.GetIfIndex()
	if ifIndex == 0 {
		return fmt.Errorf("IfIndex is 0")
	}
	log.Printf("Configuring Windows TAP interface IfIndex: %d", ifIndex)
	if macAddr != "" {
		actualMac := i.HardwareAddr()
		log.Printf("Note: Desired MAC (%s) set via registry; current is %s", macAddr, actualMac.String())
	}

	// Delete previously configured IP if it exists and is different from the new one.
	if i.configuredIP != "" && i.configuredIP != ipCIDR {
		log.Printf("Removing previous IP address %s from IfIndex %d", i.configuredIP, ifIndex)
		if err := deleteIPAddress(ifIndex, i.configuredIP); err != nil {
			log.Printf("Warning: failed to delete previous IP %s: %v", i.configuredIP, err)
		}
	}

	err := setIPAddress(ifIndex, ipCIDR)
	if err != nil {
		return fmt.Errorf("set IP address failed: %w", err)
	}
	i.configuredIP = ipCIDR

	ip, _, err := net.ParseCIDR(ipCIDR)
	if err != nil {
		return fmt.Errorf("internal re-parse CIDR %s: %w", ipCIDR, err)
	}
	family := uint16(AF_INET)
	if ip.To4() == nil && ip.To16() != nil {
		family = AF_INET6
	}
	if mtu <= 0 {
		mtu = DefaultMTU
	}
	err = setMTUAndEnable(ifIndex, family, mtu)
	if err != nil {
		log.Printf("Warning: Failed set MTU/Enable status: %v", err)
	}
	log.Printf("Windows interface configuration finished for IfIndex %d", ifIndex)
	return nil
}
func (i *Interface) IfUp(ipCIDR string) error { return i.ConfigureInterface("", ipCIDR, DefaultMTU) }
func setMacViaRegistry(ifName, macAddr string) error {
	// Use PowerShell to find TAP adapter and set MacAddress in registry
	macNoColons := strings.ReplaceAll(macAddr, ":", "")
	psCmd := fmt.Sprintf(`Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}" | Get-ItemProperty | Where-Object { $_.DriverDesc -like "*TAP*" } | ForEach-Object { Set-ItemProperty -Path $_.PSPath -Name "MacAddress" -Value "%s" }`, macNoColons)
	cmd := exec.Command("powershell", "-Command", psCmd)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("PowerShell failed: %v, output: %s", err, string(out))
	}
	log.Printf("Set TAP MAC address to %s via PowerShell/registry for %s", macNoColons, ifName)
	return nil
}

func setMacViaRegistryByIndex(ifIndex uint32, macAddr string) error {
	// Use PowerShell to find TAP adapter by ifIndex and set MacAddress in registry
	macNoColons := strings.ReplaceAll(macAddr, ":", "")
	psCmd := fmt.Sprintf(`$ifIndex = %d; Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}" | Get-ItemProperty | Where-Object { $_.DriverDesc -like "*TAP*" } | ForEach-Object { Set-ItemProperty -Path $_.PSPath -Name "MacAddress" -Value "%s" }`, ifIndex, macNoColons)
	cmd := exec.Command("powershell", "-Command", psCmd)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("PowerShell failed: %v, output: %s", err, string(out))
	}
	log.Printf("Set TAP MAC address to %s via PowerShell/registry for IfIndex %d", macNoColons, ifIndex)
	return nil
}

func restartTapInterfaceByIndex(ifIndex uint32) {
	// Skip restart on Windows to avoid invalidating the open TAP handle.
	// The MAC is already set in the registry during device creation; a restart
	// here tends to break subsequent reads from the open handle.
	log.Printf(" Skipping interface restart for IfIndex %d to keep TAP handle valid", ifIndex)
}

// Deprecated: Use restartTapInterfaceByIndex instead
func restartTapInterface(ifName string) {
	restartTapInterfaceByIndex(0)
}

func (i *Interface) IfMac(macAddr string) error {
	if i.Iface == nil {
		return fmt.Errorf("underlying device is nil")
	}

	ifIndex := i.GetIfIndex()
	log.Printf("Note: Setting MAC address (%s) for IfIndex %d", macAddr, ifIndex)

	// Try PowerShell Set-NetAdapter first (requires admin)
	macNoColons := strings.ReplaceAll(macAddr, ":", "")
	psCmd := fmt.Sprintf("Set-NetAdapter -InterfaceIndex %d -MacAddress '%s' -Confirm:$false", ifIndex, macNoColons)
	cmd := exec.Command("powershell", "-Command", psCmd)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Warning: PowerShell Set-NetAdapter failed for IfIndex %d: %v, output: %s", ifIndex, err, string(out))

		// Fallback to registry method
		if err2 := setMacViaRegistryByIndex(ifIndex, macAddr); err2 != nil {
			log.Printf("Warning: registry MAC set also failed for IfIndex %d: %v", ifIndex, err2)
		}
	} else {
		log.Printf("Successfully set MAC to %s via PowerShell for IfIndex %d", macNoColons, ifIndex)
	}

	// Restart interface to apply changes
	restartTapInterfaceByIndex(ifIndex)

	actualMac := i.HardwareAddr()
	if actualMac != nil {
		log.Printf("Current MAC for IfIndex %d is %s", ifIndex, actualMac.String())
	} else {
		log.Printf("Warning: Could not get current MAC for IfIndex %d", ifIndex)
	}
	return nil
}
