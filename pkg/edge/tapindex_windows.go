//go:build windows

package edge

import (
	"log"

	"n2n-go/pkg/tuntap"
)

// tapAdapterIfIndexes is the set of interface indexes that belong to a
// TAP-Windows adapter, decided by the driver identity the registry records for
// each network adapter rather than by anything in its name.
//
// This matters because the two signals a cross-platform address lister would
// normally use both fail on the lab Windows hosts. A tap's name is localized
// ("本地连接", "本地连接 3"), so no marker matches; and the TAP-Windows driver
// reports the adapter as up from the moment it is opened, so net.FlagUp cannot
// screen out a leftover instance either. The registry answers both questions,
// and pkg/tuntap already reads it to open the one tap it needs.
//
// The result is queried once per call rather than cached because the adapter
// set only changes when someone installs a tap, while a stale index that
// outlives the adapter is cheap: the GUID lookup drops adapters the OS no
// longer reports.
//
// An error leaves the set nil, which is not a failure mode for the caller --
// IsTapInterface still has name and address-space rules to fall back on.
func tapAdapterIfIndexes() map[uint32]bool {
	indexes, err := tuntap.TapWindowsIfIndexes()
	if err != nil {
		log.Printf("[P2P] cannot identify TAP adapters by driver identity: %v", err)
		return nil
	}
	set := make(map[uint32]bool, len(indexes))
	for _, idx := range indexes {
		set[idx] = true
	}
	return set
}
