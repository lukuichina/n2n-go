//go:build !windows

package edge

// tapAdapterIfIndexes has no driver registry to consult outside Windows, so
// the identity check is simply absent: IsTapInterface still excludes a tap by
// name or by the overlay address space, and ListLocalIPsExcluding still
// excludes the interface n2n itself opened by index, which covers every
// platform. See tapindex_windows.go for why Windows needs a third signal.
func tapAdapterIfIndexes() map[uint32]bool { return nil }
