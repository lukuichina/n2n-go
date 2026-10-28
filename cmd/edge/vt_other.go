//go:build !windows
// +build !windows

package main

func enableVTProcessing() {}

func getTerminalSize() (int, int) {
	return 0, 0 // Use term.GetSize fallback
}