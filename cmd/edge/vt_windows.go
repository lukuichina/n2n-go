//go:build windows
// +build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

func enableVTProcessing() {
	for _, f := range []*os.File{os.Stdout, os.Stderr, os.Stdin} {
		handle := windows.Handle(f.Fd())
		var mode uint32
		if err := windows.GetConsoleMode(handle, &mode); err == nil {
			mode |= windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING
			windows.SetConsoleMode(handle, mode)
		}
	}
}

func getTerminalSize() (int, int) {
	var info windows.ConsoleScreenBufferInfo
	if err := windows.GetConsoleScreenBufferInfo(windows.Handle(os.Stdout.Fd()), &info); err == nil {
		w := int(info.Window.Right - info.Window.Left + 1)
		h := int(info.Window.Bottom - info.Window.Top + 1)
		if w > 0 && h > 0 {
			return w, h
		}
	}
	return 80, 24
}