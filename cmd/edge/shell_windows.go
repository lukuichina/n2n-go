//go:build windows

package main

import "os/exec"

// defaultShell returns the default shell for this platform.
func defaultShell() string {
	return "cmd.exe"
}

// shellExecCommand creates an exec.Cmd for running a command in a shell.
func shellExecCommand(command string) *exec.Cmd {
	// Switch to UTF-8 code page (65001) before running the command so
	// that non-ASCII output (e.g. Chinese) is not garbled over SSH.
	return exec.Command("cmd.exe", "/c", "chcp 65001 >nul 2>&1 & "+command)
}