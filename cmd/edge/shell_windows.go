//go:build windows

package main

import "os/exec"

// defaultShell returns the default shell for this platform.
func defaultShell() string {
	return "cmd.exe"
}

// shellExecCommand creates an exec.Cmd for running a command in a shell.
func shellExecCommand(command string) *exec.Cmd {
	return exec.Command("cmd.exe", "/c", command)
}