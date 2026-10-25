//go:build windows

package main

import (
	"os/exec"
	"os/user"
)

func setCmdUser(cmd *exec.Cmd, u *user.User, username string) {
	// No-op on Windows; process runs as the current user.
}