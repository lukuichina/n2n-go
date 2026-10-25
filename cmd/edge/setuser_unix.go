//go:build !windows

package main

import (
	"fmt"
	"os/exec"
	"os/user"
	"syscall"
)

func setCmdUser(cmd *exec.Cmd, u *user.User, username string) {
	uid, gid := 0, 0
	fmt.Sscanf(u.Uid, "%d", &uid)
	fmt.Sscanf(u.Gid, "%d", &gid)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
}