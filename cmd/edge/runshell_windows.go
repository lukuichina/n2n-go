//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"

	"n2n-go/pkg/log"

	"golang.org/x/crypto/ssh"
)

func startInteractiveShell(channel ssh.Channel, shell, username string, cols, rows uint32) {
	log.Printf("SSH: shell request for user=%s", username)
	cmd := exec.Command(shell)
	if u, err := user.Lookup(username); err == nil {
		setCmdUser(cmd, u, username)
	}
	cmd.Env = append(os.Environ(), fmt.Sprintf("COLUMNS=%d", cols), fmt.Sprintf("LINES=%d", rows), "TERM=xterm-256color")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = channel, channel, channel
	err := cmd.Run()
	log.Printf("SSH: shell exited: %v", err)
	exitCode := getExitCode(err)
	if w, ok := channel.(interface{ CloseWrite() error }); ok {
		_ = w.CloseWrite()
	}
	_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(exitCode)}))
	_ = channel.Close()
}