//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"

	"n2n-go/pkg/log"

	"golang.org/x/crypto/ssh"
)

func startInteractiveShell(channel ssh.Channel, shell, username string, cols, rows uint32) {
	log.Printf("SSH: shell request for user=%s", username)
	// Use simple cmd.exe approach for reliable output
	interactiveShellWindows(channel, username)
	// Send exit status
	if w, ok := channel.(interface{ CloseWrite() error }); ok {
		_ = w.CloseWrite()
	}
	_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
	_ = channel.Close()
}

func interactiveShellWindows(channel ssh.Channel, username string) {
	cwd, _ := os.Getwd()
	if cwd == "" {
		cwd = "C:\\"
	}

	reader := bufio.NewReader(channel)

	for {
		// Print prompt
		fmt.Fprintf(channel, "%s> ", cwd)

		// Read input byte by byte until Enter
		var line []byte
		for {
			b, err := reader.ReadByte()
			if err != nil {
				// Connection closed
				goto done
			}
			if b == 0x1b { // ESC - handle escape sequence (DSR, cursor, etc.)
				var seq []byte
				seq = append(seq, b)
				for {
					next, err := reader.ReadByte()
					if err != nil {
						goto done
					}
					seq = append(seq, next)
					if (next >= 'A' && next <= 'Z') || (next >= 'a' && next <= 'z') || next == '~' {
						break
					}
				}
				// Silently consume; log for debug
				log.Printf("SSH: consumed escape seq")
				continue
			}
			if b == '\n' || b == '\r' {
				// Echo newline
				fmt.Fprint(channel, "\r\n")
				break
			}
			if b == 0x03 { // Ctrl+C
				fmt.Fprint(channel, "^C\r\n")
				line = nil
				break
			}
			if b == 0x04 { // Ctrl+D
				goto done
			}
			if b == 0x7f || b == 0x08 { // Backspace
				if len(line) > 0 {
					line = line[:len(line)-1]
					fmt.Fprint(channel, "\b \b")
				}
				continue
			}
			// Echo character
			channel.Write([]byte{b})
			line = append(line, b)
		}

		if line == nil {
			continue
		}

		// Strip any remaining escape sequences from input
		cmdLine := strings.TrimSpace(string(line))
		cmdLine = strings.ReplaceAll(cmdLine, "\x1b[6n", "")
		cmdLine = strings.ReplaceAll(cmdLine, "\x1b[5n", "")
		cmdLine = strings.ReplaceAll(cmdLine, "\x1b[0n", "")
		if cmdLine == "" {
			continue
		}

		// Handle exit/quit
		if cmdLine == "exit" || cmdLine == "quit" {
			fmt.Fprintln(channel, "exit")
			break
		}

		// Handle cd command
		if cmdLine == "cd" || strings.HasPrefix(cmdLine, "cd ") || strings.HasPrefix(cmdLine, "cd\t") {
			parts := strings.Fields(cmdLine)
			if len(parts) == 1 {
				if home, err := os.UserHomeDir(); err == nil {
					cwd = home
				}
			} else {
				target := parts[1]
				if target == "~" {
					if home, err := os.UserHomeDir(); err == nil {
						target = home
					}
				}
				if !strings.HasPrefix(target, "\\") && !strings.Contains(target, ":") {
					target = cwd + "\\" + target
				}
				target = strings.ReplaceAll(target, "/", "\\")
				if info, err := os.Stat(target); err == nil && info.IsDir() {
					cwd = target
				} else {
					fmt.Fprintf(channel, "The system cannot find the path specified: %s\r\n", target)
				}
			}
			continue
		}

		// Execute command via cmd.exe /C with UTF-8 output
		cmd := exec.Command("cmd.exe", "/C", "chcp 65001 >nul 2>&1 & "+cmdLine)
		cmd.Env = append(os.Environ(), "TERM=dumb", "NO_COLOR=1")
		if u, err := user.Lookup(username); err == nil {
			setCmdUser(cmd, u, username)
		}
		cmd.Dir = cwd
		cmd.Stdout = channel
		cmd.Stderr = channel
		cmd.Stdin = nil

		err := cmd.Run()
		if err != nil {
			log.Printf("SSH: command exited: %v", err)
		}
	}

done:
	exitCode := 0
	if w, ok := channel.(interface{ CloseWrite() error }); ok {
		_ = w.CloseWrite()
	}
	_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(exitCode)}))
	_ = channel.Close()
}
