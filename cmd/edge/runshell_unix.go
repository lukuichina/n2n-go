//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"syscall"
	"unsafe"

	"n2n-go/pkg/log"

	"golang.org/x/crypto/ssh"
)

func startInteractiveShell(channel ssh.Channel, shell, username string, cols, rows uint32) {
	log.Printf("SSH: shell request for user=%s", username)

	ptmx, tty, err := allocatePTY()
	if err != nil {
		log.Printf("SSH: PTY allocation failed: %v, falling back to direct", err)
		cmd := exec.Command(shell)
		if u, err := user.Lookup(username); err == nil {
			setCmdUser(cmd, u, username)
		}
		cmd.Env = append(os.Environ(), fmt.Sprintf("COLUMNS=%d", cols), fmt.Sprintf("LINES=%d", rows), "TERM=xterm-256color")
		cmd.Stdin, cmd.Stdout, cmd.Stderr = channel, channel, channel
		err = cmd.Run()
		log.Printf("SSH: shell exited: %v", err)
		exitCode := getExitCode(err)
		if w, ok := channel.(interface{ CloseWrite() error }); ok {
			_ = w.CloseWrite()
		}
		_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(exitCode)}))
		_ = channel.Close()
		return
	}
	defer ptmx.Close()
	defer tty.Close()

	cmd := exec.Command(shell)
	if u, err := user.Lookup(username); err == nil {
		setCmdUser(cmd, u, username)
	}
	cmd.Env = append(os.Environ(), fmt.Sprintf("COLUMNS=%d", cols), fmt.Sprintf("LINES=%d", rows), "TERM=xterm-256color")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = tty, tty, tty
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		log.Printf("SSH: failed to start shell: %v", err)
		_ = channel.Close()
		return
	}

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := channel.Read(buf)
			if err != nil {
				break
			}
			// Filter DSR (Device Status Report) escape sequences
			data := buf[:n]
			// Remove \x1b[6n, \x1b[5n, \x1b[0n
			filtered := make([]byte, 0, n)
			i := 0
			for i < len(data) {
				if data[i] == 0x1b && i+3 < len(data) && data[i+1] == '[' && data[i+3] == 'n' && (data[i+2] == '6' || data[i+2] == '5' || data[i+2] == '0') {
					i += 4
					continue
				}
				filtered = append(filtered, data[i])
				i++
			}
			ptmx.Write(filtered)
		}
	}()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := ptmx.Read(buf)
			if err != nil {
				break
			}
			data := buf[:n]
			// Filter [6n, [5n, [0n from output (DSR noise)
			filtered := make([]byte, 0, n)
			i := 0
			for i < len(data) {
				if data[i] == 0x1b && i+3 < len(data) && data[i+1] == '[' && data[i+3] == 'n' && (data[i+2] == '6' || data[i+2] == '5' || data[i+2] == '0') {
					i += 4
					continue
				}
				filtered = append(filtered, data[i])
				i++
			}
			channel.Write(filtered)
		}
	}()

	err = cmd.Wait()
	log.Printf("SSH: shell exited: %v", err)
	exitCode := getExitCode(err)
	if w, ok := channel.(interface{ CloseWrite() error }); ok {
		_ = w.CloseWrite()
	}
	_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(exitCode)}))
	_ = channel.Close()
}

func allocatePTY() (ptmx, tty *os.File, err error) {
	ptmx, err = os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, err
	}
	var unlock int
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, ptmx.Fd(), uintptr(syscall.TIOCSPTLCK), uintptr(unsafe.Pointer(&unlock))); errno != 0 {
		ptmx.Close()
		return nil, nil, fmt.Errorf("TIOCSPTLCK: %v", errno)
	}
	var num int
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, ptmx.Fd(), uintptr(syscall.TIOCGPTN), uintptr(unsafe.Pointer(&num))); errno != 0 {
		ptmx.Close()
		return nil, nil, fmt.Errorf("TIOCGPTN: %v", errno)
	}
	ttyPath := fmt.Sprintf("/dev/pts/%d", num)
	tty, err = os.OpenFile(ttyPath, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		ptmx.Close()
		return nil, nil, err
	}
	return ptmx, tty, nil
}