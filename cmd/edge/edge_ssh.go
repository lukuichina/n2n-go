// cmd/edge/edge_ssh.go
// SSH server for n2n-go edge, adapted from usque's sshd.go.
// Supports password + public key auth, shell/exec/scp/sftp.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"n2n-go/pkg/log"

	"github.com/pkg/sftp"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
)

var sshCommand = &cli.Command{
	Name:  "ssh",
	Usage: "Run SSH server (password + key auth, shell/exec/scp/sftp)",
	Flags: []cli.Flag{
		&cli.IntFlag{Name: "port", Aliases: []string{"p"}, Value: 22, Usage: "Port to listen on"},
		&cli.StringFlag{Name: "authorized-keys", Usage: "Path to authorized_keys file"},
		&cli.BoolFlag{Name: "allow-password", Usage: "Allow password authentication"},
		&cli.StringFlag{Name: "password", Usage: "Password for password authentication"},
		&cli.StringFlag{Name: "bind", Usage: "Bind address (default 0.0.0.0)"},
	},
	Action: sshCmd,
}

func sshCmd(c *cli.Context) error {
	port := c.Int("port")
	bind := c.String("bind")
	authorizedKeysPath := c.String("authorized-keys")
	allowPassword := c.Bool("allow-password")
	serverPassword := c.String("password")

	err := StartSSHServer(bind, port, authorizedKeysPath, allowPassword, serverPassword)
	if err != nil {
		return err
	}
	select {}
}
// the `ssh` subcommand and the `up --ssh` integration.
func StartSSHServer(virtualIP string, port int, authorizedKeysPath string, allowPassword bool, serverPassword string) error {
	bind := virtualIP
	if bind == "" {
		bind = "0.0.0.0"
	}
	listenAddr := fmt.Sprintf("%s:%d", bind, port)

	sshConfig := &ssh.ServerConfig{
		PublicKeyCallback: keyAuthCallback(authorizedKeysPath),
		ServerVersion:     "SSH-2.0-n2n-go",
	}
	if allowPassword {
		sshConfig.PasswordCallback = func(cm ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if serverPassword != "" && string(pass) == serverPassword {
				return &ssh.Permissions{Extensions: map[string]string{"user": cm.User()}}, nil
			}
			if serverPassword == "" {
				return &ssh.Permissions{Extensions: map[string]string{"user": cm.User()}}, nil
			}
			return nil, errors.New("password rejected")
		}
	}
	hostKey, err := generateHostKey()
	if err != nil {
		return fmt.Errorf("host key: %w", err)
	}
	sshConfig.AddHostKey(hostKey)

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", listenAddr, err)
	}
	log.Printf("sshd listening on %s", listenAddr)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("Accept error: %v", err)
				continue
			}
			go handleSSHConnection(conn, sshConfig)
		}
	}()
	return nil
}

func generateHostKey() (ssh.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(key)
}

func keyAuthCallback(authorizedKeysPath string) func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	if authorizedKeysPath == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			authorizedKeysPath = filepath.Join(home, ".ssh", "authorized_keys")
		}
	}
	return func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		data, err := os.ReadFile(authorizedKeysPath)
		if err != nil {
			return nil, fmt.Errorf("read authorized_keys: %w", err)
		}
		for len(data) > 0 {
			pk, _, _, rest, err := ssh.ParseAuthorizedKey(data)
			if err != nil {
				break
			}
			if ssh.FingerprintSHA256(key) == ssh.FingerprintSHA256(pk) {
				return &ssh.Permissions{Extensions: map[string]string{"user": conn.User()}}, nil
			}
			data = rest
		}
		return nil, errors.New("public key not allowed")
	}
}

func handleSSHConnection(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()
	log.Printf("SSH: new connection from %s", conn.RemoteAddr())
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		log.Printf("SSH handshake failed: %v", err)
		return
	}
	defer sshConn.Close()
	log.Printf("SSH: authenticated user=%s", sshConn.User())
	go ssh.DiscardRequests(reqs)

	for ch := range chans {
		log.Printf("SSH: new channel type=%s", ch.ChannelType())
		if ch.ChannelType() != "session" {
			ch.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, requests, err := ch.Accept()
		if err != nil {
			log.Printf("channel accept: %v", err)
			continue
		}
		go func(ch ssh.Channel, in <-chan *ssh.Request, username string, conn *ssh.ServerConn) {
			req, ok := <-in
			if !ok {
				ch.Close()
				return
			}
			if req.Type == "subsystem" {
				var sub struct{ Name string }
				if err := ssh.Unmarshal(req.Payload, &sub); err == nil && strings.ToLower(sub.Name) == "sftp" {
					req.Reply(true, nil)
					srv, err := sftp.NewServer(ch)
					if err != nil {
						log.Printf("sftp server: %v", err)
						ch.Close()
						return
					}
					if err := srv.Serve(); err != nil {
						log.Printf("sftp serve: %v", err)
					}
					srv.Close()
					ch.Close()
					return
				}
				if req.WantReply {
					req.Reply(false, nil)
				}
				ch.Close()
				return
			}
			handleSessionWithFirstRequest(ch, in, req, username, conn)
		}(channel, requests, sshConn.User(), sshConn)
	}
}

func handleSessionWithFirstRequest(channel ssh.Channel, requests <-chan *ssh.Request, firstReq *ssh.Request, username string, conn *ssh.ServerConn) {
	proxyChan := make(chan *ssh.Request, 10)
	proxyChan <- firstReq
	go func() {
		defer close(proxyChan)
		for req := range requests {
			proxyChan <- req
		}
	}()
	handleSession(channel, proxyChan, username, conn)
}

func handleSession(channel ssh.Channel, requests <-chan *ssh.Request, username string, conn *ssh.ServerConn) {
	defer channel.Close()
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}
	cols, rows := uint32(80), uint32(40)

	for req := range requests {
		switch req.Type {
		case "pty-req":
			var p struct {
				Term  string
				Cols  uint32
				Rows  uint32
				Width uint32
				Height uint32
				Modes string
			}
			if err := ssh.Unmarshal(req.Payload, &p); err == nil {
				cols, rows = p.Cols, p.Rows
			}
			req.Reply(true, nil)
		case "window-change":
			var w struct {
				Cols   uint32
				Rows   uint32
				Width  uint32
				Height uint32
			}
			if err := ssh.Unmarshal(req.Payload, &w); err == nil {
				cols, rows = w.Cols, w.Rows
			}
			req.Reply(true, nil)
		case "env":
			req.Reply(true, nil)
		case "shell":
			log.Printf("SSH: shell request for user=%s", username)
			go startInteractiveShell(channel, shell, username, cols, rows)
			req.Reply(true, nil)
		case "exec":
			var payload struct{ Command string }
			_ = ssh.Unmarshal(req.Payload, &payload)
			log.Printf("SSH: exec request: %s", payload.Command)
			go func() {
				cmd := exec.Command("/bin/sh", "-c", payload.Command)
				if u, err := user.Lookup(username); err == nil {
					setCmdUser(cmd, u, username)
				}
				cmd.Stdin = nil
				cmd.Stdout, cmd.Stderr = channel, channel
				err := cmd.Run()
				log.Printf("SSH: exec exited: %v", err)
				exitCode := getExitCode(err)
				if w, ok := channel.(interface{ CloseWrite() error }); ok {
					_ = w.CloseWrite()
				}
				_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(exitCode)}))
				_ = channel.Close()
				conn.Close()
				log.Printf("SSH: exec channel and connection closed")
			}()
			req.Reply(true, nil)
		default:
			_ = req.Reply(false, nil)
		}
	}
}

func getExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return 1
}

// setCmdUser is implemented in platform-specific files.