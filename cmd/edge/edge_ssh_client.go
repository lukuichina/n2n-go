// cmd/edge/edge_ssh_client.go
// SSH/SCP/SFTP client commands for n2n-go edge, modeled after usque.
package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// loadPrivateKey reads an SSH private key file and returns an AuthMethod.
func loadPrivateKey(path string) (ssh.AuthMethod, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		// Try with passphrase prompt
		if _, ok := err.(*ssh.PassphraseMissingError); ok {
			fmt.Fprintf(os.Stderr, "Enter passphrase for key %s: ", path)
			pass, err := term.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				return nil, err
			}
			fmt.Fprintln(os.Stderr)
			signer, err = ssh.ParsePrivateKeyWithPassphrase(data, pass)
			if err != nil {
				return nil, fmt.Errorf("parse key: %w", err)
			}
		} else {
			return nil, fmt.Errorf("parse key: %w", err)
		}
	}
	return ssh.PublicKeys(signer), nil
}

// buildAuthMethods constructs SSH auth methods from password and/or identity file.
func buildAuthMethods(password, identityPath string) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	if identityPath != "" {
		m, err := loadPrivateKey(identityPath)
		if err != nil {
			return nil, err
		}
		methods = append(methods, m)
	}
	if password != "" {
		methods = append(methods, ssh.Password(password))
	}
	if len(methods) == 0 {
		return nil, fmt.Errorf("no authentication method provided (use -w password or -i identity)")
	}
	return methods, nil
}

// sshClientCommand implements `edge ssh [user@]host[:port] [command]`
var sshClientCommand = &cli.Command{
	Name:      "ssh",
	Usage:     "SSH to a peer edge (interactive shell or remote command)",
	ArgsUsage: "[user@]host[:port] [command]",
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "user", Aliases: []string{"l"}, Value: "root", Usage: "SSH username"},
		&cli.IntFlag{Name: "port", Aliases: []string{"p"}, Value: 22, Usage: "SSH port"},
		&cli.StringFlag{Name: "password", Aliases: []string{"w"}, Usage: "SSH password"},
		&cli.StringFlag{Name: "identity", Aliases: []string{"i"}, Usage: "Path to SSH private key file"},
		&cli.IntFlag{Name: "keepalive", Value: 30, Usage: "Keepalive interval in seconds (0 to disable)"},
	},
	Action: sshClientCmd,
}

func sshClientCmd(c *cli.Context) error {
	// Check for help flag in args to avoid terminal mess
	for _, a := range os.Args {
		if a == "-h" || a == "--help" {
			return nil
		}
	}
	target := c.Args().First()
	command := ""
	if c.Args().Len() > 1 {
		command = strings.Join(c.Args().Slice()[1:], " ")
	}

	user := c.String("user")
	host := target
	port := c.Int("port")

	// Parse user@host:port
	if idx := strings.Index(target, "@"); idx != -1 {
		user = target[:idx]
		host = target[idx+1:]
	}
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		portStr := host[idx+1:]
		var portNum int
		n, _ := fmt.Sscanf(portStr, "%d", &portNum)
		if n == 1 && portNum > 0 {
			port = portNum
			host = host[:idx]
		}
	}

	password := c.String("password")
	if password == "" {
		fmt.Fprintf(os.Stderr, "SSH password for %s@%s: ", user, host)
		pw, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return fmt.Errorf("read password: %w", err)
		}
		password = string(pw)
		fmt.Fprintln(os.Stderr)
		if password == "" {
			return fmt.Errorf("password cannot be empty")
		}
	}

	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()

	authMethods, err := buildAuthMethods(password, c.String("identity"))
	if err != nil {
		return err
	}
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * 1e9,
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		return fmt.Errorf("ssh handshake: %w", err)
	}
	defer sshConn.Close()
	client := ssh.NewClient(sshConn, chans, reqs)

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("new session: %w", err)
	}
	defer session.Close()

	// Terminal setup for interactive mode
	if command == "" {
		fd := int(os.Stdin.Fd())
		oldState, err := term.MakeRaw(fd)
		if err == nil {
			defer term.Restore(fd, oldState)
		}
		modes := ssh.TerminalModes{ssh.ECHO: 1}
		w, h, _ := term.GetSize(fd)
		if w == 0 {
			w, h = 80, 24
		}
		session.RequestPty("xterm-256color", h, w, modes)
	}

	stdin, _ := session.StdinPipe()
	stdout, _ := session.StdoutPipe()
	stderr, _ := session.StderrPipe()

	if command != "" {
		if err := session.Start(command); err != nil {
			return err
		}
	} else {
		if err := session.Shell(); err != nil {
			return err
		}
	}

	go io.Copy(stdin, os.Stdin)
	go io.Copy(os.Stdout, stdout)
	go io.Copy(os.Stderr, stderr)

	// Handle terminal resize in interactive mode
	if command == "" {
		fd := int(os.Stdin.Fd())
		go func() {
			// Poll for terminal size changes
			lastW, lastH, _ := term.GetSize(fd)
			for {
				w, h, err := term.GetSize(fd)
				if err != nil {
					return
				}
				if w != lastW || h != lastH {
					session.WindowChange(h, w)
					lastW, lastH = w, h
				}
				// Sleep briefly
				time.Sleep(200 * time.Millisecond)
			}
		}()
	}

	return session.Wait()
}

// scpClientCommand implements `edge scp source dest`
var scpClientCommand = &cli.Command{
	Name:      "scp",
	Usage:     "Copy files to/from a peer edge via SCP",
	ArgsUsage: "source dest  (source/dest: [user@]host[:port]:path or local path)",
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "user", Aliases: []string{"l"}, Value: "root", Usage: "SSH username"},
		&cli.IntFlag{Name: "port", Aliases: []string{"P"}, Value: 22, Usage: "SSH port"},
		&cli.StringFlag{Name: "password", Aliases: []string{"w"}, Usage: "SSH password"},
		&cli.StringFlag{Name: "identity", Aliases: []string{"i"}, Usage: "Path to SSH private key file"},
		&cli.BoolFlag{Name: "recursive", Aliases: []string{"r"}, Usage: "Recursively copy entire directories"},
	},
	Action: scpClientCmd,
}

func scpClientCmd(c *cli.Context) error {
	for _, a := range os.Args {
		if a == "-h" || a == "--help" {
			return nil
		}
	}
	if c.Args().Len() < 2 {
		return fmt.Errorf("usage: scp [-P port] [-w password] source dest")
	}
	src := c.Args().Get(0)
	dst := c.Args().Get(1)

	// Determine which side is remote (contains :)
	remoteSrc := strings.Contains(src, ":")
	remoteDst := strings.Contains(dst, ":")

	if !remoteSrc && !remoteDst {
		return fmt.Errorf("scp: at least one of source/dest must be remote (user@host:path)")
	}
	if remoteSrc && remoteDst {
		return fmt.Errorf("scp: both source and dest are remote (not supported)")
	}

	var remoteSpec, localPath string
	var download bool
	if remoteSrc {
		remoteSpec = src
		localPath = dst
		download = true
	} else {
		remoteSpec = dst
		localPath = src
		download = false
	}

	// Parse [user@]host[:port]:path
	user := c.String("user")
	host := remoteSpec
	port := c.Int("port")
	remotePath := ""
	// Split user@
	if idx := strings.Index(host, "@"); idx != -1 {
		user = host[:idx]
		host = host[idx+1:]
	}
	// Now host may be "host:port:path" or "host:path"
	// Find the path separator (last colon followed by /)
	if idx := strings.Index(host, ":"); idx != -1 {
		rest := host[idx+1:]
		// Check if rest contains another colon (port:path) or is port:path
		if colonIdx := strings.Index(rest, ":"); colonIdx != -1 {
			// host:port:path
			fmt.Sscanf(rest[:colonIdx], "%d", &port)
			remotePath = rest[colonIdx+1:]
			host = host[:idx]
		} else if strings.HasPrefix(rest, "/") {
			// host:path
			remotePath = rest
			host = host[:idx]
		} else {
			// Try to parse as port number; if it fails, treat as relative path
			var portNum int
			n, _ := fmt.Sscanf(rest, "%d", &portNum)
			if n == 1 && portNum > 0 {
				port = portNum
				host = host[:idx]
			} else {
				// Relative path (e.g., "a.txt")
				remotePath = rest
				host = host[:idx]
			}
		}
	}

	password := c.String("password")
	if password == "" {
		fmt.Fprintf(os.Stderr, "SSH password for %s@%s: ", user, host)
		pw, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return err
		}
		password = string(pw)
		fmt.Fprintln(os.Stderr)
		if password == "" {
			return fmt.Errorf("password cannot be empty")
		}
	}

	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()

	authMethods, err := buildAuthMethods(password, c.String("identity"))
	if err != nil {
		return err
	}
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		return fmt.Errorf("ssh: %w", err)
	}
	defer sshConn.Close()
	client := ssh.NewClient(sshConn, chans, reqs)

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return fmt.Errorf("sftp: %w", err)
	}
	defer sftpClient.Close()

	recursive := c.Bool("recursive")
	if download {
		// Check if remote path is a directory
		remoteInfo, err := sftpClient.Stat(remotePath)
		isDir := err == nil && remoteInfo.IsDir()
		if isDir && !recursive {
			return fmt.Errorf("remote path is a directory; use -r for recursive copy")
		}
		if isDir {
			// Recursive download
			return scpDownloadDir(sftpClient, remotePath, localPath)
		}
		// If localPath is a directory, use remote filename
		if info, err := os.Stat(localPath); err == nil && info.IsDir() {
			parts := strings.Split(remotePath, "/")
			name := parts[len(parts)-1]
			if strings.HasSuffix(localPath, "/") {
				localPath = localPath + name
			} else {
				localPath = localPath + "/" + name
			}
		}
		srcFile, err := sftpClient.Open(remotePath)
		if err != nil {
			return fmt.Errorf("open remote: %w", err)
		}
		defer srcFile.Close()
		fi, _ := srcFile.Stat()
		dstFile, err := os.Create(localPath)
		if err != nil {
			return fmt.Errorf("create local: %w", err)
		}
		defer dstFile.Close()
		pw := &progressWriter{total: fi.Size(), label: remoteSpec}
		n, err := io.Copy(io.MultiWriter(dstFile, pw), srcFile)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		fmt.Printf("%s -> %s (%d bytes)\n", remoteSpec, localPath, n)
	} else {
		// Check if local path is a directory
		localInfo, err := os.Stat(localPath)
		isDir := err == nil && localInfo.IsDir()
		if isDir && !recursive {
			return fmt.Errorf("local path is a directory; use -r for recursive copy")
		}
		if isDir {
			// Recursive upload
			return scpUploadDir(sftpClient, localPath, remotePath)
		}
		srcFile, err := os.Open(localPath)
		if err != nil {
			return fmt.Errorf("open local: %w", err)
		}
		defer srcFile.Close()
		fi, _ := srcFile.Stat()
		dstFile, err := sftpClient.Create(remotePath)
		if err != nil {
			return fmt.Errorf("create remote: %w", err)
		}
		defer dstFile.Close()
		pw := &progressWriter{total: fi.Size(), label: localPath}
		n, err := io.Copy(io.MultiWriter(dstFile, pw), srcFile)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		fmt.Printf("%s -> %s (%d bytes)\n", localPath, remoteSpec, n)
	}
	return nil
}

// progressWriter wraps an io.Writer to display transfer progress.
type progressWriter struct {
	total   int64
	written int64
	label   string
}

func (p *progressWriter) Write(b []byte) (int, error) {
	n := len(b)
	p.written += int64(n)
	if p.total > 0 {
		pct := float64(p.written) / float64(p.total) * 100
		fmt.Fprintf(os.Stderr, "\r%s: %d/%d bytes (%.1f%%)", p.label, p.written, p.total, pct)
	} else {
		fmt.Fprintf(os.Stderr, "\r%s: %d bytes", p.label, p.written)
	}
	return n, nil
}

// scpDownloadDir recursively downloads a remote directory.
func scpDownloadDir(sftpClient *sftp.Client, remoteDir, localDir string) error {
	if err := os.MkdirAll(localDir, 0755); err != nil {
		return err
	}
	entries, err := sftpClient.ReadDir(remoteDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		remotePath := remoteDir + "/" + entry.Name()
		localPath := localDir + "/" + entry.Name()
		if entry.IsDir() {
			if err := scpDownloadDir(sftpClient, remotePath, localPath); err != nil {
				return err
			}
		} else {
			srcFile, err := sftpClient.Open(remotePath)
			if err != nil {
				return err
			}
			dstFile, err := os.Create(localPath)
			if err != nil {
				srcFile.Close()
				return err
			}
			n, err := io.Copy(dstFile, srcFile)
			srcFile.Close()
			dstFile.Close()
			if err != nil {
				return err
			}
			fmt.Printf("%s -> %s (%d bytes)\n", remotePath, localPath, n)
		}
	}
	fmt.Printf("directory %s downloaded\n", remoteDir)
	return nil
}

// scpUploadDir recursively uploads a local directory.
func scpUploadDir(sftpClient *sftp.Client, localDir, remoteDir string) error {
	if err := sftpClient.MkdirAll(remoteDir); err != nil {
		return err
	}
	entries, err := os.ReadDir(localDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		localPath := localDir + "/" + entry.Name()
		remotePath := remoteDir + "/" + entry.Name()
		if entry.IsDir() {
			if err := scpUploadDir(sftpClient, localPath, remotePath); err != nil {
				return err
			}
		} else {
			srcFile, err := os.Open(localPath)
			if err != nil {
				return err
			}
			dstFile, err := sftpClient.Create(remotePath)
			if err != nil {
				srcFile.Close()
				return err
			}
			n, err := io.Copy(dstFile, srcFile)
			srcFile.Close()
			dstFile.Close()
			if err != nil {
				return err
			}
			fmt.Printf("%s -> %s (%d bytes)\n", localPath, remotePath, n)
		}
	}
	fmt.Printf("directory %s uploaded\n", localDir)
	return nil
}

// sftpClientCommand implements `edge sftp [user@]host[:port]`
var sftpClientCommand = &cli.Command{
	Name:      "sftp",
	Usage:     "Interactive SFTP to a peer edge, or copy files (source dest)",
	ArgsUsage: "[user@]host[:port] [command] | source dest",
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "user", Aliases: []string{"l"}, Value: "root", Usage: "SSH username"},
		&cli.IntFlag{Name: "port", Aliases: []string{"P"}, Value: 22, Usage: "SSH port"},
		&cli.StringFlag{Name: "password", Aliases: []string{"w"}, Usage: "SSH password"},
		&cli.StringFlag{Name: "identity", Aliases: []string{"i"}, Usage: "Path to SSH private key file"},
	},
	Action: sftpClientCmd,
}

// resolveSftpPath resolves a path against the current directory.
func resolveSftpPath(curDir, path string) string {
	if curDir == "." {
		curDir = "/"
	}
	if path == "." {
		return curDir
	}
	if strings.HasPrefix(path, "/") {
		return path
	}
	if curDir == "/" {
		return "/" + path
	}
	return curDir + "/" + path
}

func sftpClientCmd(c *cli.Context) error {
	for _, a := range os.Args {
		if a == "-h" || a == "--help" {
			return nil
		}
	}
	if c.Args().Len() >= 2 {
		// Check if second arg looks like a command (not a file path)
		second := c.Args().Get(1)
		if !strings.Contains(second, "/") && !strings.Contains(second, ".") && !strings.Contains(second, "\\") {
			// Treat as SSH command execution
			return sshClientCmd(c)
		}
		// Delegate to scp transfer logic
		return scpClientCmd(c)
	}

	target := c.Args().First()
	user := c.String("user")
	host := target
	port := c.Int("port")

	if idx := strings.Index(target, "@"); idx != -1 {
		user = target[:idx]
		host = target[idx+1:]
	}
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		portStr := host[idx+1:]
		var portNum int
		n, _ := fmt.Sscanf(portStr, "%d", &portNum)
		if n == 1 && portNum > 0 {
			port = portNum
			host = host[:idx]
		}
	}

	password := c.String("password")
	if password == "" {
		fmt.Fprintf(os.Stderr, "SSH password for %s@%s: ", user, host)
		pw, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return err
		}
		password = string(pw)
		fmt.Fprintln(os.Stderr)
		if password == "" {
			return fmt.Errorf("password cannot be empty")
		}
	}

	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()

	authMethods, err := buildAuthMethods(password, c.String("identity"))
	if err != nil {
		return err
	}
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		return fmt.Errorf("ssh: %w", err)
	}
	defer sshConn.Close()
	client := ssh.NewClient(sshConn, chans, reqs)

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return fmt.Errorf("sftp: %w", err)
	}
	defer sftpClient.Close()

	// Interactive SFTP shell
	fmt.Println("SFTP connected. Type 'help' for commands, 'exit' to quit.")
	// Track current remote directory; resolve "." against server working dir
	curDir := "."
	if rp, err := sftpClient.RealPath("."); err == nil {
		curDir = rp
	}
	// Simple REPL
	scanner := newScanner(os.Stdin)
	for {
		fmt.Print("sftp> ")
		line, ok := scanner.readLine()
		if !ok {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line == "exit" || line == "quit" {
			break
		}
		if line == "help" {
			fmt.Println("  ls [path]     - list directory")
			fmt.Println("  cd path       - change directory")
			fmt.Println("  get remote local - download file")
			fmt.Println("  put local remote - upload file")
			fmt.Println("  exit          - quit")
			continue
		}
		parts := strings.Fields(line)
		switch parts[0] {
		case "ls":
			path := curDir
			if len(parts) > 1 {
				path = resolveSftpPath(curDir, parts[1])
			}
			entries, err := sftpClient.ReadDir(path)
			if err != nil {
				fmt.Println("error:", err)
				continue
			}
			for _, e := range entries {
				fmt.Printf("%s  %d  %s\n", e.Mode(), e.Size(), e.Name())
			}
		case "cd":
			if len(parts) < 2 {
				fmt.Println("usage: cd path")
				continue
			}
			newPath := resolveSftpPath(curDir, parts[1])
			// Verify it's a directory
			info, err := sftpClient.Stat(newPath)
			if err != nil {
				fmt.Println("error:", err)
				continue
			}
			if !info.IsDir() {
				fmt.Println("error: not a directory")
				continue
			}
			curDir = newPath
			fmt.Println("Changed to", curDir)
		case "get":
			if len(parts) < 3 {
				fmt.Println("usage: get remote local")
				continue
			}
			remotePath := resolveSftpPath(curDir, parts[1])
			src, _ := sftpClient.Open(remotePath)
			defer src.Close()
			dst, err := os.Create(parts[2])
			if err != nil {
				fmt.Println("error:", err)
				continue
			}
			defer dst.Close()
			n, _ := io.Copy(dst, src)
			fmt.Printf("downloaded %d bytes\n", n)
		case "put":
			if len(parts) < 3 {
				fmt.Println("usage: put local remote")
				continue
			}
			src, err := os.Open(parts[1])
			if err != nil {
				fmt.Println("error:", err)
				continue
			}
			defer src.Close()
			dst, err := sftpClient.Create(resolveSftpPath(curDir, parts[2]))
			if err != nil {
				fmt.Println("error:", err)
				continue
			}
			defer dst.Close()
			n, _ := io.Copy(dst, src)
			fmt.Printf("uploaded %d bytes\n", n)
		default:
			fmt.Println("unknown command:", parts[0])
		}
	}
	return nil
}

// scanner wraps bufio for simple line reading
type lineScanner struct {
	r io.Reader
}

func newScanner(r io.Reader) *lineScanner {
	return &lineScanner{r: r}
}

func (s *lineScanner) readLine() (string, bool) {
	buf := make([]byte, 4096)
	n, err := s.r.Read(buf)
	if err != nil || n == 0 {
		return "", false
	}
	line := string(buf[:n])
	// trim newline
	line = strings.TrimRight(line, "\n\r")
	return line, true
}

var _ = log.Println
