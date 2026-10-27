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

	"github.com/pkg/sftp"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// sshClientCommand implements `edge ssh [user@]host[:port] [command]`
var sshClientCommand = &cli.Command{
	Name:  "ssh",
	Usage: "SSH to a peer edge (interactive shell or remote command)",
	ArgsUsage: "[user@]host[:port] [command]",
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "user", Aliases: []string{"l"}, Value: "root", Usage: "SSH username"},
		&cli.IntFlag{Name: "port", Aliases: []string{"p"}, Value: 22, Usage: "SSH port"},
		&cli.StringFlag{Name: "password", Aliases: []string{"w"}, Usage: "SSH password"},
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
		fmt.Sscanf(host[idx+1:], "%d", &port)
		host = host[:idx]
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

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()

	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
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

	return session.Wait()
}

// scpClientCommand implements `edge scp source dest`
var scpClientCommand = &cli.Command{
	Name:  "scp",
	Usage: "Copy files to/from a peer edge via SCP",
	ArgsUsage: "source dest  (source/dest: [user@]host[:port]:path or local path)",
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "user", Aliases: []string{"l"}, Value: "root", Usage: "SSH username"},
		&cli.IntFlag{Name: "port", Aliases: []string{"P"}, Value: 22, Usage: "SSH port"},
		&cli.StringFlag{Name: "password", Aliases: []string{"w"}, Usage: "SSH password"},
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
			// Could be host:port (no path) - shouldn't happen
			fmt.Sscanf(rest, "%d", &port)
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

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()

	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
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

	if download {
		// If localPath is a directory, use remote filename
		if info, err := os.Stat(localPath); err == nil && info.IsDir() {
			// Extract filename from remote path
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
		dstFile, err := os.Create(localPath)
		if err != nil {
			return fmt.Errorf("create local: %w", err)
		}
		defer dstFile.Close()
		n, err := io.Copy(dstFile, srcFile)
		if err != nil {
			return err
		}
		fmt.Printf("%s -> %s (%d bytes)\n", remoteSpec, localPath, n)
	} else {
		srcFile, err := os.Open(localPath)
		if err != nil {
			return fmt.Errorf("open local: %w", err)
		}
		defer srcFile.Close()
		dstFile, err := sftpClient.Create(remotePath)
		if err != nil {
			return fmt.Errorf("create remote: %w", err)
		}
		defer dstFile.Close()
		n, err := io.Copy(dstFile, srcFile)
		if err != nil {
			return err
		}
		fmt.Printf("%s -> %s (%d bytes)\n", localPath, remoteSpec, n)
	}
	return nil
}

// sftpClientCommand implements `edge sftp [user@]host[:port]`
var sftpClientCommand = &cli.Command{
	Name:  "sftp",
	Usage: "Interactive SFTP to a peer edge, or copy files (source dest)",
	ArgsUsage: "[user@]host[:port] [command] | source dest",
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "user", Aliases: []string{"l"}, Value: "root", Usage: "SSH username"},
		&cli.IntFlag{Name: "port", Aliases: []string{"P"}, Value: 22, Usage: "SSH port"},
		&cli.StringFlag{Name: "password", Aliases: []string{"w"}, Usage: "SSH password"},
	},
	Action: sftpClientCmd,
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
	user := "root"
	host := target
	port := 22

	if idx := strings.Index(target, "@"); idx != -1 {
		user = target[:idx]
		host = target[idx+1:]
	}
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		fmt.Sscanf(host[idx+1:], "%d", &port)
		host = host[:idx]
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

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()

	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
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
			path := "."
			if len(parts) > 1 {
				path = parts[1]
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
			fmt.Println("cd: not supported in this version, use absolute paths")
		case "get":
			if len(parts) < 3 {
				fmt.Println("usage: get remote local")
				continue
			}
			src, _ := sftpClient.Open(parts[1])
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
			dst, err := sftpClient.Create(parts[2])
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
