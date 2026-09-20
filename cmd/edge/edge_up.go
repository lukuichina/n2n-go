package main

import (
	"encoding/base64"
	"fmt"
	"n2n-go/pkg/edge"
	"n2n-go/pkg/log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/urfave/cli/v2"
)

// --- CLI Definition ---

var (
	// Define the 'logs' subcommand
	upCommand = &cli.Command{
		Name:        "up",
		Usage:       "starts edge instance",
		UsageText:   "up [args...]",
		Description: `starts edge instance`,
		Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "proxy-url",
			Aliases: []string{"p"},
			Usage:   "Proxy URL (http://, https://, socks5://, or socks5s://)",
		},
		&cli.StringFlag{
			Name:    "supernode",
			Aliases: []string{"s"},
			Usage:   "Supernode URL for WS/WSS (ws:// or wss://)",
		},
		&cli.StringFlag{
			Name:    "community",
			Aliases: []string{"c"},
			Usage:   "Community name",
		},
		&cli.StringFlag{
			Name:    "id",
			Aliases: []string{"i"},
			Usage:   "Edge identifier",
		},
		&cli.BoolFlag{
			Name:    "stdout-log",
			Aliases: []string{"l"},
			Usage:   "stdout-log",
		},
		&cli.BoolFlag{
			Name:  "ws",
			Usage: "Enable WS connection to supernode",
		},
		&cli.BoolFlag{
			Name:  "wss",
			Usage: "Enable WSS connection to supernode",
		},
		&cli.StringFlag{
			Name:  "wss-cert",
			Usage: "WSS client certificate file",
		},
		&cli.StringFlag{
			Name:  "wss-key",
			Usage: "WSS client key file",
		},
		&cli.StringFlag{
			Name:    "api-listen",
			Aliases: []string{"A"},
			Usage:   "Management API listen address (default: 127.0.0.1:7778)",
		},
		&cli.StringFlag{
			Name:    "config",
			Usage:   "Path to configuration file (default: edge.yaml)",
		},
		&cli.StringFlag{
			Name:    "tap",
			Aliases: []string{"t"},
			Usage:   "TAP interface name (default: n2n_tap0)",
		},
		&cli.IntFlag{
			Name:    "port",
			Aliases: []string{"P"},
			Usage:   "Local UDP port (default: 0, system-assigned)",
		},
		&cli.BoolFlag{
			Name:    "enableFuze",
			Aliases: []string{"F"},
			Usage:   "Enable VFuze fastpath (default: true)",
			Value:   true,
		},
		&cli.DurationFlag{
			Name:    "heartbeat",
			Aliases: []string{"H"},
			Usage:   "Heartbeat interval (default: 30s)",
			Value:   30 * time.Second,
		},
		&cli.IntFlag{
			Name:    "udpbuffersize",
			Aliases: []string{"b"},
			Usage:   "UDP buffer size (default: 8388608)",
			Value:   8388608,
		},
		&cli.StringFlag{
			Name:    "encryption-passphrase",
			Aliases: []string{"k"},
			Usage:   "Passphrase for encryption key derivation",
		},
		&cli.BoolFlag{
			Name:    "compress-payload",
			Aliases: []string{"C"},
			Usage:   "Enable Zstd compression for data payloads (default: false)",
		},
	},
		// Positional arg: supernode URL shortcut
		// Usage: ./edge up wss://host/n2n -l
		// Equivalent to: ./edge up -c default -s wss://host/n2n?community=default -l
		Action: upCmd,
	}
)

func upCmd(c *cli.Context) error {
	up(c)
	return nil
}
func up(c *cli.Context) {
	noSqlLogger := false
	if c.IsSet("stdout-log") {
		if c.Bool("stdout-log") {
			log.SetStd()
			noSqlLogger = true
		}
	}
	if !noSqlLogger {
		edge.EnsureEdgeLogger()
	}
	log.Printf("starting edge...")

	b, _ := base64.StdEncoding.DecodeString(banner)
	fmt.Printf(string(b), Version, BuildTime)

	cfg, err := edge.LoadConfig(false) // Load config using Viper (skip flag parsing, cli.Context handles flags)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	log.Printf("using config file %s", cfg.ConfigFile)

	// Positional arg shortcut: ./edge up wss://host/n2n -l
	// Equivalent to: ./edge up -c default -s wss://host/n2n?community=default -l
	if c.NArg() >= 1 {
		posURL := c.Args().Get(0)
		if posURL != "" {
			cfg.SupernodeURL = posURL
			if cfg.Community == "" {
				cfg.Community = "default"
			}
			log.Printf("positional supernode-url: %s (community=%s)", posURL, cfg.Community)
		}
	}

	if c.IsSet("community") {
		comm := c.String("community")
		if comm != "" {
			cfg.Community = comm
		}
	}

	if c.IsSet("id") {
		eid := c.String("id")
		if eid != "" {
			cfg.EdgeID = eid
		}
	}

	if c.IsSet("proxy-url") {
		cfg.ProxyURL = c.String("proxy-url")
	}

	if c.IsSet("supernode") {
		cfg.SupernodeURL = c.String("supernode")
	}

	// 自动构建 community 到 supernode-url
	// 支持用法：./edge up -c default -s wss://host/n2n -l
	// 自动构建为：wss://host/n2n?community=default
	// 如果 -c 未设置但 URL 中没有 ?community=，默认使用 default
	if cfg.SupernodeURL != "" && !strings.Contains(cfg.SupernodeURL, "?community=") {
		community := cfg.Community
		if community == "" {
			community = "default"
		}
		separator := "?"
		if strings.Contains(cfg.SupernodeURL, "?") {
			separator = "&"
		}
		cfg.SupernodeURL = cfg.SupernodeURL + separator + "community=" + community
		if cfg.Community == "" {
			cfg.Community = community
		}
		log.Printf("auto-appended community to supernode-url: %s", cfg.SupernodeURL)
	}

	// Auto-enable WS/WSS based on supernode URL scheme
	if cfg.SupernodeURL != "" {
		if strings.HasPrefix(cfg.SupernodeURL, "wss://") {
			cfg.WSSEnabled = true
		} else if strings.HasPrefix(cfg.SupernodeURL, "ws://") {
			cfg.WSEnabled = true
		}
	}

	if c.IsSet("ws") {
		cfg.WSEnabled = c.Bool("ws")
	}

	if c.IsSet("wss") {
		cfg.WSSEnabled = c.Bool("wss")
	}

	if c.IsSet("wss-cert") {
		cfg.WSSCert = c.String("wss-cert")
	}

	if c.IsSet("wss-key") {
		cfg.WSSKey = c.String("wss-key")
	}

	if c.IsSet("api-listen") {
		cfg.APIListenAddr = c.String("api-listen")
	}

	// --- Additional flags ---
	if c.IsSet("config") {
		cfg.ConfigFile = c.String("config")
	}
	if c.IsSet("tap") {
		cfg.TapName = c.String("tap")
	}
	if c.IsSet("port") {
		cfg.LocalPort = c.Int("port")
	}
	if c.IsSet("enableFuze") {
		cfg.EnableVFuze = c.Bool("enableFuze")
	}
	if c.IsSet("heartbeat") {
		cfg.HeartbeatInterval = c.Duration("heartbeat")
	}
	if c.IsSet("udpbuffersize") {
		cfg.UDPBufferSize = c.Int("udpbuffersize")
	}
	if c.IsSet("encryption-passphrase") {
		cfg.EncryptionPassphrase = c.String("encryption-passphrase")
	}
	if c.IsSet("compress-payload") {
		cfg.CompressPayload = c.Bool("compress-payload")
	}

	client, err := edge.NewEdgeClient(*cfg) // Pass the config struct
	if err != nil {
		log.Fatalf("Failed to create edge client: %v", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		log.Printf("Received signal %s, shutting down gracefully...", sig)
		client.Close()
		os.Exit(0)
	}()

	if err := client.InitialSetup(); err != nil {
		log.Printf("edge setup failed: %v", err)
		client.Close()
		os.Exit(127)
	}
	log.Printf("edge setup successful")
	udpPort := cfg.LocalPort
	if udpPort == 0 {
		if client.Conn != nil {
			udpPort = client.Conn.LocalAddr().(*net.UDPAddr).Port
		}
	}
	log.Printf("edge %s registered on local UDP port %d. TAP interface: %s",
		cfg.EdgeID, udpPort, cfg.TapName)
	headerFormat := "protoV"
	log.Printf("Using %s header format - protocol v%d", headerFormat, client.ProtocolVersion())
	log.Printf("edge node is running. Press Ctrl+C to stop.")

	client.Run() // Start the edge client.

	log.Printf("edge node has been shut down.")
	os.Exit(0)
}
