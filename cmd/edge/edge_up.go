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
			Name:    "supernode-url",
			Aliases: []string{"s"},
			Usage:   "Supernode URL for WS/WSS (ws:// or wss://)",
		},
		&cli.StringFlag{
			Name:    "community",
			Aliases: []string{"c"},
			Usage:   "Community name",
		},
		&cli.StringFlag{
			Name:    "edge-id",
			Aliases: []string{"i"},
			Usage:   "edge-id EdgeName",
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
			Usage:   "Management API listen address (default: 127.0.0.1:7778)",
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

	if c.IsSet("edge-id") {
		eid := c.String("edge-id")
		if eid != "" {
			cfg.EdgeID = eid
		}
	}

	if c.IsSet("proxy-url") {
		cfg.ProxyURL = c.String("proxy-url")
	}

	if c.IsSet("supernode-url") {
		cfg.SupernodeURL = c.String("supernode-url")
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
