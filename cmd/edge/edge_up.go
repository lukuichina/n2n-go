package main

import (
	"encoding/base64"
	"fmt"
	"n2n-go/pkg/edge"
	"n2n-go/pkg/log"
	"n2n-go/pkg/p2p"
	"net"
	"os"
	"os/signal"
	"strconv"
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
				Aliases: []string{"x"},
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
				Usage:   "Management API listen endpoint, as `addr:port`. The addr may be omitted (defaults to 127.0.0.1) and the port may be omitted (defaults to 7778), so a bare `-A` yields 127.0.0.1:7778. Examples: `-A :9000`, `-A 9000`, `-A 0.0.0.0:9000`",
			},
			&cli.StringFlag{
				Name:  "config",
				Usage: "Path to configuration file (default: edge.yaml)",
			},
			&cli.StringFlag{
				Name:    "tap",
				Aliases: []string{"t"},
				Usage:   "TAP interface name (default: n2n_tap0)",
			},
			&cli.IntFlag{
				Name:    "port",
				Aliases: []string{"p"},
				Usage:   "Local UDP port (default: 0, system-assigned)",
			},
			&cli.StringFlag{
				Name:    "p2p-listen",
				Aliases: []string{"P"},
				Usage:   "P2P UDP listen endpoint for hole punching, as `addr:port`. The addr may be omitted (defaults to 0.0.0.0) and the port may be omitted (defaults to 0, system-assigned). Examples: `-P :7777`, `-P 7777`, `-P 10.0.0.5:7777`",
			},
			&cli.IntFlag{
				Name:  "nat-hole-probe-ttl",
				Usage: "IP TTL for the NAT-hole receiver's pre-mapping probe (default: 7). The probe exists to make the local NAT allocate a mapping towards the sender before the sender punches, and is deliberately low so the datagram never reaches the sender. 7 is FRP's value and is right for a consumer router, where the NAT lookup happens at hop 1 -- on a cloud network the EIP translation can sit further out, and a probe that dies before reaching it opens no mapping at all. Set this to at least the measured hop count to the peer, or 0 to disable the probe and send with the socket's normal TTL",
				Value: 7,
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
			&cli.BoolFlag{
				Name:    "ipv6-prefer",
				Aliases: []string{"6"},
				Usage:   "Dial IPv6 first instead of IPv4 first; the other family is only used if this one cannot be reached",
			},
			&cli.BoolFlag{
				Name:  "db-log",
				Usage: "Log into the SQLite database at /root/.n2n-go/edge.db instead of the console",
			},
			&cli.StringFlag{
				Name:    "socks5-listen",
				Aliases: []string{"S"},
				Usage:   "Run a SOCKS5 / HTTP proxy whose traffic is routed through this edge's TAP. `SPEC` is a proxy URL: `socks5` for the defaults, `socks5://HOST:PORT`, `http://[USER:PASS@]HOST:PORT`, or a bare `HOST:PORT`. An omitted address means 127.0.0.1 and an omitted port means 1080, so plain `socks5` gives 127.0.0.1:1080. One listener serves both SOCKS5 and HTTP. Omit the flag to run no proxy at all. `-L` and `-R` are the port-forwarding flags; this one is the proxy specifically",
			},
			&cli.StringSliceFlag{
				Name:    "port-forward",
				Aliases: []string{"L"},
				Usage:   "Local port forward: bind `BIND:PORT:TARGET:TPORT[/proto]` on this host and relay it to TARGET:TPORT, which is normally a service on another edge (proto is `tcp` by default, `udp` for stateless forwarding, `both` for one TCP plus one UDP listener). Repeatable. `-R` is the remote direction",
			},
			&cli.StringSliceFlag{
				Name:    "remote-forward",
				Aliases: []string{"R"},
				Usage:   "Remote port forward: listen on this edge's own virtual IP as `VIP:PORT:TARGET:TPORT[/proto]` and relay to TARGET:TPORT, which is normally a service outside the overlay. Repeatable. Peers reach the service at this edge's 100.64.0.x",
			},
			&cli.StringFlag{
				Name:  "socks5-policy",
				Value: "overlay",
				Usage: "Which destinations the proxy may reach: `overlay` (default) only serves addresses inside the TAP's own subnet, `any` also serves the internet through this host. `any` turns the edge into an egress proxy, and on a non-loopback address without credentials it is an open relay",
			},
			&cli.DurationFlag{
				Name:  "socks5-idle-timeout",
				Usage: "Close a proxied connection after this long with no traffic in either direction (default: 30m, 0 keeps the default). Raise it for long-lived idle tunnels such as an SSH session running without ServerAliveInterval",
			},
			&cli.StringFlag{
				Name:  "socks5-auth",
				Usage: "Require username/password authentication, as `user:pass`. Without it the proxy offers the SOCKS5 'no authentication required' method",
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
	// The console is the default sink, and --stdout-log/-l still selects it
	// explicitly for scripts that used to pass it.
	//
	// SQLite became the unconditional default at some point, and that moved
	// every log line off the terminal: the log file kept receiving the banner
	// and nothing else, and the only way to see what the edge was doing became
	// the edge logs subcommand. That is the opposite of what the flag's name
	// implies, and it is what a remote deployment actually wants -- an edge
	// that says nothing to stdout looks dead. So the sink is opt-in now:
	//
	//	./edge up -c myc -s wss://...          -> console
	//	./edge up -c myc -s wss://... -l       -> console (explicit)
	//	./edge up -c myc -s wss://... --db-log -> /root/.n2n-go/edge.db
	//
	// The `edge logs` command initialises the database itself (see
	// edge_logs.go), so a console-logging edge can still read an existing
	// edge.db -- it just does not write one.
	toStdout := true
	if c.Bool("db-log") {
		toStdout = false
	}
	if c.IsSet("stdout-log") && !c.Bool("stdout-log") {
		// --stdout-log=false used to mean "not stdout", i.e. the database.
		// Keep that spelling working now that it takes an explicit opt-in.
		toStdout = false
	}
	if toStdout {
		log.SetStd()
	} else {
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

	// Not gated on IsSet: this one has a non-zero default in the other
	// direction, and -6 is a plain switch, not a value.
	cfg.PreferIPv6 = c.Bool("ipv6-prefer")

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
	if c.IsSet("p2p-listen") {
		// One "addr:port" spec, both parts optional. Split it back into the
		// two config fields the P2P socket setup expects.
		normalized, err := edge.ParseListenAddr(c.String("p2p-listen"), "0.0.0.0", "0")
		if err != nil {
			log.Fatalf("invalid --p2p-listen value: %v", err)
		}
		host, portStr, _ := strings.Cut(normalized, ":")
		port, _ := strconv.Atoi(portStr)
		cfg.P2PListenAddr = host
		cfg.P2PListenPort = port
	}
	if c.IsSet("nat-hole-probe-ttl") {
		p2p.SetReceiverProbeIPTTL(c.Int("nat-hole-probe-ttl"))
		log.Printf("NAT hole receiver pre-mapping probe IP TTL set to %d (0 disables the probe)", p2p.ReceiverProbeIPTTL())
	}
	if c.IsSet("api-listen") {
		normalized, err := edge.ParseListenAddr(c.String("api-listen"), "127.0.0.1", "7778")
		if err != nil {
			log.Fatalf("invalid --api-listen value: %v", err)
		}
		cfg.APIListenAddr = normalized
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

	if c.IsSet("socks5-listen") {
		spec, err := edge.ParseProxyListenSpec(c.String("socks5-listen"))
		if err != nil {
			log.Fatalf("invalid -S/--socks5-listen value: %v", err)
		}
		cfg.Socks5ListenAddr = spec.Addr

		// Credentials: an explicit --socks5-auth wins, but only when it
		// actually carries a value. Testing IsSet alone is not enough -- cli
		// reports a flag that was never given as "set" when it has a default,
		// and c.String then hands back the empty default, which silently
		// throws away the password that was just parsed out of -S and leaves
		// an unauthenticated relay on a routable address.
		if v := c.String("socks5-auth"); v != "" {
			cfg.Socks5Auth = v
		} else if a := spec.Auth(); a != "" {
			cfg.Socks5Auth = a
		}

		authState := "disabled"
		if cfg.Socks5Auth != "" {
			authState = "enabled"
		}
		// Log the effective state, not the intent: the difference between
		// "credentials were typed" and "credentials are in force" is exactly
		// what is invisible when a tunnel unexpectedly has no auth on it.
		log.Printf("proxy ingress: %s (auth %s)", spec.Redacted(), authState)
	} else if v := c.String("socks5-auth"); v != "" {
		// --socks5-auth without -S is a configuration error, not a silent
		// no-op. Credentials without a listener to attach them to would
		// otherwise leave the operator believing an authenticated proxy is
		// running when nothing is listening at all.
		log.Fatalf("credentials given without a listener: --socks5-auth %q but no -S/--socks5-listen", v)
	}
	if v := c.String("socks5-policy"); v != "" {
		cfg.Socks5Policy = v
	}
	if c.IsSet("socks5-idle-timeout") {
		cfg.Socks5IdleTimeout = c.Duration("socks5-idle-timeout")
	}
	for _, raw := range c.StringSlice("port-forward") {
		specs, err := edge.ParsePortForwardSpec(raw)
		if err != nil {
			log.Fatalf("invalid -L/--port-forward value %q: %v", raw, err)
		}
		cfg.PortForwards = append(cfg.PortForwards, specs...)
	}
	for _, raw := range c.StringSlice("remote-forward") {
		specs, err := edge.ParsePortForwardSpec(raw)
		if err != nil {
			log.Fatalf("invalid -R/--remote-forward value %q: %v", raw, err)
		}
		cfg.RemoteForwards = append(cfg.RemoteForwards, specs...)
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
