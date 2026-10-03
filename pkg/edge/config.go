// pkg/edge/config.go (Modified)
package edge

import (
	"flag"
	"fmt"
	"n2n-go/pkg/protocol"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// stringSliceFlag implements flag.Value for []string CLI args.
type stringSliceFlag struct {
	value *[]string
}

func (f *stringSliceFlag) String() string { return strings.Join(*f.value, ",") }
func (f *stringSliceFlag) Set(v string) error {
	*f.value = append(*f.value, v)
	return nil
}

// ParseListenAddr normalizes an "addr:port" listen specification in which
// BOTH parts are optional, and returns the combined "addr:port" form.
//
//	""            -> defaultAddr:defaultPort
//	":7778"       -> defaultAddr:7778   (addr omitted)
//	"7778"        -> defaultAddr:7778   (bare number reads as a port)
//	"0.0.0.0:9000"-> 0.0.0.0:9000
//	"[::1]:9000"  -> [::1]:9000         (bracketed IPv6)
//	"::1"         -> ::1:defaultPort    (bare IPv6 literal, no port)
//
// A bare number is read as a port rather than an address, because that is what
// someone typing `-P 7778` means; a non-numeric bare token is read as an address
// with the default port. IPv6 literals need care: a bare "::1" contains colons
// that would otherwise split into three fields, so anything with more than one
// colon and no brackets is treated as a host-less IPv6 address.
func ParseListenAddr(spec, defaultAddr, defaultPort string) (string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return defaultAddr + ":" + defaultPort, nil
	}

	var addr, port string
	switch {
	case strings.HasPrefix(spec, "["):
		// Bracketed IPv6, e.g. [::1]:9000 or [::1]
		end := strings.Index(spec, "]")
		if end < 0 {
			return "", fmt.Errorf("invalid listen address %q: missing ']' closing the IPv6 literal", spec)
		}
		addr = spec[1:end]
		rest := spec[end+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return "", fmt.Errorf("invalid listen address %q: expected ':port' after the IPv6 literal", spec)
			}
			port = rest[1:]
		}
		// Preserve the brackets so the result is a valid "host:port" string.
		if addr == "" {
			addr = defaultAddr
		} else {
			addr = "[" + addr + "]"
		}

	default:
		switch strings.Count(spec, ":") {
		case 0:
			if isAllDigits(spec) {
				port = spec
			} else {
				addr = spec
			}
		case 1:
			i := strings.Index(spec, ":")
			addr, port = spec[:i], spec[i+1:]
		default:
			// More than one colon and no brackets: a bare IPv6 literal.
			addr = spec
		}
	}

	if addr == "" {
		addr = defaultAddr
	}
	if port == "" {
		port = defaultPort
	}
	if !isAllDigits(port) {
		return "", fmt.Errorf("invalid listen address %q: port %q is not a number", spec, port)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return "", fmt.Errorf("invalid listen address %q: port %q is out of range 0-65535", spec, port)
	}
	return addr + ":" + port, nil
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

type Config struct {
	UDPBufferSize        int           `mapstructure:"udp_buffer_size"` // Use mapstructure for Viper
	EdgeID               string        `mapstructure:"edge_id"`
	Community            string        `mapstructure:"community"`
	TapName              string        `mapstructure:"tap_name"`
	LocalPort            int           `mapstructure:"local_port"`
	SupernodeAddr        string        `mapstructure:"supernode_addr"`
	HeartbeatInterval    time.Duration `mapstructure:"heartbeat_interval"`
	ProtocolVersion      uint8         `mapstructure:"protocol_version"`
	VerifyHash           bool          `mapstructure:"verify_hash"`
	EnableVFuze          bool          `mapstructure:"enable_vfuze"`
	ConfigFile           string        `mapstructure:"config_file"` // Path to the config file
	APIListenAddr        string        `mapstructure:"api_listen_address"`
	EncryptionPassphrase string        `mapstructure:"encryption_passphrase"`
	CompressPayload      bool          `mapstructure:"compress_payload"`

	// WS configuration
	WSEnabled bool `mapstructure:"ws_enabled"`

	// WSS configuration
	SupernodeURL string `mapstructure:"supernode_url" env:"N2N_SUPERNODE_URL"`
	WSSCert      string `mapstructure:"wss_cert" env:"N2N_WSS_CERT"`
	WSSKey       string `mapstructure:"wss_key" env:"N2N_WSS_KEY"`
	WSSEnabled   bool   `mapstructure:"wss_enabled"`
	ProxyURL     string `mapstructure:"proxy_url" env:"N2N_PROXY_URL"`
	PreferIPv6   bool   `mapstructure:"prefer_ipv6" env:"N2N_PREFER_IPV6"`

	// P2P configuration
	P2PListenAddr string `mapstructure:"p2p_listen_addr"`
	P2PListenPort int    `mapstructure:"p2p_listen_port"`

	// STUN configuration
	STUNServers []string `mapstructure:"stun_servers"`

	// DisableAssistedAddrs stops the edge from advertising its own LAN
	// addresses to the relay (FRP parity: natHole.disableAssistedAddrs).
	//
	// The addresses are what let two peers on the same LAN find each other
	// directly instead of hairpinning through the local router. Turn this
	// off only when the extra sendto per address is measurably harmful -- the
	// peer simply skips them, so the worst case is a slightly slower punch,
	// not a failure. Leaving it on costs nothing in the common case: a host
	// with a single interface contributes exactly one address, and the peer
	// reaches it in the first sendto of the first round.
	DisableAssistedAddrs bool `mapstructure:"disable_assisted_addrs" env:"N2N_DISABLE_ASSISTED_ADDRS"`

	// P2P keepalive configuration
	//
	// A UDP NAT mapping expires when nothing is sent through it, typically
	// after 30s-2min depending on the gateway. When ours expired, the peer
	// could no longer reach us: its ARP replies went out over P2P and were
	// dropped, our ARP entry went INCOMPLETE, and the tunnel was dead even
	// though it still reported FullDuplex. Sending something on a timer
	// keeps the mapping open.
	//
	// KeepAliveInterval must be comfortably shorter than the shortest NAT
	// idle timeout in the path. FRP does not rely on this for the mapping —
	// its yamux keepalive is 10s but its KCP layer retransmits underneath —
	// so it can be comparatively lazy (its 90s ticker is a reconnect check).
	// We have no such lower layer, so this value is the only thing holding
	// the mapping open; keep it conservative.
	//
	// 0 disables the keepalive entirely.
	KeepAliveInterval time.Duration `mapstructure:"p2p_keepalive_interval"`
	// KeepAliveTimeout is how long a peer may go without any inbound frame
	// before we stop trusting FullDuplex. FRP's analogue is yamux's
	// ConnectionWriteTimeout, applied to the ping/pong round trip. Must be
	// greater than KeepAliveInterval so a single lost keepalive does not
	// tear the state down.
	KeepAliveTimeout time.Duration `mapstructure:"p2p_keepalive_timeout"`
}

func DefaultConfig() *Config {
	return &Config{
		HeartbeatInterval: 30 * time.Second,
		ProtocolVersion:   protocol.VersionV,
		VerifyHash:        true,
		// VFuze is the fast path; ProtoV-only is the slow path. The CLI flag
		// already defaults to true, but this config default is what applies
		// when edge is started via a YAML config (or any path that does not
		// go through the CLI flag), so leaving it false meant the two entry
		// points disagreed.
		EnableVFuze:   true,
		UDPBufferSize: 8388608,
		TapName:       "n2n_tap0",
		LocalPort:     0,           // 0 means automatically assigned
		ConfigFile:    "edge.yaml", // Default config file name.
		APIListenAddr: ":7778",

		// WS defaults
		WSEnabled: false,

		// WSS defaults
		WSSEnabled:   false,
		ProxyURL:     "",
		SupernodeURL: "",
		WSSCert:      "",
		WSSKey:       "",

		// P2P defaults
		P2PListenAddr: "",
		P2PListenPort: 0, // 0 means auto-assigned

		// STUN defaults
		//
		// stun.easyvoip.com is listed first on purpose: it is the server
		// FRP uses (frp pkg/config/v1/client.go DefaultNatHoleSTUNServer),
		// and it is the only one verified to answer from both edge hosts.
		// The Google STUN endpoints time out here — the cloud NAT swallows
		// their replies — which left pubSocket stale and made every hole
		// punch target a dead address. Keep them as fallbacks only.
		// The list is ordered by observed reachability from the edge hosts,
		// because DiscoverWithClassification walks it serially and returns the
		// LAST error: an unreachable server first is invisible, and three dead
		// entries ahead of a live one cost 15s per refresh.
		//
		// Re-verified 2026-10-01 by sending a real BindingRequest and checking
		// for a 0101 magic-cookie answer: nextcloud, miwifi and voipbuster all
		// answered; the Google endpoints (and easyvoip, which used to be the
		// only verified one) now time out from both hosts. That is what left
		// the periodic refresh reporting "STUN discovery failed" on every tick
		// -- the refresh ran correctly but had nothing to discover with.
		STUNServers: []string{
			"stun.nextcloud.com:443",
			"stun.miwifi.com:3478",
			"stun.voipbuster.com:3478",
			"stun.easyvoip.com:3478",
			"stun.l.google.com:19302",
			"stun1.l.google.com:19302",
		},

		// P2P keepalive defaults
		//
		// FRP uses a 10s yamux keepalive (client/visitor/xtcp.go:351) and a
		// 90s tunnel re-check (MinRetryInterval, default 90). We mirror the
		// 10s for the mapping, but the timeout is 3x rather than
		// ConnectionWriteTimeout, so one dropped keepalive amid normal
		// jitter does not drop FullDuplex.
		KeepAliveInterval: 10 * time.Second,
		KeepAliveTimeout:  30 * time.Second,
	}
}

// LoadConfig
// LoadConfig loads configuration from file, environment, and flags, in that order of precedence.
func LoadConfig(parseFlags bool) (*Config, error) {
	cfg := DefaultConfig()

	// Use Viper to load configuration
	viper.SetConfigName(cfg.ConfigFile)  // name of config file (without extension)
	viper.SetConfigType("yaml")          // REQUIRED if the config file does not have the extension in the name
	viper.AddConfigPath(".")             // look for config in the working directory
	viper.AddConfigPath("/etc/n2n-go/")  // path to look for the config file in
	viper.AddConfigPath("$HOME/.n2n-go") // call multiple times to add many search paths
	viper.SetEnvPrefix("N2N")            // will be uppercased automatically, N2N_...
	viper.AutomaticEnv()                 // read in environment variables that match

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			// Config file was found but another error was produced
			return nil, err
		}
		// Config file not found; ignore error if desired
	}

	// Print config file path and content for debugging
	if cfgPath := viper.ConfigFileUsed(); cfgPath != "" {
		fmt.Printf("Using config file: %s\n", cfgPath)
		if data, err := os.ReadFile(cfgPath); err == nil {
			fmt.Printf("Config content:\n%s\n", string(data))
		} else {
			fmt.Printf("Failed to read config file: %v\n", err)
		}
	}

	if parseFlags {
		// Bind command-line flags to Viper
		// This is where we connect our flags to our config struct
		flag.StringVar(&cfg.ConfigFile, "config", cfg.ConfigFile, "Path to the configuration file")
		flag.StringVar(&cfg.EdgeID, "id", cfg.EdgeID, "Unique edge identifier (defaults to hostname if omitted)")
		flag.StringVar(&cfg.Community, "community", cfg.Community, "Community name")
		flag.StringVar(&cfg.TapName, "tap", cfg.TapName, "TAP interface name")
		flag.IntVar(&cfg.LocalPort, "port", cfg.LocalPort, "Local UDP port (0 for system-assigned)")
		flag.BoolVar(&cfg.EnableVFuze, "enableFuze", cfg.EnableVFuze, "enable fuze fastpath")
		flag.StringVar(&cfg.SupernodeAddr, "supernode", cfg.SupernodeAddr, "Supernode address (host:port)")
		flag.DurationVar(&cfg.HeartbeatInterval, "heartbeat", cfg.HeartbeatInterval, "Heartbeat interval")
		flag.IntVar(&cfg.UDPBufferSize, "udpbuffersize", cfg.UDPBufferSize, "UDP BUffer Sizes")
		flag.StringVar(&cfg.APIListenAddr, "api-listen", cfg.APIListenAddr, "API listen address")
		flag.StringVar(&cfg.EncryptionPassphrase, "encryption-passphrase", cfg.EncryptionPassphrase, "Passphrase to encryption key derivation")
		flag.BoolVar(&cfg.CompressPayload, "compress-payload", cfg.CompressPayload, "Add zstd fast compression/decompression to data packets")
		flag.StringVar(&cfg.P2PListenAddr, "p2p-listen-addr", cfg.P2PListenAddr, "P2P UDP listen address (empty = auto-detect)")
		flag.IntVar(&cfg.P2PListenPort, "p2p-listen-port", cfg.P2PListenPort, "P2P UDP listen port (0 = system-assigned)")
		flag.Var(&stringSliceFlag{&cfg.STUNServers}, "stun-servers", "STUN servers for NAT traversal (comma-separated)")
		flag.BoolVar(&cfg.DisableAssistedAddrs, "nat-hole-disable-assisted-addrs", false, "Do not advertise this edge's LAN addresses to the relay (FRP parity: natHole.disableAssistedAddrs). The addresses let a peer on the same LAN address this machine directly instead of hairpinning through the local router")

		flag.Parse() // MUST call this to parse the flags
	}
	// Unmarshal the config into our struct.
	if err := viper.Unmarshal(cfg); err != nil {
		return nil, err
	}

	// Handle defaults that Viper can't.
	if cfg.EdgeID == "" {
		h, err := os.Hostname()
		if err != nil {
			return nil, err // We MUST have an edge ID
		}
		cfg.EdgeID = h
	}
	//If localport is not in config use default
	if cfg.LocalPort == 0 {
		if viper.IsSet("local_port") {
			cfg.LocalPort = viper.GetInt("local_port")
		}
	}

	return cfg, nil
}
