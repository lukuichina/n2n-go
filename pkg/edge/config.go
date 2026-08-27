// pkg/edge/config.go (Modified)
package edge

import (
	"flag"
	// "n2n-go/pkg/log"
	"n2n-go/pkg/protocol"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

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
	WSEnabled    bool   `mapstructure:"ws_enabled"`

	// WSS configuration
	SupernodeURL string `mapstructure:"supernode_url" env:"N2N_SUPERNODE_URL"`
	WSSCert      string `mapstructure:"wss_cert" env:"N2N_WSS_CERT"`
	WSSKey       string `mapstructure:"wss_key" env:"N2N_WSS_KEY"`
	WSSEnabled   bool   `mapstructure:"wss_enabled"`
}

func DefaultConfig() *Config {
	return &Config{
		HeartbeatInterval: 30 * time.Second,
		ProtocolVersion:   protocol.VersionV,
		VerifyHash:        true,
		EnableVFuze:       true,
		UDPBufferSize:     8192 * 8192,
		TapName:           "n2n_tap0",
		LocalPort:         0,           // 0 means automatically assigned
		ConfigFile:        "edge.yaml", // Default config file name.
		APIListenAddr:     ":7778",

		// WS defaults
		WSEnabled:    false,

		// WSS defaults
		WSSEnabled:   false,
		SupernodeURL: "",
		WSSCert:      "",
		WSSKey:       "",
	}
}

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

		// WSS flags
		flag.StringVar(&cfg.SupernodeURL, "supernode-url", cfg.SupernodeURL, "Supernode URL (ws:// or wss://)")
		flag.StringVar(&cfg.WSSCert, "wss-cert", cfg.WSSCert, "WSS client certificate file")
		flag.StringVar(&cfg.WSSKey, "wss-key", cfg.WSSKey, "WSS client key file")
		flag.BoolVar(&cfg.WSEnabled, "ws", cfg.WSEnabled, "Enable WS connection to supernode")
	flag.BoolVar(&cfg.WSSEnabled, "wss", cfg.WSSEnabled, "Enable WSS connection to supernode")

		flag.Parse() // MUST call this to parse the flags
	}
	
	// log.Printf("DEBUG config: after flag parse, SupernodeURL=%q, WSSEnabled=%v", cfg.SupernodeURL, cfg.WSSEnabled)
	// Save flag values before unmarshal (CLI flags should override config file)
	supernodeURL := cfg.SupernodeURL
	supernodeAddr := cfg.SupernodeAddr
	wssEnabled := cfg.WSSEnabled
	wssCert := cfg.WSSCert
	wssKey := cfg.WSSKey

	// Unmarshal the config into our struct.
	if err := viper.Unmarshal(cfg); err != nil {
		return nil, err
	}

	// log.Printf("DEBUG config: after restore, SupernodeURL=%q, WSSEnabled=%v", cfg.SupernodeURL, cfg.WSSEnabled)
	// Restore flag values (CLI flags override config file)
	if supernodeURL != "" {
		cfg.SupernodeURL = supernodeURL
	}
	if supernodeAddr != "" {
		cfg.SupernodeAddr = supernodeAddr
	}
	if wssEnabled {
		cfg.WSSEnabled = wssEnabled
	}
	if wssCert != "" {
		cfg.WSSCert = wssCert
	}
	if wssKey != "" {
		cfg.WSSKey = wssKey
	}

	// Handle defaults that Viper can't.
	
	// log.Printf("DEBUG config: before auto-enable, SupernodeURL=%q, WSEnabled=%v, WSSEnabled=%v", cfg.SupernodeURL, cfg.WSEnabled, cfg.WSSEnabled)
	// Auto-enable WS/WSS if SupernodeURL is set
	if cfg.SupernodeURL != "" {
		if strings.HasPrefix(cfg.SupernodeURL, "wss://") {
			cfg.WSSEnabled = true
		} else if strings.HasPrefix(cfg.SupernodeURL, "ws://") {
			cfg.WSEnabled = true
		}
	// log.Printf("DEBUG config: after auto-enable, SupernodeURL=%q, WSEnabled=%v, WSSEnabled=%v", cfg.SupernodeURL, cfg.WSEnabled, cfg.WSSEnabled)
	}

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
