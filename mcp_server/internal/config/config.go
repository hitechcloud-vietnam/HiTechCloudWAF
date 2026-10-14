package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/mcp_server/pkg/errors"
	"gopkg.in/yaml.v3"
)

// Backends the server can talk to.
const (
	// BackendHCW is the hcw-waf engine management API (X-HCW-API-TOKEN).
	BackendHCW = "hcw-waf"
	// BackendLegacy is the management API of the legacy engine. It exposes
	// only the read-only get_attack_events tool.
	BackendLegacy = "legacy"
)

// Transports the MCP server can serve.
const (
	// TransportHTTP serves Streamable HTTP on server.host:server.port.
	TransportHTTP = "http"
	// TransportStdio speaks MCP on stdin/stdout, for clients that launch the
	// server as a subprocess (Claude Desktop, Claude Code).
	TransportStdio = "stdio"
)

// Config is the complete MCP server configuration.
type Config struct {
	// Backend selects the management API: "hcw-waf" (default) or "legacy".
	Backend string `yaml:"backend"`
	// ReadOnly hides every tool that changes the configuration of an
	// instance. Only reading tools are registered.
	ReadOnly  bool              `yaml:"read_only"`
	Server    *ServerConfig     `yaml:"server"`
	Logger    *LoggerConfig     `yaml:"logger"`
	Instances []*InstanceConfig `yaml:"instances"`
}

// InstanceConfig identifies one independently authenticated HiTechCloud WAF instance.
// The API token is deliberately referenced through a file or an environment
// variable instead of being embedded in the main configuration file.
type InstanceConfig struct {
	ID          string `yaml:"id"`
	DisplayName string `yaml:"display_name"`
	BaseURL     string `yaml:"base_url"`
	TokenFile   string `yaml:"token_file"`
	// TokenEnv names the environment variable holding the API token
	// (hcw-waf backend only). Exactly one of token_file and token_env is set.
	TokenEnv string `yaml:"token_env"`
	CAFile   string `yaml:"ca_file"`
	Timeout  int    `yaml:"timeout"`
	Debug    bool   `yaml:"debug"`
	// ReadOnly refuses write tools for this instance even when the server
	// registers them for other instances.
	ReadOnly           bool `yaml:"read_only"`
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
}

// ServerConfig is the MCP server listener configuration.
type ServerConfig struct {
	// Transport is "http" (default) or "stdio". The --transport flag and
	// MCP_TRANSPORT override it.
	Transport   string `yaml:"transport"`
	Name        string `yaml:"name"`
	Version     string `yaml:"version"`
	Port        int    `yaml:"port"`
	Host        string `yaml:"host"`
	TLSCertFile string `yaml:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file"`
}

// LoggerConfig is the logging configuration.
type LoggerConfig struct {
	Level       string `yaml:"level"`
	FilePath    string `yaml:"file_path"`
	Console     bool   `yaml:"console"`
	Caller      bool   `yaml:"caller"`
	Development bool   `yaml:"development"`
}

var config *Config

func getEnvString(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value, exists := os.LookupEnv(key); exists {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// Load reads and validates the configuration file. Relative token_file paths
// are resolved from the directory containing the configuration file so that a
// deployment does not depend on the server process working directory.
func Load(path string) error {
	return LoadWithTransport(path, "")
}

// LoadWithTransport is Load with a transport chosen on the command line; an
// empty transport keeps MCP_TRANSPORT or the configured one.
func LoadWithTransport(path, transport string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return errors.Wrap(err, "read config file failed")
	}

	next := &Config{}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(next); err != nil {
		return errors.Wrap(err, "unmarshal config failed")
	}

	if next.Server != nil {
		next.Server.Host = getEnvString("LISTEN_ADDRESS", next.Server.Host)
		next.Server.Port = getEnvInt("LISTEN_PORT", next.Server.Port)
		// Empty compose values must not wipe yaml paths.
		if cert := strings.TrimSpace(os.Getenv("MCP_TLS_CERT")); cert != "" {
			next.Server.TLSCertFile = cert
		} else {
			next.Server.TLSCertFile = strings.TrimSpace(next.Server.TLSCertFile)
		}
		if key := strings.TrimSpace(os.Getenv("MCP_TLS_KEY")); key != "" {
			next.Server.TLSKeyFile = key
		} else {
			next.Server.TLSKeyFile = strings.TrimSpace(next.Server.TLSKeyFile)
		}
	}

	if next.Server == nil {
		return errors.New("server configuration is required")
	}
	switch {
	case strings.TrimSpace(transport) != "":
		next.Server.Transport = transport
	case strings.TrimSpace(os.Getenv("MCP_TRANSPORT")) != "":
		next.Server.Transport = os.Getenv("MCP_TRANSPORT")
	}
	next.Server.Transport = strings.ToLower(strings.TrimSpace(next.Server.Transport))
	if next.Server.Transport == "" {
		next.Server.Transport = TransportHTTP
	}
	if next.Server.Transport != TransportHTTP && next.Server.Transport != TransportStdio {
		return errors.New(fmt.Sprintf("server.transport must be %q or %q", TransportHTTP, TransportStdio))
	}
	if strings.TrimSpace(next.Server.Name) == "" {
		return errors.New("server.name is required")
	}
	if strings.TrimSpace(next.Server.Version) == "" {
		return errors.New("server.version is required")
	}
	if next.Server.Transport == TransportHTTP {
		if strings.TrimSpace(next.Server.Host) == "" {
			return errors.New("server.host is required")
		}
		if next.Server.Port < 1 || next.Server.Port > 65535 {
			return errors.New("server.port must be between 1 and 65535")
		}
	}
	if next.Logger == nil {
		return errors.New("logger configuration is required")
	}

	next.Backend = strings.ToLower(strings.TrimSpace(next.Backend))
	switch next.Backend {
	case "":
		next.Backend = BackendHCW
	case BackendHCW, BackendLegacy:
	default:
		return errors.New(fmt.Sprintf("backend must be %q or %q", BackendHCW, BackendLegacy))
	}

	if err := normalizeInstances(next, filepath.Dir(path)); err != nil {
		return err
	}

	config = next
	return nil
}

func normalizeInstances(cfg *Config, configDir string) error {
	if len(cfg.Instances) == 0 {
		return errors.New("at least one HiTechCloud WAF instance is required")
	}

	seen := make(map[string]struct{}, len(cfg.Instances))
	for index, instance := range cfg.Instances {
		if instance == nil {
			return errors.New(fmt.Sprintf("instances[%d] is required", index))
		}

		instance.ID = strings.TrimSpace(instance.ID)
		instance.DisplayName = strings.TrimSpace(instance.DisplayName)
		instance.BaseURL = strings.TrimSpace(instance.BaseURL)
		instance.TokenFile = strings.TrimSpace(instance.TokenFile)
		instance.TokenEnv = strings.TrimSpace(instance.TokenEnv)
		instance.CAFile = strings.TrimSpace(instance.CAFile)
		if instance.ID == "" {
			return errors.New(fmt.Sprintf("instances[%d].id is required", index))
		}
		if _, ok := seen[instance.ID]; ok {
			return errors.New(fmt.Sprintf("duplicate instance id %q", instance.ID))
		}
		seen[instance.ID] = struct{}{}

		if instance.DisplayName == "" {
			instance.DisplayName = instance.ID
		}
		if instance.BaseURL == "" {
			return errors.New(fmt.Sprintf("instances[%d].base_url is required", index))
		}
		switch {
		case cfg.Backend == BackendLegacy && instance.TokenEnv != "":
			return errors.New(fmt.Sprintf("instances[%d].token_env is only supported by the %s backend; use token_file", index, BackendHCW))
		case instance.TokenFile != "" && instance.TokenEnv != "":
			return errors.New(fmt.Sprintf("instances[%d]: set only one of token_file and token_env", index))
		case instance.TokenFile == "" && instance.TokenEnv == "" && cfg.Backend == BackendLegacy:
			return errors.New(fmt.Sprintf("instances[%d].token_file is required", index))
		case instance.TokenFile == "" && instance.TokenEnv == "":
			return errors.New(fmt.Sprintf("instances[%d]: token_file or token_env is required", index))
		case instance.TokenEnv != "" && !envNameRe.MatchString(instance.TokenEnv):
			return errors.New(fmt.Sprintf("instances[%d].token_env must be an environment variable name", index))
		}
		if instance.TokenFile != "" && !filepath.IsAbs(instance.TokenFile) {
			instance.TokenFile = filepath.Clean(filepath.Join(configDir, instance.TokenFile))
		}
		if instance.CAFile != "" && !filepath.IsAbs(instance.CAFile) {
			instance.CAFile = filepath.Clean(filepath.Join(configDir, instance.CAFile))
		}

		if instance.InsecureSkipVerify {
			return errors.New(fmt.Sprintf(
				"instances[%d].insecure_skip_verify is not supported; set ca_file to trust a self-signed instance certificate",
				index,
			))
		}
	}

	for index, instance := range cfg.Instances {
		for previousIndex := 0; previousIndex < index; previousIndex++ {
			previous := cfg.Instances[previousIndex]
			if strings.EqualFold(instance.DisplayName, previous.DisplayName) {
				return errors.New(fmt.Sprintf(
					"duplicate instance display_name %q for instances %q and %q",
					instance.DisplayName,
					previous.ID,
					instance.ID,
				))
			}
		}
		for otherIndex, other := range cfg.Instances {
			if otherIndex != index && strings.EqualFold(instance.DisplayName, other.ID) {
				return errors.New(fmt.Sprintf(
					"instance display_name %q for %q conflicts with instance id %q",
					instance.DisplayName,
					instance.ID,
					other.ID,
				))
			}
		}
	}

	return nil
}

// GetServer returns the listener configuration.
func GetServer() *ServerConfig {
	if config == nil {
		return nil
	}
	return config.Server
}

// GetBackend returns the configured backend.
func GetBackend() string {
	if config == nil {
		return ""
	}
	return config.Backend
}

// GetReadOnly reports whether write tools are hidden.
func GetReadOnly() bool {
	return config != nil && config.ReadOnly
}

// GetLogger returns the logging configuration.
func GetLogger() *LoggerConfig {
	if config == nil {
		return nil
	}
	return config.Logger
}

// GetInstances returns all configured HiTechCloud WAF instances.
func GetInstances() []*InstanceConfig {
	if config == nil {
		return nil
	}
	return config.Instances
}
