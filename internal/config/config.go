// Package config defines the application configuration structure
// and provides loading/validation via Viper.
package config

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds the full application configuration.
type Config struct {
	LogLevel      string        `mapstructure:"log_level"`
	LabelSelector string        `mapstructure:"label_selector"`
	SyncPeriod    time.Duration `mapstructure:"sync_period"`
	DeletePolicy  string        `mapstructure:"delete_policy"`
	// MetricsBindAddress is the host:port the Prometheus metrics server listens on.
	// Set to "0" to disable the metrics server.
	MetricsBindAddress string `mapstructure:"metrics_bind_address"`
	// HealthProbeBindAddress is the host:port the health/readiness probe server listens on.
	// Set to "0" to disable the probe server.
	HealthProbeBindAddress string `mapstructure:"health_probe_bind_address"`
	// KnownHostsFile is an optional path to a known_hosts file used for SSH host key verification.
	// If empty, host key verification is disabled only when InsecureIgnoreHostKey is true.
	KnownHostsFile string `mapstructure:"known_hosts_file"`
	// InsecureIgnoreHostKey disables SSH host key verification. This is insecure and should only be
	// used for quick tests.
	InsecureIgnoreHostKey bool      `mapstructure:"insecure_ignore_host_key"`
	SSHPort               int       `mapstructure:"ssh_port"`
	SSHKey                SSHKeyRef `mapstructure:"ssh_key"`
	Routers               []Router  `mapstructure:"routers"`
}

// SSHKeyRef points to a Kubernetes Secret containing an SSH private key.
type SSHKeyRef struct {
	SecretName      string `mapstructure:"secret_name"`
	SecretNamespace string `mapstructure:"secret_namespace"`
	SecretKey       string `mapstructure:"secret_key"`
}

// Router defines a MikroTik router target.
type Router struct {
	Name     string     `mapstructure:"name"`
	Address  string     `mapstructure:"address"`
	SSHPort  int        `mapstructure:"ssh_port"`
	Username string     `mapstructure:"username"`
	SSHKey   *SSHKeyRef `mapstructure:"ssh_key"`
	Services []Service  `mapstructure:"services"`
}

// EffectiveSSHPort returns the router-specific port or the global default.
func (r Router) EffectiveSSHPort(globalPort int) int {
	if r.SSHPort != 0 {
		return r.SSHPort
	}
	return globalPort
}

// EffectiveSSHKey returns the router-specific key ref or the global default.
func (r Router) EffectiveSSHKey(globalKey SSHKeyRef) SSHKeyRef {
	if r.SSHKey != nil {
		return *r.SSHKey
	}
	return globalKey
}

// Service defines a MikroTik service to bind certificates to.
type Service struct {
	Type         string `mapstructure:"type"`
	PeerName     string `mapstructure:"peer_name"`
	IdentityName string `mapstructure:"identity_name"`
}

// Load reads configuration from the given file path, applying defaults
// and environment variable overrides.
func Load(path string) (*Config, error) {
	v := viper.New()

	v.SetDefault("log_level", "info")
	v.SetDefault("label_selector", "cert-controller.mikrotik.io/enabled=true")
	v.SetDefault("sync_period", "1h")
	v.SetDefault("delete_policy", "retain")
	v.SetDefault("metrics_bind_address", ":8080")
	v.SetDefault("health_probe_bind_address", ":8081")
	v.SetDefault("known_hosts_file", "")
	v.SetDefault("insecure_ignore_host_key", false)
	v.SetDefault("ssh_port", 22)
	v.SetDefault("ssh_key.secret_key", "ssh-privatekey")

	v.SetConfigFile(path)
	v.SetEnvPrefix("CERTCTL")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return &cfg, nil
}

// Validate checks that the configuration is complete and consistent.
func (c *Config) Validate() error {
	if c.DeletePolicy != "retain" && c.DeletePolicy != "remove" {
		return fmt.Errorf("delete_policy must be 'retain' or 'remove', got %q", c.DeletePolicy)
	}

	if err := validateBindAddress("metrics_bind_address", c.MetricsBindAddress); err != nil {
		return err
	}
	if err := validateBindAddress("health_probe_bind_address", c.HealthProbeBindAddress); err != nil {
		return err
	}

	// When routers are configured, require SSH key and host key verification settings.
	if len(c.Routers) > 0 {
		if c.KnownHostsFile == "" && !c.InsecureIgnoreHostKey {
			return fmt.Errorf("either known_hosts_file must be set or insecure_ignore_host_key must be true")
		}

		if c.SSHKey.SecretName == "" {
			return fmt.Errorf("ssh_key.secret_name is required when routers are configured")
		}
		if c.SSHKey.SecretNamespace == "" {
			return fmt.Errorf("ssh_key.secret_namespace is required when routers are configured")
		}
	}

	for i, r := range c.Routers {
		if r.Name == "" {
			return fmt.Errorf("router[%d].name is required", i)
		}
		if r.Address == "" {
			return fmt.Errorf("router[%d].address is required", i)
		}
		if r.Username == "" {
			return fmt.Errorf("router[%d].username is required", i)
		}
		if r.SSHKey != nil {
			if r.SSHKey.SecretName == "" {
				return fmt.Errorf("router[%d].ssh_key.secret_name is required when ssh_key is specified", i)
			}
			if r.SSHKey.SecretNamespace == "" {
				return fmt.Errorf("router[%d].ssh_key.secret_namespace is required when ssh_key is specified", i)
			}
		}
		for j, s := range r.Services {
			if err := validateService(s, i, j); err != nil {
				return err
			}
		}
	}

	return nil
}

// validateBindAddress accepts "0", which disables the corresponding server, or any
// address net.SplitHostPort accepts. An empty value is rejected: controller-runtime
// disables the health probe server for it but silently falls back to the default
// ":8080" for metrics, so "0" is the only unambiguous way to turn a server off.
func validateBindAddress(field, addr string) error {
	if addr == "0" {
		return nil
	}
	if addr == "" {
		return fmt.Errorf("%s must be a host:port address, or \"0\" to disable the server", field)
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return fmt.Errorf("%s %q is not a valid host:port address: %w", field, addr, err)
	}
	return nil
}

func validateService(s Service, routerIdx, serviceIdx int) error {
	switch s.Type {
	case "www-ssl", "api-ssl":
		// no extra fields required
	case "ipsec":
		if s.PeerName == "" && s.IdentityName == "" {
			return fmt.Errorf("router[%d].services[%d]: ipsec service requires peer_name or identity_name", routerIdx, serviceIdx)
		}
	default:
		return fmt.Errorf("router[%d].services[%d]: unknown service type %q", routerIdx, serviceIdx, s.Type)
	}
	return nil
}
