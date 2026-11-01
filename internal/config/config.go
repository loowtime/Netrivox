package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	AppName            = "netrivox"
	DefaultTimeout     = 5 * time.Second
	DefaultConcurrency = 16
)

var ErrNoAuthorizedTargets = errors.New("no authorized targets configured")

// Config contains the settings that govern all discovery operations.
// An empty AuthorizedTargets list is intentional: it prevents accidental scans.
type Config struct {
	AuthorizedTargets []string      `json:"authorized_targets"`
	Timeout           time.Duration `json:"timeout"`
	MaxConcurrency    int           `json:"max_concurrency"`
	LogLevel          string        `json:"log_level"`
}

func Default() Config {
	return Config{
		AuthorizedTargets: []string{},
		Timeout:           DefaultTimeout,
		MaxConcurrency:    DefaultConcurrency,
		LogLevel:          "info",
	}
}

func (c Config) Validate() error {
	if len(c.AuthorizedTargets) == 0 {
		return ErrNoAuthorizedTargets
	}
	if c.Timeout <= 0 {
		return errors.New("timeout must be greater than zero")
	}
	if c.MaxConcurrency < 1 {
		return errors.New("max_concurrency must be at least 1")
	}
	for _, target := range c.AuthorizedTargets {
		if _, _, err := net.ParseCIDR(target); err != nil {
			if net.ParseIP(target) == nil {
				return fmt.Errorf("authorized target %q is not an IP address or CIDR", target)
			}
		}
	}
	return nil
}

func Path() (string, error) {
	if override := os.Getenv("NETRIVOX_CONFIG"); override != "" {
		return override, nil
	}
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config directory: %w", err)
	}
	return filepath.Join(configDir, AppName, "config.json"), nil
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %q: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config %q: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("validate config %q: %w", path, err)
	}
	return cfg, nil
}

func WriteDefault(path string) error {
	cfg := Default()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encode default config: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write config %q: %w", path, err)
	}
	return nil
}
