package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultRejectsScanningWithoutAuthorizedTargets(t *testing.T) {
	if err := Default().Validate(); err != ErrNoAuthorizedTargets {
		t.Fatalf("Validate() error = %v, want %v", err, ErrNoAuthorizedTargets)
	}
}

func TestWriteAndLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := WriteDefault(path); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), ErrNoAuthorizedTargets.Error()) {
		t.Fatalf("Load() error = %v, want missing targets error", err)
	}

	data := []byte(`{"authorized_targets":["192.0.2.0/24"],"timeout":2000000000,"max_concurrency":4,"log_level":"debug"}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Timeout != 2*time.Second || cfg.MaxConcurrency != 4 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}
