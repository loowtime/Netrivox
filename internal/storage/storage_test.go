package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/loowtime/netrivox/pkg/models"
)

func TestSaveAndLoadScan(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC().Truncate(time.Microsecond)
	input := models.ScanResult{
		Scan:     models.Scan{ID: "scan-test", StartedAt: now, CompletedAt: now.Add(time.Second), TargetCount: 1, HostCount: 1, SchemaVersion: models.SchemaVersion},
		Hosts:    []models.Host{{IP: "192.0.2.1", Reachable: true, Observed: now}},
		Services: []models.Service{{HostIP: "192.0.2.1", Port: 443, Protocol: "tcp", State: "open", Name: "https", Banner: "HTTP/1.1 200 OK", ObservedAt: now}},
		TLS:      []models.TLSMetadata{{Host: "192.0.2.1", Port: 443, Version: "TLS 1.3", SANs: []string{"example.test"}, NotAfter: now.Add(time.Hour)}},
	}
	if err := store.Save(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load(context.Background(), input.Scan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Hosts) != 1 || len(got.Services) != 1 || len(got.TLS) != 1 || got.Services[0].Name != "https" || got.Services[0].Banner == "" {
		t.Fatalf("unexpected loaded result: %+v", got)
	}
	history, err := store.List(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 || history[0].ID != input.Scan.ID {
		t.Fatalf("unexpected history: %+v", history)
	}
}

func TestSaveIsTransactionalOnDuplicateID(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	input := models.ScanResult{Scan: models.Scan{ID: "duplicate", StartedAt: time.Now(), SchemaVersion: models.SchemaVersion}}
	if err := store.Save(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(context.Background(), input); err == nil {
		t.Fatal("Save() succeeded for duplicate scan ID")
	}
	history, err := store.List(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 {
		t.Fatalf("duplicate save changed history: %+v", history)
	}
}
