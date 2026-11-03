package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/loowtime/netrivox/pkg/models"
	_ "modernc.org/sqlite"
)

var ErrScanNotFound = errors.New("scan not found")

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open SQLite database: %w", err)
	}
	store := &Store{db: db}
	if err := store.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate(ctx context.Context) error {
	const schema = `
CREATE TABLE IF NOT EXISTS schema_migrations (
	version INTEGER PRIMARY KEY,
	applied_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
	id TEXT PRIMARY KEY,
	started_at TEXT NOT NULL,
	completed_at TEXT,
	target_count INTEGER NOT NULL,
	host_count INTEGER NOT NULL,
	schema_version INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS hosts (
	scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
	ip TEXT NOT NULL,
	mac TEXT NOT NULL DEFAULT '',
	hostname TEXT NOT NULL DEFAULT '',
	reachable INTEGER NOT NULL,
	observed_at TEXT NOT NULL,
	PRIMARY KEY (scan_id, ip)
);
CREATE TABLE IF NOT EXISTS services (
	scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
	host_ip TEXT NOT NULL,
	port INTEGER NOT NULL,
	protocol TEXT NOT NULL,
	state TEXT NOT NULL,
	name TEXT NOT NULL DEFAULT '',
	category TEXT NOT NULL DEFAULT '',
	description TEXT NOT NULL DEFAULT '',
	banner TEXT NOT NULL DEFAULT '',
	version TEXT NOT NULL DEFAULT '',
	version_confidence TEXT NOT NULL DEFAULT '',
	version_evidence TEXT NOT NULL DEFAULT '',
	vulnerabilities_json TEXT NOT NULL DEFAULT '[]',
	observed_at TEXT NOT NULL,
	duration_ns INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (scan_id, host_ip, port, protocol)
);
CREATE TABLE IF NOT EXISTS tls_metadata (
	scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
	host TEXT NOT NULL,
	port INTEGER NOT NULL,
	version TEXT NOT NULL DEFAULT '',
	subject TEXT NOT NULL DEFAULT '',
	issuer TEXT NOT NULL DEFAULT '',
	sans_json TEXT NOT NULL DEFAULT '[]',
	not_after TEXT,
	expires_in_days INTEGER NOT NULL DEFAULT 0,
	expiry_warning INTEGER NOT NULL,
	verified INTEGER NOT NULL DEFAULT 0,
	verification_error TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (scan_id, host, port)
);
CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_services_scan_state ON services(scan_id, state);
`
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("run SQLite migrations: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE services ADD COLUMN banner TEXT NOT NULL DEFAULT ''`); err != nil && !strings.Contains(err.Error(), "duplicate column") {
		return fmt.Errorf("upgrade services table: %w", err)
	}
	for _, column := range []string{
		`ALTER TABLE services ADD COLUMN version TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE services ADD COLUMN version_confidence TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE services ADD COLUMN version_evidence TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE services ADD COLUMN vulnerabilities_json TEXT NOT NULL DEFAULT '[]'`,
		`ALTER TABLE tls_metadata ADD COLUMN verified INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE tls_metadata ADD COLUMN verification_error TEXT NOT NULL DEFAULT ''`,
	} {
		if _, err := s.db.ExecContext(ctx, column); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return fmt.Errorf("upgrade services table: %w", err)
		}
	}
	if _, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES(1, ?)`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("record SQLite migration: %w", err)
	}
	return nil
}

func (s *Store) Save(ctx context.Context, result models.ScanResult) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin scan transaction: %w", err)
	}
	defer tx.Rollback()
	scan := result.Scan
	if _, err := tx.ExecContext(ctx, `INSERT INTO scans(id, started_at, completed_at, target_count, host_count, schema_version) VALUES(?, ?, ?, ?, ?, ?)`,
		scan.ID, scan.StartedAt.UTC().Format(time.RFC3339Nano), scan.CompletedAt.UTC().Format(time.RFC3339Nano),
		scan.TargetCount, scan.HostCount, scan.SchemaVersion); err != nil {
		return fmt.Errorf("save scan metadata: %w", err)
	}
	for _, host := range result.Hosts {
		if _, err := tx.ExecContext(ctx, `INSERT INTO hosts(scan_id, ip, mac, hostname, reachable, observed_at) VALUES(?, ?, ?, ?, ?, ?)`,
			scan.ID, host.IP, host.MAC, host.Hostname, host.Reachable, host.Observed.UTC().Format(time.RFC3339Nano)); err != nil {
			return fmt.Errorf("save host %q: %w", host.IP, err)
		}
	}
	for _, service := range result.Services {
		vulnerabilities, err := json.Marshal(service.Vulnerabilities)
		if err != nil {
			return fmt.Errorf("encode vulnerabilities for %s:%d: %w", service.HostIP, service.Port, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO services(scan_id, host_ip, port, protocol, state, name, category, description, banner, version, version_confidence, version_evidence, vulnerabilities_json, observed_at, duration_ns) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			scan.ID, service.HostIP, service.Port, service.Protocol, service.State, service.Name, service.Category, service.Description,
			service.Banner, service.Version, service.VersionConfidence, service.VersionEvidence, string(vulnerabilities),
			service.ObservedAt.UTC().Format(time.RFC3339Nano), service.Duration.Nanoseconds()); err != nil {
			return fmt.Errorf("save service %s:%d: %w", service.HostIP, service.Port, err)
		}
	}
	for _, metadata := range result.TLS {
		sans, err := json.Marshal(metadata.SANs)
		if err != nil {
			return fmt.Errorf("encode TLS SANs for %s:%d: %w", metadata.Host, metadata.Port, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO tls_metadata(scan_id, host, port, version, subject, issuer, sans_json, not_after, expires_in_days, expiry_warning, verified, verification_error) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			scan.ID, metadata.Host, metadata.Port, metadata.Version, metadata.Subject, metadata.Issuer, string(sans),
			metadata.NotAfter.UTC().Format(time.RFC3339Nano), metadata.ExpiresIn, metadata.ExpiryWarning, metadata.Verified, metadata.VerificationError); err != nil {
			return fmt.Errorf("save TLS metadata for %s:%d: %w", metadata.Host, metadata.Port, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit scan: %w", err)
	}
	return nil
}

func (s *Store) List(ctx context.Context, limit int) ([]models.Scan, error) {
	if limit < 1 {
		return nil, fmt.Errorf("history limit must be at least 1")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, started_at, completed_at, target_count, host_count, schema_version FROM scans ORDER BY started_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list scans: %w", err)
	}
	defer rows.Close()
	var scans []models.Scan
	for rows.Next() {
		var scan models.Scan
		var started, completed string
		if err := rows.Scan(&scan.ID, &started, &completed, &scan.TargetCount, &scan.HostCount, &scan.SchemaVersion); err != nil {
			return nil, fmt.Errorf("read scan history: %w", err)
		}
		scan.StartedAt, err = time.Parse(time.RFC3339Nano, started)
		if err != nil {
			return nil, fmt.Errorf("parse scan start time: %w", err)
		}
		if completed != "" {
			scan.CompletedAt, err = time.Parse(time.RFC3339Nano, completed)
			if err != nil {
				return nil, fmt.Errorf("parse scan completion time: %w", err)
			}
		}
		scans = append(scans, scan)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate scan history: %w", err)
	}
	return scans, nil
}

func (s *Store) Load(ctx context.Context, id string) (models.ScanResult, error) {
	var result models.ScanResult
	var scan models.Scan
	var started, completed string
	err := s.db.QueryRowContext(ctx, `SELECT id, started_at, completed_at, target_count, host_count, schema_version FROM scans WHERE id = ?`, id).
		Scan(&scan.ID, &started, &completed, &scan.TargetCount, &scan.HostCount, &scan.SchemaVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return result, ErrScanNotFound
	}
	if err != nil {
		return result, fmt.Errorf("load scan metadata: %w", err)
	}
	var parseErr error
	scan.StartedAt, parseErr = time.Parse(time.RFC3339Nano, started)
	if parseErr != nil {
		return result, fmt.Errorf("parse scan start time: %w", parseErr)
	}
	if completed != "" {
		scan.CompletedAt, parseErr = time.Parse(time.RFC3339Nano, completed)
		if parseErr != nil {
			return result, fmt.Errorf("parse scan completion time: %w", parseErr)
		}
	}
	result.Scan = scan
	rows, err := s.db.QueryContext(ctx, `SELECT ip, mac, hostname, reachable, observed_at FROM hosts WHERE scan_id = ? ORDER BY ip`, id)
	if err != nil {
		return result, fmt.Errorf("load hosts: %w", err)
	}
	for rows.Next() {
		var host models.Host
		var observed string
		if err := rows.Scan(&host.IP, &host.MAC, &host.Hostname, &host.Reachable, &observed); err != nil {
			rows.Close()
			return result, fmt.Errorf("read host: %w", err)
		}
		host.Observed, err = time.Parse(time.RFC3339Nano, observed)
		if err != nil {
			rows.Close()
			return result, fmt.Errorf("parse host time: %w", err)
		}
		result.Hosts = append(result.Hosts, host)
	}
	if err := rows.Close(); err != nil {
		return result, fmt.Errorf("close host rows: %w", err)
	}
	rows, err = s.db.QueryContext(ctx, `SELECT host_ip, port, protocol, state, name, category, description, banner, version, version_confidence, version_evidence, vulnerabilities_json, observed_at, duration_ns FROM services WHERE scan_id = ? ORDER BY host_ip, port`, id)
	if err != nil {
		return result, fmt.Errorf("load services: %w", err)
	}
	for rows.Next() {
		var service models.Service
		var observed, vulnerabilities string
		var duration int64
		if err := rows.Scan(&service.HostIP, &service.Port, &service.Protocol, &service.State, &service.Name, &service.Category, &service.Description, &service.Banner, &service.Version, &service.VersionConfidence, &service.VersionEvidence, &vulnerabilities, &observed, &duration); err != nil {
			rows.Close()
			return result, fmt.Errorf("read service: %w", err)
		}
		if err := json.Unmarshal([]byte(vulnerabilities), &service.Vulnerabilities); err != nil {
			rows.Close()
			return result, fmt.Errorf("parse service vulnerabilities: %w", err)
		}
		service.ObservedAt, err = time.Parse(time.RFC3339Nano, observed)
		if err != nil {
			rows.Close()
			return result, fmt.Errorf("parse service time: %w", err)
		}
		service.Duration = time.Duration(duration)
		result.Services = append(result.Services, service)
	}
	if err := rows.Close(); err != nil {
		return result, fmt.Errorf("close service rows: %w", err)
	}
	rows, err = s.db.QueryContext(ctx, `SELECT host, port, version, subject, issuer, sans_json, not_after, expires_in_days, expiry_warning, verified, verification_error FROM tls_metadata WHERE scan_id = ? ORDER BY host, port`, id)
	if err != nil {
		return result, fmt.Errorf("load TLS metadata: %w", err)
	}
	for rows.Next() {
		var metadata models.TLSMetadata
		var sans, notAfter string
		if err := rows.Scan(&metadata.Host, &metadata.Port, &metadata.Version, &metadata.Subject, &metadata.Issuer, &sans, &notAfter, &metadata.ExpiresIn, &metadata.ExpiryWarning, &metadata.Verified, &metadata.VerificationError); err != nil {
			rows.Close()
			return result, fmt.Errorf("read TLS metadata: %w", err)
		}
		if err := json.Unmarshal([]byte(sans), &metadata.SANs); err != nil {
			rows.Close()
			return result, fmt.Errorf("parse TLS SANs: %w", err)
		}
		if notAfter != "" {
			metadata.NotAfter, err = time.Parse(time.RFC3339Nano, notAfter)
			if err != nil {
				rows.Close()
				return result, fmt.Errorf("parse TLS expiry: %w", err)
			}
		}
		result.TLS = append(result.TLS, metadata)
	}
	if err := rows.Close(); err != nil {
		return result, fmt.Errorf("close TLS rows: %w", err)
	}
	return result, nil
}

func DatabasePath(configPath string) string {
	if configPath == "" {
		return "netrivox.db"
	}
	return filepath.Join(filepath.Dir(configPath), "netrivox.db")
}
