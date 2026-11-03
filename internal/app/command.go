package app

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/loowtime/netrivox/internal/advisory"
	"github.com/loowtime/netrivox/internal/config"
	"github.com/loowtime/netrivox/internal/discovery"
	"github.com/loowtime/netrivox/internal/dns"
	"github.com/loowtime/netrivox/internal/export"
	"github.com/loowtime/netrivox/internal/intelligence"
	"github.com/loowtime/netrivox/internal/scanner"
	"github.com/loowtime/netrivox/internal/storage"
	"github.com/loowtime/netrivox/internal/telemetry"
	"github.com/loowtime/netrivox/internal/tlsinfo"
	"github.com/loowtime/netrivox/internal/versioning"
	"github.com/loowtime/netrivox/pkg/models"
	"github.com/spf13/cobra"
)

const version = "0.1.0"

const maxRequestedPorts = 4096

func NewCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "netrivox",
		Short: "Network discovery and infrastructure intelligence",
		Long:  "Netrivox inventories explicitly authorized network targets.",
	}
	root.AddCommand(
		newVersionCommand(),
		newConfigCommand(),
		newDiscoveryCommand(),
		newScanCommand(),
		newDNSCommand(),
		newCompareCommand(),
		newPlaceholderCommand("inventory", "Inspect stored host and service inventory."),
		newPlaceholderCommand("export", "Export inventory data."),
		newHistoryCommand(),
	)
	return root
}

func newScanCommand() *cobra.Command {
	var probePort int
	var ports string
	var format string
	var output string
	var inspectTLS bool
	var allowUntrustedTLS bool
	var grabBanners bool
	var advisories bool
	command := &cobra.Command{
		Use:   "scan",
		Short: "Discover hosts and inventory selected TCP services",
		Example: "  netrivox scan --ports 22,80,443 --format table\n" +
			"  netrivox scan --ports 80,443 --tls --format json --output scan.json",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			portList, err := parsePorts(ports)
			if err != nil {
				return err
			}
			start := time.Now()
			hosts, err := (discovery.Scanner{
				Timeout: cfg.Timeout, Workers: cfg.MaxConcurrency,
				MaxHosts: cfg.MaxHosts, ProbePort: probePort,
			}).Discover(cmd.Context(), cfg.AuthorizedTargets)
			if err != nil {
				return fmt.Errorf("discover hosts: %w", err)
			}
			reachableHosts := make([]string, 0)
			for _, host := range hosts {
				if host.Reachable {
					reachableHosts = append(reachableHosts, host.IP)
				}
			}
			services := scanner.PortScanner{
				Timeout: cfg.Timeout, Workers: cfg.MaxConcurrency, GrabBanner: grabBanners || advisories,
			}.ScanHosts(cmd.Context(), reachableHosts, portList)
			for index := range services {
				versioning.Enrich(&services[index])
			}
			if advisories {
				client := advisory.Client{}
				for index := range services {
					if services[index].State != "open" || services[index].Version == "" {
						continue
					}
					found, lookupErr := client.Lookup(cmd.Context(), services[index].Name, services[index].Version)
					if lookupErr != nil {
						fmt.Fprintf(cmd.ErrOrStderr(), "warning: advisory lookup for %s:%d: %v\n", services[index].HostIP, services[index].Port, lookupErr)
						continue
					}
					services[index].Vulnerabilities = found
				}
			}
			result := models.ScanResult{
				Scan: models.Scan{
					ID:        fmt.Sprintf("scan-%d", start.UnixNano()),
					StartedAt: start, CompletedAt: time.Now(),
					TargetCount: len(cfg.AuthorizedTargets), HostCount: len(hosts),
					SchemaVersion: models.SchemaVersion,
				},
				Hosts: hosts, Services: services,
			}
			if inspectTLS {
				result.TLS = inspectOpenTLS(cmd, cfg.Timeout, services, allowUntrustedTLS)
			}
			if err := saveScan(cmd.Context(), result); err != nil {
				return err
			}
			if err := writeScanResult(cmd, result, format, output); err != nil {
				return err
			}

			if output == "" && strings.EqualFold(format, "table") {
				fmt.Fprintf(cmd.ErrOrStderr(), "\nCompleted in %s: %d hosts, %d reachable, %d services checked, %d open\n",
					time.Since(start).Round(time.Millisecond), len(hosts), len(reachableHosts),
					len(services), countOpenServices(services))
			}
			return nil
		},
	}
	command.Flags().IntVar(&probePort, "probe-port", 443, "TCP port used to identify reachable hosts")
	command.Flags().StringVar(&ports, "ports", "22,80,443,8080", "TCP ports/ranges to inventory, e.g. 22,80-443")
	command.Flags().StringVar(&format, "format", "table", "Output format: table, json, or csv")
	command.Flags().StringVarP(&output, "output", "o", "", "Write results to a file instead of stdout")
	command.Flags().BoolVar(&inspectTLS, "tls", false, "Inspect TLS metadata on open TLS services")
	command.Flags().BoolVar(&allowUntrustedTLS, "tls-untrusted", false, "Allow TLS metadata inspection without certificate verification; results are marked untrusted")
	command.Flags().BoolVar(&grabBanners, "banner", false, "Read a small, bounded service banner from open TCP services")
	command.Flags().BoolVar(&advisories, "cve", false, "Query NVD for possible CVEs matching detected product versions")
	return command
}

func newDNSCommand() *cobra.Command {
	var format string
	command := &cobra.Command{
		Use:   "dns <name>",
		Short: "Query controlled DNS intelligence for a name",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := (dns.Client{Timeout: 5 * time.Second}).Lookup(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if strings.EqualFold(format, "table") {
				fmt.Fprintf(cmd.OutOrStdout(), "DNS: %s\nA: %s\nAAAA: %s\nMX: %s\nNS: %s\nTXT: %s\nPTR: %s\n",
					result.Name, strings.Join(result.A, ", "), strings.Join(result.AAAA, ", "),
					strings.Join(result.MX, ", "), strings.Join(result.NS, ", "),
					strings.Join(result.TXT, ", "), strings.Join(result.PTR, ", "))
				return nil
			}
			if !strings.EqualFold(format, "json") {
				return fmt.Errorf("unsupported DNS format %q; choose table or json", format)
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
		},
	}
	command.Flags().StringVar(&format, "format", "table", "Output format: table or json")
	return command
}

func newCompareCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "compare <older-scan-id> <newer-scan-id>",
		Short: "Compare two stored scans and show infrastructure changes",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath, err := config.Path()
			if err != nil {
				return err
			}
			store, err := storage.Open(storage.DatabasePath(configPath))
			if err != nil {
				return err
			}
			defer store.Close()
			older, err := store.Load(cmd.Context(), args[0])
			if err != nil {
				return fmt.Errorf("load older scan: %w", err)
			}
			newer, err := store.Load(cmd.Context(), args[1])
			if err != nil {
				return fmt.Errorf("load newer scan: %w", err)
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(intelligence.Compare(older, newer))
		},
	}
}

func saveScan(ctx context.Context, result models.ScanResult) error {
	configPath, err := config.Path()
	if err != nil {
		return err
	}
	store, err := storage.Open(storage.DatabasePath(configPath))
	if err != nil {
		return err
	}
	defer store.Close()
	if err := store.Save(ctx, result); err != nil {
		return fmt.Errorf("save scan history: %w", err)
	}
	return nil
}

func newHistoryCommand() *cobra.Command {
	var limit int
	command := &cobra.Command{
		Use:   "history",
		Short: "Review recent scan history",
		RunE: func(cmd *cobra.Command, _ []string) error {
			configPath, err := config.Path()
			if err != nil {
				return err
			}
			store, err := storage.Open(storage.DatabasePath(configPath))
			if err != nil {
				return err
			}
			defer store.Close()
			scans, err := store.List(cmd.Context(), limit)
			if err != nil {
				return err
			}
			for _, scan := range scans {
				fmt.Fprintf(cmd.OutOrStdout(), "%s  %s  hosts=%d targets=%d\n",
					scan.ID, scan.StartedAt.Format(time.RFC3339), scan.HostCount, scan.TargetCount)
			}
			return nil
		},
	}
	command.Flags().IntVar(&limit, "limit", 20, "Maximum number of scans to show")
	return command
}

func loadConfig() (config.Config, error) {
	path, err := config.Path()
	if err != nil {
		return config.Config{}, err
	}
	return config.Load(path)
}

func parsePorts(value string) ([]int, error) {
	if strings.TrimSpace(value) == "" {
		return nil, fmt.Errorf("ports must not be empty")
	}
	seen := make(map[int]struct{})
	for _, part := range strings.Split(value, ",") {
		parts := strings.Split(strings.TrimSpace(part), "-")
		if len(parts) > 2 {
			return nil, fmt.Errorf("invalid TCP port range %q", part)
		}
		first, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil || first < 1 || first > 65535 {
			return nil, fmt.Errorf("invalid TCP port %q", part)
		}
		last := first
		if len(parts) == 2 {
			last, err = strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil || last < first || last > 65535 {
				return nil, fmt.Errorf("invalid TCP port range %q", part)
			}
		}
		for port := first; port <= last; port++ {
			seen[port] = struct{}{}
		}
	}

	result := make([]int, 0, len(seen))
	if len(seen) > maxRequestedPorts {
		return nil, fmt.Errorf("port selection contains %d ports; maximum is %d", len(seen), maxRequestedPorts)
	}
	for port := range seen {
		result = append(result, port)
	}
	sort.Ints(result)
	return result, nil
}

func countOpenServices(services []models.Service) int {
	count := 0
	for _, service := range services {
		if service.State == "open" {
			count++
		}
	}
	return count
}

func inspectOpenTLS(cmd *cobra.Command, timeout time.Duration, services []models.Service, allowUntrusted bool) []models.TLSMetadata {
	analyzer := tlsinfo.Analyzer{Timeout: timeout, AllowUntrusted: allowUntrusted}
	result := make([]models.TLSMetadata, 0)
	for _, service := range services {
		if service.State != "open" || (service.Port != 443 && service.Port != 8443) {
			continue
		}
		metadata, err := analyzer.Inspect(cmd.Context(), service.HostIP, service.Port)
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: %v\n", err)
			continue
		}
		result = append(result, metadata)
	}
	return result
}

func writeScanResult(cmd *cobra.Command, result models.ScanResult, format, output string) error {
	var writer *os.File
	if output == "" {
		switch strings.ToLower(format) {
		case "json":
			return export.JSON(cmd.OutOrStdout(), result)
		case "csv":
			return export.CSV(cmd.OutOrStdout(), result)
		case "table":
			return export.Table(cmd.OutOrStdout(), result)
		default:
			return fmt.Errorf("unsupported format %q; choose table, json, or csv", format)
		}
	}
	var err error
	writer, err = os.Create(output)
	if err != nil {
		return fmt.Errorf("create output %q: %w", output, err)
	}
	defer writer.Close()
	switch strings.ToLower(format) {
	case "json":
		err = export.JSON(writer, result)
	case "csv":
		err = export.CSV(writer, result)
	case "table":
		err = export.Table(writer, result)
	default:
		return fmt.Errorf("unsupported format %q; choose table, json, or csv", format)
	}
	if err != nil {
		return fmt.Errorf("write output %q: %w", output, err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Scan written to %s\n", output)
	return nil
}

func newDiscoveryCommand() *cobra.Command {
	var probePort int
	command := &cobra.Command{
		Use:   "discovery",
		Short: "Run controlled discovery against authorized targets",
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := config.Path()
			if err != nil {
				return err
			}
			cfg, err := config.Load(path)
			if err != nil {
				return err
			}
			hosts, err := (discovery.Scanner{
				Timeout: cfg.Timeout, Workers: cfg.MaxConcurrency,
				MaxHosts: cfg.MaxHosts, ProbePort: probePort,
			}).Discover(cmd.Context(), cfg.AuthorizedTargets)
			if err != nil {
				return fmt.Errorf("discover hosts: %w", err)
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(hosts)
		},
	}
	command.Flags().IntVar(&probePort, "probe-port", 443, "TCP port used for the reachability probe")
	return command
}

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the Netrivox version",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintln(cmd.OutOrStdout(), version)
		},
	}
}

func newConfigCommand() *cobra.Command {
	configCommand := &cobra.Command{Use: "config", Short: "Manage Netrivox configuration"}
	configCommand.AddCommand(&cobra.Command{
		Use:   "init",
		Short: "Create a secure default configuration",
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := config.Path()
			if err != nil {
				return err
			}
			if _, err := os.Stat(path); err == nil {
				return fmt.Errorf("configuration already exists at %s", path)
			} else if !os.IsNotExist(err) {
				return fmt.Errorf("check configuration: %w", err)
			}
			if err := config.WriteDefault(path); err != nil {
				return err
			}
			telemetry.NewLogger("info").Info("created configuration", slog.String("path", path))
			fmt.Fprintf(cmd.OutOrStdout(), "Created %s\n", path)
			return nil
		},
	})
	return configCommand
}

func newPlaceholderCommand(use, short string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return fmt.Errorf("%s is not implemented yet; configure authorized targets before scanning", use)
		},
	}
}
