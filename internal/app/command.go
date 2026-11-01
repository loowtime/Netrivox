package app

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/loowtime/netrivox/internal/config"
	"github.com/loowtime/netrivox/internal/discovery"
	"github.com/loowtime/netrivox/internal/telemetry"
	"github.com/spf13/cobra"
)

const version = "0.1.0"

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
		newPlaceholderCommand("inventory", "Inspect stored host and service inventory."),
		newPlaceholderCommand("export", "Export inventory data."),
		newPlaceholderCommand("history", "Review scan history."),
	)
	return root
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
