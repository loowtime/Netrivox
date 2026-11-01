# Netrivox

Netrivox is an open-source platform for controlled network discovery and infrastructure inventory.

## Status

The project is in **Phase 1 — Foundation**. The current release provides the Go module, safe configuration defaults, structured logging, CLI commands, and shared inventory models. Discovery and persistence modules will be added in subsequent phases.

## Build and run

Requires Go 1.24 or newer.

```sh
go mod download
go test ./...
go run ./cmd/netrivox version
go run ./cmd/netrivox config init
```

The generated configuration contains no authorized targets. This is intentional: Netrivox refuses to run discovery until explicit IP addresses or CIDR ranges are configured. Set `NETRIVOX_CONFIG` to use a different configuration path.

## Security model

Netrivox is designed for networks that you own or are authorized to test. Scanning is opt-in, bounded by configured targets, and will use context cancellation, timeouts, and concurrency limits as the scanner modules are implemented.

## Roadmap

1. Foundation: configuration, logging, CLI, and models.
2. Storage: SQLite migrations and repository interfaces.
3. Discovery and controlled TCP port inventory.
4. DNS/TLS intelligence and exports.
5. TUI, API, dashboard, and release automation.

See [LICENSE](./LICENSE) for licensing information.
