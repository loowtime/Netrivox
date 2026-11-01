# Netrivox

Netrivox is an open-source platform for controlled network discovery and infrastructure inventory.

## Status

The project is in **Phase 2 — Core Engine**. The current release provides safe configuration defaults, structured logging, shared inventory models, bounded host discovery, controlled TCP port inventory, and DNS record lookups. SQLite persistence and presentation layers will be added in subsequent phases.

## Build and run

Requires Go 1.24 or newer.

```sh
go mod download
go test ./...
go run ./cmd/netrivox version
go run ./cmd/netrivox config init
```

The generated configuration contains no authorized targets. This is intentional: Netrivox refuses to run discovery until explicit IP addresses or CIDR ranges are configured. Set `NETRIVOX_CONFIG` to use a different configuration path.

After adding authorized targets to the JSON configuration, run `go run ./cmd/netrivox discovery`. Results are emitted as JSON; `--probe-port` selects the explicit TCP port used for the bounded reachability probe.

Core engine limits are configured centrally: `timeout` bounds individual operations, `max_concurrency` controls workers, and `max_hosts` prevents an accidentally broad CIDR from being expanded. Host discovery uses an explicit TCP probe port and does not perform stealth or packet-flooding scans.

## Security model

Netrivox is designed for networks that you own or are authorized to test. Scanning is opt-in, bounded by configured targets, and will use context cancellation, timeouts, and concurrency limits as the scanner modules are implemented.

## Roadmap

1. Foundation: configuration, logging, CLI, and models.
2. Core engine: bounded discovery, TCP port inventory, and DNS intelligence.
3. Storage: SQLite migrations and repository interfaces.
4. TLS intelligence and exports.
5. TUI, API, dashboard, and release automation.

See [LICENSE](./LICENSE) for licensing information.
