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

For the complete user-facing scan workflow:

```sh
go run ./cmd/netrivox scan --ports 22,80,443 --format table
go run ./cmd/netrivox scan --ports 80,443 --tls --format json --output scan.json
go run ./cmd/netrivox scan --ports 22,80,443 --format csv --output services.csv
go run ./cmd/netrivox scan --ports 1-1024 --format table
```

The scan command first performs the bounded reachability check, then inventories ports only on reachable hosts. Known ports receive a service classification; TLS analysis is optional and reads certificate metadata without trusting or modifying the remote certificate.

Every completed `scan` is stored in a local SQLite database next to the configuration file as `netrivox.db`. Review recent runs with:

```sh
go run ./cmd/netrivox history
go run ./cmd/netrivox history --limit 50
```

Network intelligence commands:

```sh
go run ./cmd/netrivox scan --ports 22,80,443 --banner
go run ./cmd/netrivox scan --ports 22,80,443 --banner --cve --format json
go run ./cmd/netrivox dns example.com --format json
go run ./cmd/netrivox compare scan-older-id scan-newer-id
```

Banner collection is opt-in, bounded to 1024 bytes and a short read deadline. Detected versions are marked with evidence and confidence. `--cve` automatically enables the bounded banner read, then performs an opt-in NVD keyword lookup and reports only possible matches; keyword results are not proof that a target is vulnerable and must be verified against the vendor advisory, package backports, configuration and deployment context. Netrivox does not authenticate, exploit, brute-force, or bypass a service.

Port selections accept individual ports and ranges, for example `22,80,443` or `1-1024`. A hard limit of 4096 selected ports prevents accidental resource exhaustion. Host and port work share a bounded worker pool from `max_concurrency`, so large authorized ranges do not create one goroutine pool per host. Results remain sorted by host and port for stable automation output.

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
