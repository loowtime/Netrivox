# Development

Requirements:

- Go 1.24 or newer
- No external network is required for tests

Use the standard validation gate:

```sh
gofmt -w $(find cmd internal pkg -name '*.go' -type f)
go test ./...
go vet ./...
go build ./cmd/netrivox
```

Tests use loopback listeners, local TLS servers, HTTP fixtures, fake resolvers, and temporary SQLite databases. Do not add tests that contact public networks.

Keep modules small, return contextual errors, preserve cancellation, and avoid broad catches or silent fallbacks. Changes that alter scan behavior must update tests and documentation.
