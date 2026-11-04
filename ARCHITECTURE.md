# Architecture

Netrivox separates acquisition, analysis, persistence, and presentation:

- `internal/config`: validated, safe-by-default configuration.
- `internal/discovery`: authorized target expansion and bounded host probes.
- `internal/scanner`: bounded TCP port and optional banner collection.
- `internal/dns`, `internal/tlsinfo`, `internal/httpinfo`: passive protocol metadata.
- `internal/versioning`, `internal/advisory`, `internal/risk`: evidence enrichment and triage.
- `internal/storage`: SQLite repository and migrations.
- `internal/export`: stable JSON, CSV, and table output.
- `internal/app`: Cobra command wiring and orchestration.
- `pkg/models`: versioned data contracts shared across modules.

Long-running work accepts `context.Context`. Network operations use explicit timeouts, worker limits, response limits, and cancellation. External advisory lookups are opt-in and are never treated as confirmed vulnerabilities without product/version verification.
