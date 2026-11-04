# Configuration

Netrivox stores its configuration in the platform user configuration directory. On macOS this is:

```text
~/Library/Application Support/netrivox/config.json
```

Override the location with `NETRIVOX_CONFIG`.

Example:

```json
{
  "authorized_targets": ["192.168.1.0/24"],
  "timeout": 5000000000,
  "max_concurrency": 16,
  "max_hosts": 256,
  "log_level": "info"
}
```

`timeout` is encoded as Go duration nanoseconds in JSON. Empty authorized targets are rejected by design. The database is stored as `netrivox.db` next to this file.
