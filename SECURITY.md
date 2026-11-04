# Security Policy

## Scope

Netrivox is intended for networks and systems that the operator owns or is explicitly authorized to assess. It performs bounded TCP connection checks and passive metadata collection. It does not provide stealth scanning, exploit execution, credential attacks, evasion, or vulnerability exploitation.

## Safe operation

- Configure only explicitly authorized IP addresses or CIDR ranges.
- Keep `max_hosts`, `max_concurrency`, and `timeout` bounded.
- Treat banner-derived versions and NVD keyword matches as unverified evidence.
- Use `--tls-untrusted` only for known internal/self-signed endpoints; its output is explicitly marked untrusted.
- Review exported data before sharing it because banners, hostnames, and certificate metadata can be sensitive.

## Reporting a vulnerability

Do not disclose sensitive details in a public issue. Contact the maintainers privately with a description, affected version, reproduction steps using a local test fixture, and suggested mitigation. Allow reasonable time for triage and remediation before public disclosure.

## Limitations

Netrivox is an inventory and triage tool, not proof of exploitability. CVE results require validation against the vendor advisory, exact product identity, package backports, configuration, and deployment context.
