# Security Policy

## Reporting a vulnerability

Please **do not** report security issues in public GitHub issues, discussions, or pull requests.

Report privately by either:
- GitHub: **Security → Report a vulnerability** on this repository (private advisory), or
- Email: **partners@kymatech.io** with the subject `AIGIS SECURITY`.

Include affected version or commit, steps to reproduce, and impact. You will receive an acknowledgement
within 3 business days. Please allow up to 90 days for a fix before public disclosure; we will credit
reporters in the release notes unless asked not to.

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | ✅ |

## Deployment guidance

- Always set `AIGIS_API_KEY` on any instance reachable by others; without it all write endpoints are open.
- Run behind TLS (a reverse proxy such as nginx or Caddy) — the reference server speaks plain HTTP.
- The reference implementation stores the registry in memory; it is not yet a system of record.
