# Changelog

All notable changes to the AIGIS protocol and reference implementation are recorded here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [Semantic Versioning](https://semver.org/).

Every pull request adds a line under **[Unreleased]**. On release, that section is renamed to the new version and date.

## [Unreleased]

### Added
- Registry persistence: every change is appended to `data/registry.jsonl` and replayed on startup (`AIGIS_DATA_DIR`).
- Ownership: each agent and prompter belongs to the credential that registered it; only the owner can suspend,
  revoke, attach ownership records to, or read the history of its agents. Gateways can name the user in `X-AIGIS-Owner`.
- Per-owner registration limit (`AIGIS_MAX_AGENTS_PER_OWNER`, default 10,000; 429 when reached).
- `GET /registry` paging (`page`, `size` 1–100); `/stats` is now constant-time at any registry size.
- Tests for ownership, quotas, paging and restart recovery (9 tests).

### Changed
- License changed from MIT to Apache License 2.0 (explicit patent grant with litigation termination); added `NOTICE`.
- Name unified as "AIGIS: Serialization & Identification Protocol".
- `SPECIFICATION.md` rewritten so Sections 1–8 describe exactly what the reference implementation does;
  planned features moved to a non-normative roadmap.
- Unknown categories are rejected (400) instead of silently becoming `MDL`; text fields are limited to 200 characters.
- `GET /verify/{recordHash}` answers 404 when the record is missing or fails verification.
- `/protocol` and response messages no longer claim signatures or anchoring the implementation does not perform.

### Fixed
- Any caller holding a write key could suspend or revoke any agent.
- Audit-chain forwarding posted to `/append`; it now posts a valid entry to `{AUDIT_CHAIN_URL}/record`.
- API-key comparison is constant-time.

## [1.0.0] - 2026-10-29

### Added
- AIGIS Protocol Specification v1.0.0 (`SPECIFICATION.md`).
- Reference implementation (Java 21, Helidon SE 4.1.6): agent serial numbers, prompter identity,
  Action Ownership Records, registry lookup/verify/stats, suspend and revoke, API-key protected writes.
- Standalone Maven build with pinned dependencies, Maven wrapper, and a self-contained runnable jar.
- Unit tests for serial format, per-category sequencing, identity-hash normalization, and ownership-record rules.
- CI, Dependabot, CODEOWNERS, pull-request and issue templates, changelog enforcement, security policy.

### Fixed
- `application.yaml` used `${VAR:}` placeholders that Helidon 4.1.6 does not resolve. With no environment
  variables set, the literal text became the API key (a publicly known value) and the audit-chain URL,
  forcing auth on and INTEGRATED mode. Settings are now read only from environment variables.
