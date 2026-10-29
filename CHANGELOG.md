# Changelog

All notable changes to the AIGIS protocol and reference implementation are recorded here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [Semantic Versioning](https://semver.org/).

Every pull request adds a line under **[Unreleased]**. On release, that section is renamed to the new version and date.

## [Unreleased]

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
