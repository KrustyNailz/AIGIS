# AIGIS — Agent Identity Governance and Identification Standard

**An open-source protocol and reference implementation for identifying, registering, and tracking AI agents.**

[![CI](https://github.com/KrustyNailz/AIGIS/actions/workflows/ci.yml/badge.svg)](https://github.com/KrustyNailz/AIGIS/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Java 21](https://img.shields.io/badge/Java-21-orange.svg)](https://adoptium.net/)
[![Protocol v1.0.0](https://img.shields.io/badge/Protocol-v1.0.0-green.svg)](SPECIFICATION.md)

Free to use, modify, and deploy. No cost. No vendor lock-in.

---

## Contents

- [The Problem](#the-problem)
- [The Solution](#the-solution)
- [Quick Start (5 minutes)](#quick-start-5-minutes)
- [API Reference](#api-reference)
- [Configuration](#configuration)
- [Dependencies](#dependencies)
- [Repository Layout](#repository-layout)
- [Specification vs. Reference Implementation](#specification-vs-reference-implementation)
- [Alignment with Standards](#alignment-with-standards)
- [Contributing, Pull Requests, and Change Control](#contributing-pull-requests-and-change-control)
- [Versioning and Upgrade Tracking](#versioning-and-upgrade-tracking)
- [Security](#security)
- [License and Patent Notice](#license-and-patent-notice)
- [Author](#author)

---

## The Problem

AI agents are operating at scale with no universal identity layer. There is no standardized way to know:

- **Who** deployed an agent
- **What** an agent is authorized to do
- **Where** an agent has been
- **Who is liable** when an agent goes rogue

Regulators worldwide — the EU AI Act, NIST AI RMF, CISA Five Eyes guidance — are placing the burden of accountability on prompters and providers. Without a way to identify and register agents, that accountability is unenforceable.

## The Solution

AIGIS gives every AI model and agent a permanent, verifiable identity and binds every action it takes to the parties responsible for it.

| Concept | What it does |
|---|---|
| **Agent Serial Number** | A permanent, tamper-evident ID for every model or agent, derived from a SHA-256 hash of its identity (provider, model, version, first-seen time). |
| **Prompter Identity** | A one-way hash of *who* instructed the agent. Proves responsibility without exposing personal data. |
| **Action Ownership Record (AOR)** | Binds each action to the **Agent + Prompter + Provider** triple. No registered agent and prompter = no record = action denied. |
| **Registry** | Look up, verify, suspend, and permanently revoke agents. |

Example serial issued by the reference implementation:

```
AIGIS-AGT-bc2b4ac4-000001
      │   │        └── 6-digit sequence (per category)
      │   └── first 8 hex chars of the SHA-256 identity hash
      └── category: MDL (model) · AGT (agent) · SYS (multi-agent system) · EMB (embedded)
```

---

## Quick Start (5 minutes)

### Requirements

- **Java 21** or newer (e.g. [Eclipse Temurin 21](https://adoptium.net/))
- Nothing else. Maven is downloaded automatically by the included wrapper (`mvnw`).

### Build

```bash
git clone https://github.com/KrustyNailz/AIGIS.git
cd AIGIS
./mvnw clean verify          # Windows: mvnw.cmd clean verify
```

This compiles the code, runs the test suite, and produces a single self-contained runnable jar with every dependency bundled: `target/aigis.jar` (~4.4 MB).

### Run

```bash
java -jar target/aigis.jar                    # standalone, port 8097, no auth (dev mode)
java -jar target/aigis.jar --port 9090        # custom port
AIGIS_API_KEY=change-me java -jar target/aigis.jar   # require an API key on write endpoints
```

### Try it

```bash
# 1. Register an agent → receive its permanent AIGIS serial
curl -s -X POST localhost:8097/api/v1/aigis/register \
  -H 'Content-Type: application/json' \
  -d '{"provider":"anthropic","modelName":"claude","modelVersion":"5","category":"AGT"}'
# → {"serialNumber":"AIGIS-AGT-bc2b4ac4-000001","fullHash":"bc2b4ac4...","status":"ACTIVE",...}

# 2. Register the prompter (the human or system giving instructions)
curl -s -X POST localhost:8097/api/v1/aigis/prompter \
  -H 'Content-Type: application/json' \
  -d '{"organizationId":"org-1","authenticatedIdentity":"ops@example.com","authMethod":"oidc"}'
# → {"prompterHash":"5dda5446...","type":"HUMAN",...}

# 3. Bind an action to Agent + Prompter + Provider
curl -s -X POST localhost:8097/api/v1/aigis/ownership \
  -H 'Content-Type: application/json' \
  -d '{"agentSerial":"AIGIS-AGT-bc2b4ac4-000001","prompterHash":"5dda5446...","providerId":"acme","actionType":"web-search"}'
# → {"recordHash":"b15be9a4...","integrityVerified":true,...}

# 4. Anyone can verify the record and look up the agent
curl -s localhost:8097/api/v1/aigis/verify/b15be9a4...
curl -s localhost:8097/api/v1/aigis/lookup/AIGIS-AGT-bc2b4ac4-000001

# 5. Revoke — the agent can never be bound to another action
curl -s -X POST localhost:8097/api/v1/aigis/revoke/AIGIS-AGT-bc2b4ac4-000001
```

When `AIGIS_API_KEY` is set, add `-H 'X-AIGIS-Key: <key>'` (or `-H 'Authorization: Bearer <key>'`) to write requests.

---

## API Reference

Base path: `/api/v1/aigis`

### Public (no authentication)

| Method | Path | Description |
|---|---|---|
| GET | `/protocol` | Protocol summary (serial format, categories, hashing rules) |
| GET | `/registry` | All registered agents (newest first, up to 500) |
| GET | `/lookup/{serial}` | Agent details by serial, including an integrity check |
| GET | `/lookup/hash/{hash}` | Agent details by full identity hash |
| GET | `/verify/{recordHash}` | Verify an Action Ownership Record's integrity |
| GET | `/stats` | Registry counts (active, suspended, revoked, prompters, records) |

### Authenticated (when `AIGIS_API_KEY` is set)

| Method | Path | Body / Description |
|---|---|---|
| POST | `/register` | `{provider*, modelName*, modelVersion, category (MDL\|AGT\|SYS\|EMB), spiffeId}` → serial (201) |
| POST | `/prompter` | `{organizationId*, authenticatedIdentity, authMethod, type (HUMAN\|SYSTEM\|AGENT_UPSTREAM\|API_CLIENT\|SCHEDULED_TASK), spiffeId}` → prompterHash (201) |
| POST | `/ownership` | `{agentSerial*, prompterHash*, providerId*, actionType*, actionTarget, actionPayloadHash, verdict}` → recordHash (201), or 403 if the agent is not active or the prompter is unknown |
| GET | `/history/agent/{serial}` | Action history for an agent (up to 100 records) |
| GET | `/history/prompter/{hash}` | Action count for a prompter |
| POST | `/suspend/{serial}` | Suspend an agent (reversible status) |
| POST | `/revoke/{serial}` | Permanently revoke an agent |

`*` = required. Other endpoints: `GET /health` and `GET /` (service info).

---

## Configuration

| Setting | How | Default |
|---|---|---|
| Port | `AIGIS_PORT` env, or `--port <n>` | `8097` |
| API key for write endpoints | `AIGIS_API_KEY` env | unset = dev mode, no auth |
| Bind address | `server.host` in `application.yaml` | `0.0.0.0` |
| External audit chain | `AUDIT_CHAIN_URL` env (events are POSTed to `<url>/append`) | unset = standalone |

> **Always set `AIGIS_API_KEY` on any server reachable by others.** Without it, anyone can register, suspend, or revoke agents.

---

## Dependencies

Everything needed to run AIGIS is declared in [`pom.xml`](pom.xml) with pinned versions, and bundled into `target/aigis.jar` by the build. There is nothing else to install besides Java 21.

### Direct dependencies

| Library | Version | License | Purpose |
|---|---|---|---|
| Helidon SE WebServer (`io.helidon.webserver:helidon-webserver`) | 4.1.6 | Apache 2.0 | HTTP server |
| Helidon WebServer CORS (`helidon-webserver-cors`) | 4.1.6 | Apache 2.0 | Cross-origin support |
| Helidon Config + YAML (`helidon-config`, `helidon-config-yaml`) | 4.1.6 | Apache 2.0 | `application.yaml` loading |
| Helidon Health Checks (`helidon-health-checks`) | 4.1.6 | Apache 2.0 | Health support |
| Jackson Databind + JSR-310 (`jackson-databind`, `jackson-datatype-jsr310`) | 2.18.6 | Apache 2.0 | JSON |
| JUnit Jupiter (test only) | 5.10.3 | EPL 2.0 | Tests |

### Full resolved runtime dependency set (bundled in the jar)

<details>
<summary>36 artifacts — click to expand</summary>

```
com.fasterxml.jackson.core:jackson-annotations:2.18.6
com.fasterxml.jackson.core:jackson-core:2.18.6
com.fasterxml.jackson.core:jackson-databind:2.18.6
com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.18.6
io.helidon:helidon:4.1.6
io.helidon.builder:helidon-builder-api:4.1.6
io.helidon.common:helidon-common:4.1.6
io.helidon.common:helidon-common-buffers:4.1.6
io.helidon.common:helidon-common-config:4.1.6
io.helidon.common:helidon-common-configurable:4.1.6
io.helidon.common:helidon-common-context:4.1.6
io.helidon.common:helidon-common-key-util:4.1.6
io.helidon.common:helidon-common-mapper:4.1.6
io.helidon.common:helidon-common-media-type:4.1.6
io.helidon.common:helidon-common-parameters:4.1.6
io.helidon.common:helidon-common-security:4.1.6
io.helidon.common:helidon-common-socket:4.1.6
io.helidon.common:helidon-common-task:4.1.6
io.helidon.common:helidon-common-tls:4.1.6
io.helidon.common:helidon-common-uri:4.1.6
io.helidon.common.concurrency:helidon-common-concurrency-limits:4.1.6
io.helidon.common.features:helidon-common-features:4.1.6
io.helidon.common.features:helidon-common-features-api:4.1.6
io.helidon.config:helidon-config:4.1.6
io.helidon.config:helidon-config-yaml:4.1.6
io.helidon.cors:helidon-cors:4.1.6
io.helidon.health:helidon-health:4.1.6
io.helidon.health:helidon-health-checks:4.1.6
io.helidon.http:helidon-http:4.1.6
io.helidon.http.encoding:helidon-http-encoding:4.1.6
io.helidon.http.media:helidon-http-media:4.1.6
io.helidon.logging:helidon-logging-common:4.1.6
io.helidon.webserver:helidon-webserver:4.1.6
io.helidon.webserver:helidon-webserver-cors:4.1.6
org.yaml:snakeyaml:2.2
```

Regenerate with `./mvnw dependency:list -DincludeScope=runtime`.
</details>

### Build tooling (downloaded automatically)

Maven 3.9.9 (via wrapper 3.3.4) · maven-compiler-plugin 3.13.0 · maven-surefire-plugin 3.2.5 · maven-shade-plugin 3.6.0 · maven-enforcer-plugin 3.5.0 (enforces Java ≥ 21, Maven ≥ 3.8).

Dependency updates are proposed automatically each week by Dependabot and go through the same pull-request review as any other change (see below).

---

## Repository Layout

```
AIGIS/
├── README.md                 ← you are here
├── SPECIFICATION.md          ← the AIGIS protocol (normative)
├── CHANGELOG.md              ← every release and modification, newest first
├── CONTRIBUTING.md           ← how to propose changes; PR and protocol-change process
├── SECURITY.md               ← how to report vulnerabilities privately
├── LICENSE                   ← MIT
├── pom.xml                   ← build + pinned dependencies
├── mvnw, mvnw.cmd, .mvn/     ← Maven wrapper (no Maven install needed)
├── src/main/java/io/kymatech/aigis/
│   ├── AigisApplication.java             ← entry point, config, HTTP server
│   ├── route/AigisRoutes.java            ← REST API
│   └── identity/
│       ├── AgentSerialNumber.java        ← serial format + identity hash
│       ├── PrompterIdentity.java         ← one-way prompter hash
│       ├── ActionOwnershipRecord.java    ← Agent+Prompter+Provider binding
│       └── AgentSerializationService.java← registry logic
├── src/main/resources/application.yaml
├── src/test/java/...                     ← JUnit tests
└── .github/                  ← CI, PR template, issue templates, CODEOWNERS, Dependabot
```

---

## Specification vs. Reference Implementation

[`SPECIFICATION.md`](SPECIFICATION.md) defines the full AIGIS protocol. This repository's code is the **reference implementation, v1.0.0**, and implements the core of it today. Being explicit about what is and isn't built yet:

| Capability | Specification | Reference implementation v1.0.0 |
|---|---|---|
| Deterministic SHA-256 agent identity + serial number | ✅ | ✅ (format `AIGIS-{CAT}-{hash8}-{seq6}`; see note) |
| Prompter identity (one-way hash, no PII) | ✅ | ✅ |
| Agent + Prompter + Provider ownership binding | ✅ | ✅ |
| Record integrity verification | ✅ | ✅ (SHA-256 recomputation) |
| Suspension and revocation | ✅ | ✅ |
| Public registry, lookup, stats | ✅ | ✅ |
| API-key protected write endpoints | ✅ | ✅ |
| Persistent storage | ✅ | ⏳ in-memory only — data is lost on restart |
| Doubly-chained path ledger | ✅ | ⏳ planned |
| Ed25519-signed entries / Merkle anchoring | ✅ | ⏳ planned (can forward events to an external audit chain via `AUDIT_CHAIN_URL`) |
| Mandate attenuation, lineage revocation | ✅ | ⏳ planned |
| RFC 9421 HTTP message signatures | ✅ | ⏳ planned |
| Federation | future version | — |

Note: the specification's serial format (`AIGIS-{PROVIDER}-{MODEL_HASH}-{SEQ}-{TIMESTAMP}-{CHECK}`) and endpoint paths (`/api/v1/agents/...`) differ from the reference implementation's (`AIGIS-{CAT}-{hash8}-{seq6}`, `/api/v1/aigis/...`). Aligning the two is tracked as protocol work; contributions that close any ⏳ item are very welcome.

---

## Alignment with Standards

| Standard | Alignment |
|----------|-----------|
| **EU AI Act** | Agent registration, provider identification, risk classification documentation |
| **NIST AI RMF** | Governance function (GV), transparency, accountability |
| **CISA Five Eyes Guidance** | AI system identification and inventory |
| **CAISI / NCCoE** | Agent identification standards initiative |
| **ISO/IEC 42001** | AI management system controls |
| **DoD Directive 3000.09** | Autonomous system identification and oversight |

---

## Contributing, Pull Requests, and Change Control

All changes — code, dependencies, and the protocol itself — go through pull requests. Nobody, including maintainers, pushes directly to `main`.

1. Fork, branch (`feature/…`, `fix/…`, `protocol/…`), commit, open a PR.
2. **Every PR must:**
   - pass CI (`./mvnw clean verify` on Java 21),
   - add an entry under `## [Unreleased]` in [`CHANGELOG.md`](CHANGELOG.md),
   - complete the PR template checklist,
   - be approved by a code owner (see [`.github/CODEOWNERS`](.github/CODEOWNERS)).
3. **Changes to `SPECIFICATION.md`** are protocol changes: open a *Protocol change proposal* issue first, label the PR `protocol-change`, and state whether it is backward compatible. Breaking changes require a major protocol version bump.

Full details: [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Versioning and Upgrade Tracking

- **Semantic Versioning** for both the protocol (`SPECIFICATION.md` header) and the reference implementation (`pom.xml`).
  - MAJOR — breaking change to serial format, API, or protocol semantics
  - MINOR — backward-compatible additions
  - PATCH — fixes and dependency updates
- **[`CHANGELOG.md`](CHANGELOG.md)** records every modification, newest first ([Keep a Changelog](https://keepachangelog.com/) format).
- **Git tags** (`v1.0.0`, …) and **GitHub Releases** mark each version; each release attaches the runnable `aigis.jar`.
- **Dependabot** opens weekly PRs for Maven and GitHub Actions updates; each one is reviewed, tested by CI, and logged in the changelog.

## Security

Please **do not** open public issues for vulnerabilities. See [`SECURITY.md`](SECURITY.md) — report privately to **partners@kymatech.io** or via GitHub's private vulnerability reporting.

## License and Patent Notice

The AIGIS protocol and this reference implementation are released under the **[MIT License](LICENSE)** — free for anyone to use, copy, modify, merge, publish, distribute, sublicense, and sell, provided the copyright notice is retained.

Related enforcement and governance technologies (outside this repository) are covered by U.S. Provisional Patent Application 63/789,142 and related pending applications, and remain proprietary to the inventor. The MIT License grants full rights to everything in this repository.

## Author

**Russell Lea Renison**
KYMA Tech Solutions — Costa Mesa, CA
[kymatech.io](https://kymatech.io) · partners@kymatech.io

AIGIS is the open identity layer of the **ICOSA** AI governance platform. For enterprise governance, policy enforcement, and compliance built on AIGIS, visit [kymatech.io](https://kymatech.io).
