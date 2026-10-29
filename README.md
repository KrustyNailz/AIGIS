# AIGIS — Agent Identity Governance and Identification Standard

**An open-source protocol for identifying, registering, and tracking AI agents.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## The Problem

AI agents are operating at scale with no universal identity layer. There is no standardized way to know:

- **Who** deployed an agent
- **What** an agent is authorized to do
- **Where** an agent has been
- **Who is liable** when an agent goes rogue

Regulators worldwide — the EU AI Act, NIST AI RMF, CISA Five Eyes guidance — are placing the burden of accountability on prompters and providers. But without a way to identify and register agents, accountability is unenforceable.

## The Solution

AIGIS (Agent Identity Governance and Identification Standard) is an open-source protocol that provides:

### Agent Serial Numbers
Every AI agent instance receives a unique, verifiable serial identity at creation time — a deterministic identifier derived from its model, provider, deployment context, and creation timestamp.

```
Format: AIGIS-{PROVIDER}-{MODEL_HASH}-{INSTANCE}-{TIMESTAMP}-{CHECK}
Example: AIGIS-ANTH-7f3a-0001-20261029T050000Z-a4b2
```

### Central Registry
A registration authority that maintains the authoritative record of:
- **Agent identity** — serial number, model, version, capabilities
- **Prompter** — who instructed the agent (individual or organization)
- **Provider** — who deployed and operates the agent
- **Mandate** — what the agent is authorized to do
- **Status** — active, suspended, revoked, retired

### Path Ledger
A doubly-chained, append-only record of an agent's operational history:
- Every action checkpoint is registered
- Forward and backward hash chains ensure tamper evidence
- Full provenance trail from creation through retirement

### Ownership Records
Clear chain of custody documenting:
- Who created the agent
- Who currently operates it
- Transfer history
- Mandate attenuation (permissions can only narrow, never widen)

## Why Open Source

This protocol is donated to the AI industry at no cost. Agent identification is infrastructure — it should be a shared standard, not a proprietary product. AIGIS is designed for universal adoption:

- **For developers:** Register your agents. Know what's running. Demonstrate compliance.
- **For providers:** Track deployed agents. Manage liability. Respond to incidents.
- **For enterprises:** Require agent identification before granting access to your systems.
- **For regulators:** A verifiable, auditable standard for agent accountability.

## Alignment with Standards

AIGIS is designed to satisfy requirements from:

| Standard | Alignment |
|----------|-----------|
| **EU AI Act** | Agent registration, provider identification, risk classification documentation |
| **NIST AI RMF** | Governance function (GV), transparency, accountability |
| **CISA Five Eyes Guidance** | AI system identification and inventory |
| **CAISI / NCCoE** | Agent identification standards initiative |
| **ISO/IEC 42001** | AI management system controls |
| **DOD 3000.09** | Autonomous system identification and oversight |

## Protocol Specification

See [`SPECIFICATION.md`](SPECIFICATION.md) for the full protocol definition, including:
- Serial number format and generation
- Registration API
- Path ledger schema
- Ownership transfer protocol
- Verification endpoints
- Revocation and suspension

## Quick Start

```bash
# Register a new agent
POST /api/v1/agents/register
{
  "model": "claude-sonnet-5-5",
  "provider": "your-org-id",
  "prompter": "operator-id",
  "mandate": "customer-support-tier-1",
  "capabilities": ["text-generation", "tool-use"]
}

# Response
{
  "serial": "AIGIS-ANTH-7f3a-0001-20261029T050000Z-a4b2",
  "status": "ACTIVE",
  "registered": "2026-10-29T05:00:00Z",
  "registry": "https://registry.aigis-protocol.org"
}

# Verify an agent's identity
GET /api/v1/agents/verify/AIGIS-ANTH-7f3a-0001-20261029T050000Z-a4b2

# Check an agent's path ledger
GET /api/v1/agents/AIGIS-ANTH-7f3a-0001-20261029T050000Z-a4b2/ledger
```

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  AIGIS Registry                  │
│                                                  │
│  ┌──────────┐  ┌──────────┐  ┌───────────────┐  │
│  │  Agent    │  │  Path    │  │  Ownership    │  │
│  │  Serial   │  │  Ledger  │  │  Records      │  │
│  │  Registry │  │          │  │               │  │
│  └──────────┘  └──────────┘  └───────────────┘  │
│                                                  │
│  ┌──────────────────────────────────────────┐    │
│  │         Verification API (RFC 9421)      │    │
│  └──────────────────────────────────────────┘    │
└─────────────────────────────────────────────────┘
         │              │              │
    ┌────▼────┐   ┌─────▼─────┐  ┌────▼─────┐
    │ Agent A │   │  Agent B  │  │ Agent C  │
    │ AIGIS-  │   │  AIGIS-   │  │ AIGIS-   │
    │ xxxx    │   │  yyyy     │  │ zzzz     │
    └─────────┘   └───────────┘  └──────────┘
```

## Project Status

| Component | Status |
|-----------|--------|
| Protocol Specification | Complete |
| Serial Number Format | Complete |
| Registration Schema | Complete |
| Path Ledger Schema | Complete |
| Verification API Spec | Complete |
| Reference Implementation | In Development |
| Registry Service | In Development |

## Patent Notice

The AIGIS identification and registry protocol is released under the MIT License for free use by the industry. Related enforcement and governance technologies are covered by U.S. Provisional Patent Applications 63/789,142 and [pending] and remain proprietary to the inventor.

## Author

**Russell Lea Renison**
KYMA Tech Solutions — Costa Mesa, CA
[kymatech.io](https://kymatech.io)

## License

MIT — See [LICENSE](LICENSE) for details.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
