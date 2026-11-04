# AIGIS Protocol Specification

**AIGIS: Serialization & Identification Protocol**
**Version:** 1.0.0
**Date:** November 3, 2026
**Author:** Russell Lea Renison, KYMA Tech Solutions
**License:** Apache License 2.0

The key words MUST, MUST NOT, SHOULD and MAY are to be interpreted as described in RFC 2119.
Sections 1–8 are normative and are implemented by the reference implementation in this
repository. Section 9 is a non-normative roadmap.

---

## 1. Overview

AIGIS assigns every AI model and agent a permanent serial number and records, for each action
an agent takes, three accountable parties:

1. **Agent**: the model or agent that acted, identified by its AIGIS serial number.
2. **Prompter**: the human or system that instructed it, identified by a one-way hash.
3. **Provider**: the organization that supplies or hosts the agent.

A registry stores serials, prompters and Action Ownership Records (AORs) and answers public
lookups, so anyone can check who stands behind an agent and whether it is still active.

## 2. Agent Serial Number

### 2.1 Format

```
AIGIS-{CAT}-{HASH8}-{SEQ6}

AIGIS-AGT-bc2b4ac4-000001
```

| Field | Description |
|---|---|
| `AIGIS` | Protocol identifier (fixed) |
| `CAT` | Category: `MDL` foundation model, `AGT` autonomous agent, `SYS` multi-agent system, `EMB` embedded model |
| `HASH8` | First 8 lowercase hex characters of the identity hash (2.2) |
| `SEQ6` | Issue sequence within the category at this registry, zero-padded to 6 digits (wider if it overflows) |

Regular expression: `^AIGIS-(MDL|AGT|SYS|EMB)-[0-9a-f]{8}-\d{6,}$`

### 2.2 Identity hash

```
identityHash = SHA-256( norm(provider) | norm(modelName) | norm(modelVersion) | firstSeen )
```

- `norm(x)` is `x` trimmed and lowercased; a missing `modelVersion` is `"unknown"`.
- `firstSeen` is the registration instant in ISO-8601 UTC (`Instant.toString()` form).
- `|` is a literal vertical bar. The hash is encoded as 64 lowercase hex characters.

Because `firstSeen` is part of the hash, registering the same model twice yields two distinct
serials. Anyone holding the four inputs can recompute the hash and confirm the serial was not
altered (`integrityVerified` in lookups).

### 2.3 Rules

1. A serial is assigned once, at registration, and is never reused or reassigned.
2. Sequences are monotonically increasing per category and MUST continue across restarts.
3. A serial carries no personal data.

## 3. Prompter Identity

```
prompterHash = SHA-256( norm(organizationId) | norm(authenticatedIdentity) | norm(authMethod) )
```

The registry stores only the hash, the organization ID, the authentication method and the
prompter type (`HUMAN`, `SYSTEM`, `AGENT_UPSTREAM`, `API_CLIENT`, `SCHEDULED_TASK`). The hash is
one-way: it cannot be reversed to reveal the identity, but the prompter can prove it by
presenting the same inputs.

## 4. Action Ownership Record (AOR)

An AOR binds one action to the agent, prompter and provider:

| Field | Description |
|---|---|
| `agentSerial`, `agentFullHash` | The acting agent |
| `prompterHash` | The instructing prompter |
| `providerId` | The supplying provider |
| `actionType`, `actionTarget`, `actionPayloadHash` | What was done, to what, and a hash of the payload |
| `timestamp` | When (ISO-8601 UTC) |
| `verdict` | Free-form outcome, default `PENDING` |
| `recordHash` | `SHA-256(agentSerial|prompterHash|providerId|actionType|actionTarget|timestamp)` |

A registry MUST refuse an AOR unless the agent is `ACTIVE` and both the agent and the prompter
belong to the caller (Section 6). Anyone MAY verify an AOR by its `recordHash`; verification
recomputes the hash from the stored fields.

## 5. Status: suspension and revocation

| Status | Meaning |
|---|---|
| `ACTIVE` | The agent may be attached to new AORs. |
| `SUSPENDED` | Temporarily inactive; new AORs are refused. |
| `REVOKED` | Permanently inactive. Irreversible; the serial is never reassigned. |

Status changes MUST be recorded with their time and MUST survive registry restarts.

## 6. Ownership and access control

- Every agent and prompter has exactly one owner: the credential that registered it.
- Only the owner (or the registry administrator) may suspend or revoke an agent, attach AORs
  to it, or read its action history.
- A registry that fronts many users (for example a gateway issuing per-user API keys)
  authenticates each user itself and forwards the user's identity to the registry. In the
  reference implementation the gateway sends the registry's service key in `X-AIGIS-Key` and
  the user's ID in `X-AIGIS-Owner`; the registry MUST ignore `X-AIGIS-Owner` from callers that
  do not hold the service key. A call with the service key and no owner acts as administrator.
- Registries SHOULD cap registrations per owner and rate-limit registration.

## 7. Registry API

Base path `/api/v1/aigis`. All bodies are JSON.

| Method | Path | Access | Result |
|---|---|---|---|
| GET | `/protocol` | public | Protocol summary |
| GET | `/registry?page=0&size=25` | public | Registry page, newest first; `size` 1–100 |
| GET | `/lookup/{serial}` | public | Agent, with `integrityVerified` |
| GET | `/lookup/hash/{identityHash}` | public | Agent |
| GET | `/verify/{recordHash}` | public | 200 if the AOR exists and verifies, else 404 |
| GET | `/stats` | public | Counts of agents by status, prompters and AORs |
| POST | `/register` | credential | `{provider*, modelName*, modelVersion, category (MDL\|AGT\|SYS\|EMB), spiffeId}` → 201 agent; 429 at the owner's limit |
| POST | `/prompter` | credential | `{organizationId*, authenticatedIdentity, authMethod, type, spiffeId}` → 201 |
| POST | `/ownership` | owner | `{agentSerial*, prompterHash*, providerId*, actionType*, actionTarget, actionPayloadHash, verdict}` → 201 AOR, or 403 |
| GET | `/history/agent/{serial}` | owner | Up to 100 most recent AORs |
| GET | `/history/prompter/{hash}` | owner | Up to 100 most recent AORs |
| POST | `/suspend/{serial}` | owner | 200, 403 or 404 |
| POST | `/revoke/{serial}` | owner | 200, 403 or 404 |

`*` = required. Text fields are limited to 200 characters. Unknown categories are rejected with 400.

## 8. Durability and audit

- A conforming registry MUST persist agents, status changes, prompters and AORs so that a
  restart loses nothing. The reference implementation appends every change to a JSON-lines
  journal and replays it on startup.
- A registry MAY additionally forward each event to an external tamper-evident audit chain.
  The reference implementation does so when `AUDIT_CHAIN_URL` is set, POSTing to
  `{AUDIT_CHAIN_URL}/record`.
- Deployments MUST serve the API over TLS.

## 9. Roadmap (non-normative)

Planned for future versions, subject to change through the protocol-change process in
[CONTRIBUTING.md](CONTRIBUTING.md):

- **Path ledger:** an append-only, hash-chained record of each agent's checkpoints (actions,
  mandate changes, transfers, status changes), with registry signatures on each entry.
- **Mandates and attenuation:** a declared purpose and capability set per agent that can only
  narrow over time, never widen.
- **Ownership transfer** recorded in the ledger.
- **Lineage:** parent/child relationships between agents, with suspension of a revoked
  agent's descendants pending review.
- **RFC 9421 HTTP Message Signatures** carrying the agent's serial, so services can verify an
  agent inline.
- **Federation** between independently operated registries under one namespace.

## 10. Conformance

An implementation conforms to AIGIS 1.0 if it implements Sections 2 through 8.
