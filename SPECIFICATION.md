# AIGIS Protocol Specification

**Version:** 1.0.0
**Date:** October 29, 2026
**Author:** Russell Lea Renison
**License:** Apache License 2.0

---

## 1. Overview

AIGIS (Agent Identity Governance and Identification Standard) defines a protocol for assigning, registering, verifying, and managing unique identities for AI agent instances. The protocol establishes a universal standard for agent accountability across the AI ecosystem.

## 2. Agent Serial Number Format

### 2.1 Structure

```
AIGIS-{PROVIDER_CODE}-{MODEL_HASH}-{INSTANCE_SEQ}-{TIMESTAMP}-{CHECKSUM}
```

| Field | Length | Description |
|-------|--------|-------------|
| `AIGIS` | 5 | Protocol identifier (fixed) |
| `PROVIDER_CODE` | 2-8 | Registered provider abbreviation |
| `MODEL_HASH` | 4 | First 4 hex chars of SHA-256 of model identifier |
| `INSTANCE_SEQ` | 4 | Zero-padded sequential instance number |
| `TIMESTAMP` | 18 | ISO 8601 compact UTC creation time (YYYYMMDDTHHmmssZ) |
| `CHECKSUM` | 4 | First 4 hex chars of SHA-256 of preceding fields |

### 2.2 Generation Rules

1. Serial numbers are generated at agent instantiation time
2. The provider code must be pre-registered with an AIGIS registry
3. Instance sequence numbers are monotonically increasing per provider
4. Timestamps use UTC exclusively
5. The checksum is computed over the concatenation of all preceding fields (including hyphens)
6. Serial numbers are immutable once assigned — they cannot be reused or reassigned

### 2.3 Examples

```
AIGIS-ANTH-7f3a-0001-20261029T050000Z-a4b2    (Anthropic Claude instance)
AIGIS-OAI-3b2c-0142-20261029T120000Z-f7e1     (OpenAI GPT instance)
AIGIS-META-9d4e-0007-20261029T080000Z-c3a9     (Meta Llama instance)
AIGIS-CUST-1a2b-0001-20261029T090000Z-d5f3     (Custom/self-hosted instance)
```

## 3. Registration Protocol

### 3.1 Agent Registration

To register a new agent, a provider submits a registration request to an AIGIS registry.

**Request:**
```json
POST /api/v1/agents/register
Content-Type: application/json

{
  "model": {
    "name": "claude-sonnet-5-5",
    "version": "2026-10-01",
    "provider": "anthropic"
  },
  "deployer": {
    "id": "org-123456",
    "name": "Acme Corp",
    "contact": "ai-ops@acme.com"
  },
  "prompter": {
    "id": "user-789",
    "role": "operator",
    "organization": "org-123456"
  },
  "mandate": {
    "purpose": "customer-support-tier-1",
    "capabilities": ["text-generation", "tool-use", "web-search"],
    "restrictions": ["no-code-execution", "no-financial-transactions"],
    "expiry": "2027-10-29T00:00:00Z"
  }
}
```

**Response:**
```json
{
  "serial": "AIGIS-ANTH-7f3a-0001-20261029T050000Z-a4b2",
  "status": "ACTIVE",
  "registered_at": "2026-10-29T05:00:00Z",
  "registry_url": "https://registry.aigis-protocol.org",
  "certificate": {
    "issuer": "AIGIS Registry Authority",
    "valid_from": "2026-10-29T05:00:00Z",
    "valid_until": "2027-10-29T00:00:00Z",
    "fingerprint": "sha256:a1b2c3d4..."
  }
}
```

### 3.2 Registration Fields

| Field | Required | Description |
|-------|----------|-------------|
| `model.name` | Yes | Model identifier |
| `model.version` | Yes | Model version or release date |
| `model.provider` | Yes | Model provider (Anthropic, OpenAI, Meta, etc.) |
| `deployer.id` | Yes | Unique deployer organization ID |
| `deployer.name` | Yes | Human-readable organization name |
| `deployer.contact` | Yes | Contact for incident response |
| `prompter.id` | Yes | Individual or system that instructed the agent |
| `prompter.role` | Yes | Role classification (operator, developer, automated) |
| `mandate.purpose` | Yes | Declared purpose of the agent |
| `mandate.capabilities` | Yes | Permitted capability set |
| `mandate.restrictions` | No | Explicit prohibitions |
| `mandate.expiry` | No | Mandate expiration (default: 1 year) |

## 4. Path Ledger

### 4.1 Overview

The path ledger is a doubly-chained, append-only record of an agent's operational checkpoints. Each entry links to both the previous and next entries via cryptographic hashes, providing tamper-evident provenance.

### 4.2 Ledger Entry Schema

```json
{
  "entry_id": "uuid-v4",
  "serial": "AIGIS-ANTH-7f3a-0001-20261029T050000Z-a4b2",
  "sequence": 42,
  "timestamp": "2026-10-29T05:30:00Z",
  "checkpoint_type": "ACTION | MANDATE_CHANGE | TRANSFER | SUSPENSION | REVOCATION",
  "data": {
    "action": "web-search",
    "context": "customer-support-session-789",
    "outcome": "completed"
  },
  "prev_hash": "sha256:...",
  "curr_hash": "sha256:...",
  "signature": "ed25519:..."
}
```

### 4.3 Chain Integrity

- **Forward chain:** Each entry's `curr_hash` includes the `prev_hash`, creating an append-only forward chain
- **Backward chain:** Upon next entry creation, the previous entry's record is updated with a `next_hash` pointer
- **Signatures:** Each entry is signed with the registry's Ed25519 key
- **Verification:** Any party can verify chain integrity by walking forward or backward and validating hashes

### 4.4 Checkpoint Types

| Type | Description |
|------|-------------|
| `ACTION` | Agent performed a registered action |
| `MANDATE_CHANGE` | Agent's mandate was narrowed (attenuation only — mandates can never widen) |
| `TRANSFER` | Agent ownership transferred to a new operator |
| `SUSPENSION` | Agent temporarily suspended |
| `REVOCATION` | Agent permanently revoked |
| `REACTIVATION` | Previously suspended agent reactivated |

## 5. Ownership and Mandate Attenuation

### 5.1 Ownership Records

Every agent has exactly one owner at any point in time. Ownership transfers are recorded in the path ledger.

```json
{
  "serial": "AIGIS-ANTH-7f3a-0001-20261029T050000Z-a4b2",
  "current_owner": {
    "id": "org-123456",
    "since": "2026-10-29T05:00:00Z"
  },
  "ownership_history": [
    {
      "owner": "org-123456",
      "from": "2026-10-29T05:00:00Z",
      "to": null,
      "transfer_reason": "CREATION"
    }
  ]
}
```

### 5.2 Mandate Attenuation

A core safety principle of AIGIS: **mandates can only narrow, never widen.**

- An agent created with `["text-generation", "tool-use", "web-search"]` capabilities can have capabilities removed but never added
- Restriction lists can grow but never shrink
- This ensures that delegation through chains of agents always reduces privilege, never escalates it

## 6. Verification API

### 6.1 Verify Agent Identity

```
GET /api/v1/agents/verify/{serial}
```

Returns the agent's current registration status, owner, and mandate.

### 6.2 Query Path Ledger

```
GET /api/v1/agents/{serial}/ledger?from={timestamp}&to={timestamp}
```

Returns ledger entries for the specified time range.

### 6.3 Verify Chain Integrity

```
GET /api/v1/agents/{serial}/ledger/verify
```

Walks the full chain and returns integrity status.

### 6.4 HTTP Message Signatures (RFC 9421)

Agent requests to external services SHOULD include an HTTP message signature per RFC 9421, with the agent's serial number in the signature parameters. This allows receiving services to verify agent identity inline without a separate registry lookup.

## 7. Revocation and Suspension

### 7.1 Suspension

A suspended agent's serial remains valid but is marked inactive. Suspended agents MUST NOT be granted access to secured resources. Suspension is reversible.

### 7.2 Revocation

A revoked agent's serial is permanently deactivated. Revocation is irreversible. The serial number is never reassigned.

### 7.3 Lineage Revocation

When an agent that has spawned child agents is revoked, all child agents in its lineage tree are automatically suspended pending review. This prevents orphaned agents from continuing to operate under a revoked parent's authority.

## 8. Federation

AIGIS registries can federate, allowing multiple registry operators while maintaining a unified namespace. Federation details will be specified in a future version of this document.

## 9. Security Considerations

- All registry communications MUST use TLS 1.3+
- Ed25519 signatures on all ledger entries
- Serial numbers contain no personally identifiable information
- Registry access controls are provider-configurable
- Rate limiting on registration and verification endpoints

## 10. Conformance

An implementation conforms to AIGIS if it:

1. Generates serial numbers according to Section 2
2. Implements the registration protocol per Section 3
3. Maintains a path ledger per Section 4
4. Enforces mandate attenuation per Section 5.2
5. Provides verification endpoints per Section 6
6. Implements revocation and suspension per Section 7
