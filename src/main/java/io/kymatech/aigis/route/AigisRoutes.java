package io.kymatech.aigis.route;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.helidon.webserver.http.HttpRules;
import io.helidon.webserver.http.HttpService;
import io.helidon.webserver.http.ServerRequest;
import io.helidon.webserver.http.ServerResponse;
import io.kymatech.aigis.identity.*;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Logger;

/**
 * AI-GIS REST API — Agent Identity Governance & Identification Serialization.
 *
 * Public endpoints (no auth):
 *   GET  /protocol        — Protocol specification (open standard)
 *   GET  /registry        — Public registry of all serialized agents
 *   GET  /lookup/{serial} — Look up agent by AIGIS serial number
 *   GET  /lookup/hash/{h} — Look up agent by identity hash
 *   GET  /verify/{hash}   — Verify ownership record integrity
 *   GET  /stats           — Registry statistics
 *
 * Authenticated endpoints (API key or SPIFFE mTLS):
 *   POST /register        — Register a model/agent → receive AIGIS serial
 *   POST /prompter        — Register a prompter identity
 *   POST /ownership       — Create an Action Ownership Record
 *   GET  /history/agent/{s}   — Agent action history
 *   GET  /history/prompter/{h} — Prompter action history
 *   POST /suspend/{serial}    — Suspend an agent serial
 *   POST /revoke/{serial}     — Permanently revoke an agent serial
 *
 * Codename: Black Reigns
 */
public class AigisRoutes implements HttpService {
    private static final Logger LOG = Logger.getLogger(AigisRoutes.class.getName());
    private static final ObjectMapper JSON = new ObjectMapper()
        .registerModule(new JavaTimeModule())
        .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    private final AgentSerializationService service;
    private final String apiKey;

    public AigisRoutes(AgentSerializationService service, String apiKey) {
        this.service = service;
        this.apiKey = apiKey;
    }

    @Override
    public void routing(HttpRules rules) {
        rules
            // Public
            .get("/protocol", this::protocol)
            .get("/registry", this::registry)
            .get("/lookup/{serial}", this::lookupBySerial)
            .get("/lookup/hash/{hash}", this::lookupByHash)
            .get("/verify/{recordHash}", this::verify)
            .get("/stats", this::stats)
            // Authenticated
            .post("/register", this::register)
            .post("/prompter", this::registerPrompter)
            .post("/ownership", this::createOwnership)
            .get("/history/agent/{serial}", this::agentHistory)
            .get("/history/prompter/{hash}", this::prompterHistory)
            .post("/suspend/{serial}", this::suspend)
            .post("/revoke/{serial}", this::revoke);
    }

    // ── Public ───────────────────────────────────────────────────

    private void protocol(ServerRequest req, ServerResponse res) {
        send(res, 200, Map.ofEntries(
            Map.entry("protocol", "AI-GIS: Agent Identity Governance & Identification Serialization"),
            Map.entry("codename", "Black Reigns"),
            Map.entry("version", "1.0.0"),
            Map.entry("license", "Apache License 2.0 — freely available for global adoption"),
            Map.entry("patent", "U.S. Provisional App. No. 64/186,696"),
            Map.entry("referenceImplementation", "ICOSA Platform by Kymatech, Inc."),
            Map.entry("description", "A deterministic, tamper-evident identity and accountability protocol "
                + "for AI models and autonomous agents. Every agent receives a permanent AIGIS serial number. "
                + "Every action is bound to an Agent-Prompter-Provider ownership triple. "
                + "Every binding is sealed into a Merkle-anchored, Ed25519-signed audit chain. "
                + "Zero-trust enforcement via SPIFFE/SPIRE workload attestation."),
            Map.entry("serialFormat", "AIGIS-{CAT}-{8-char-SHA256}-{6-digit-sequence}"),
            Map.entry("categories", "MDL=Foundation Model, AGT=Autonomous Agent, SYS=Multi-Agent System, EMB=Embedded Model"),
            Map.entry("identityHash", "SHA-256(provider|modelName|modelVersion|firstSeenTimestamp)"),
            Map.entry("ownershipTriple", "Agent Serial + Prompter Hash + Provider ID"),
            Map.entry("auditChain", "Ed25519-signed, Merkle-root-anchored, tamper-evident (Rigel-compatible)")
        ));
    }

    private void registry(ServerRequest req, ServerResponse res) {
        List<AgentSerialNumber> all = service.listAll();
        var entries = all.stream().limit(500).map(sn -> Map.of(
            "serialNumber", (Object) sn.serialNumber(),
            "provider", sn.provider(),
            "modelName", sn.modelName(),
            "category", sn.category(),
            "status", sn.status().name(),
            "firstSeen", sn.firstSeen().toString()
        )).toList();

        send(res, 200, Map.of(
            "protocol", "AI-GIS v1.0.0",
            "totalRegistered", all.size(),
            "agents", entries
        ));
    }

    private void lookupBySerial(ServerRequest req, ServerResponse res) {
        String serial = req.path().pathParameters().get("serial");
        Optional<AgentSerialNumber> result = service.lookupBySerial(serial);

        if (result.isEmpty()) {
            send(res, 404, Map.of("error", "Serial not found", "serial", serial));
            return;
        }

        AgentSerialNumber sn = result.get();
        send(res, 200, Map.ofEntries(
            Map.entry("serialNumber", sn.serialNumber()),
            Map.entry("fullHash", sn.fullHash()),
            Map.entry("category", sn.category()),
            Map.entry("provider", sn.provider()),
            Map.entry("modelName", sn.modelName()),
            Map.entry("modelVersion", sn.modelVersion()),
            Map.entry("spiffeId", sn.spiffeId() != null ? sn.spiffeId() : ""),
            Map.entry("firstSeen", sn.firstSeen().toString()),
            Map.entry("lastSeen", sn.lastSeen().toString()),
            Map.entry("status", sn.status().name()),
            Map.entry("integrityVerified", sn.verifyIntegrity())
        ));
    }

    private void lookupByHash(ServerRequest req, ServerResponse res) {
        String hash = req.path().pathParameters().get("hash");
        Optional<AgentSerialNumber> result = service.lookupByHash(hash);
        if (result.isEmpty()) {
            send(res, 404, Map.of("error", "Hash not found"));
            return;
        }
        AgentSerialNumber sn = result.get();
        send(res, 200, Map.of(
            "serialNumber", sn.serialNumber(),
            "fullHash", sn.fullHash(),
            "provider", sn.provider(),
            "modelName", sn.modelName(),
            "status", sn.status().name()
        ));
    }

    private void verify(ServerRequest req, ServerResponse res) {
        String hash = req.path().pathParameters().get("recordHash");
        boolean valid = service.verifyOwnershipRecord(hash);
        send(res, 200, Map.of(
            "recordHash", hash,
            "integrityVerified", valid,
            "message", valid ? "Record integrity confirmed — hash matches fields"
                : "Record not found or integrity check failed"
        ));
    }

    private void stats(ServerRequest req, ServerResponse res) {
        send(res, 200, service.getStats());
    }

    // ── Authenticated ────────────────────────────────────────────

    private void register(ServerRequest req, ServerResponse res) {
        if (!authenticate(req, res)) return;
        try {
            Map<?, ?> body = JSON.readValue(req.content().as(String.class), Map.class);
            String provider = str(body, "provider");
            String modelName = str(body, "modelName");
            String modelVersion = str(body, "modelVersion", "unknown");
            String category = str(body, "category", "MDL");
            String spiffeId = str(body, "spiffeId", "");

            if (provider.isBlank() || modelName.isBlank()) {
                send(res, 400, Map.of("error", "provider and modelName are required"));
                return;
            }

            AgentSerialNumber sn = service.registerAgent(
                provider, modelName, modelVersion, category, spiffeId, Map.of());

            send(res, 201, Map.of(
                "serialNumber", sn.serialNumber(),
                "fullHash", sn.fullHash(),
                "category", sn.category(),
                "provider", sn.provider(),
                "modelName", sn.modelName(),
                "status", sn.status().name(),
                "firstSeen", sn.firstSeen().toString(),
                "message", "Agent registered. AIGIS serial number is permanent and audit-chain-anchored."
            ));
        } catch (Exception e) {
            send(res, 500, Map.of("error", "Registration failed: " + e.getMessage()));
        }
    }

    private void registerPrompter(ServerRequest req, ServerResponse res) {
        if (!authenticate(req, res)) return;
        try {
            Map<?, ?> body = JSON.readValue(req.content().as(String.class), Map.class);
            String orgId = str(body, "organizationId");
            String authId = str(body, "authenticatedIdentity", "");
            String authMethod = str(body, "authMethod", "api-key");
            String typeStr = str(body, "type", "HUMAN");
            String spiffeId = str(body, "spiffeId", "");

            if (orgId.isBlank()) {
                send(res, 400, Map.of("error", "organizationId is required"));
                return;
            }

            PrompterIdentity.PrompterType type;
            try { type = PrompterIdentity.PrompterType.valueOf(typeStr.toUpperCase()); }
            catch (IllegalArgumentException e) { type = PrompterIdentity.PrompterType.HUMAN; }

            PrompterIdentity id = service.registerPrompter(orgId, authId, authMethod, type, spiffeId);
            send(res, 201, Map.of(
                "prompterHash", id.prompterHash(),
                "organizationId", id.organizationId(),
                "type", id.type().name(),
                "actionCount", id.actionCount(),
                "message", "Prompter registered. Hash is one-way — cannot be reversed to reveal PII."
            ));
        } catch (Exception e) {
            send(res, 500, Map.of("error", e.getMessage()));
        }
    }

    private void createOwnership(ServerRequest req, ServerResponse res) {
        if (!authenticate(req, res)) return;
        try {
            Map<?, ?> body = JSON.readValue(req.content().as(String.class), Map.class);
            String agentSerial = str(body, "agentSerial");
            String prompterHash = str(body, "prompterHash");
            String providerId = str(body, "providerId");
            String actionType = str(body, "actionType");
            String actionTarget = str(body, "actionTarget", "");
            String payloadHash = str(body, "actionPayloadHash", "");
            String verdict = str(body, "verdict", "PENDING");

            if (agentSerial.isBlank() || prompterHash.isBlank()
                || providerId.isBlank() || actionType.isBlank()) {
                send(res, 400, Map.of("error",
                    "agentSerial, prompterHash, providerId, and actionType are required"));
                return;
            }

            ActionOwnershipRecord record = service.createOwnershipRecord(
                agentSerial, prompterHash, providerId, actionType,
                actionTarget, payloadHash, verdict);

            if (record == null) {
                send(res, 403, Map.of("error",
                    "Denied — agent serial not registered/active or prompter not registered"));
                return;
            }

            send(res, 201, Map.of(
                "recordHash", record.recordHash(),
                "agentSerial", record.agentSerial(),
                "prompterHash", record.prompterHash(),
                "providerId", record.providerId(),
                "actionType", record.actionType(),
                "verdict", record.verdict(),
                "timestamp", record.timestamp().toString(),
                "integrityVerified", record.verifyIntegrity(),
                "message", "Ownership record sealed. Action is attributed and tamper-evident."
            ));
        } catch (Exception e) {
            send(res, 500, Map.of("error", e.getMessage()));
        }
    }

    private void agentHistory(ServerRequest req, ServerResponse res) {
        if (!authenticate(req, res)) return;
        String serial = req.path().pathParameters().get("serial");
        List<ActionOwnershipRecord> records = service.getAgentHistory(serial);
        var entries = records.stream().limit(100).map(r -> Map.of(
            "recordHash", (Object) r.recordHash(),
            "actionType", r.actionType(),
            "verdict", r.verdict(),
            "timestamp", r.timestamp().toString()
        )).toList();
        send(res, 200, Map.of("agentSerial", serial, "total", records.size(), "records", entries));
    }

    private void prompterHistory(ServerRequest req, ServerResponse res) {
        if (!authenticate(req, res)) return;
        String hash = req.path().pathParameters().get("hash");
        List<ActionOwnershipRecord> records = service.getPrompterHistory(hash);
        send(res, 200, Map.of("prompterHash", hash, "total", records.size()));
    }

    private void suspend(ServerRequest req, ServerResponse res) {
        if (!authenticate(req, res)) return;
        String serial = req.path().pathParameters().get("serial");
        if (service.suspendAgent(serial)) {
            send(res, 200, Map.of("status", "SUSPENDED", "serial", serial));
        } else {
            send(res, 404, Map.of("error", "Serial not found"));
        }
    }

    private void revoke(ServerRequest req, ServerResponse res) {
        if (!authenticate(req, res)) return;
        String serial = req.path().pathParameters().get("serial");
        if (service.revokeAgent(serial)) {
            send(res, 200, Map.of("status", "REVOKED", "serial", serial,
                "message", "Permanent. This agent can never perform governed actions again."));
        } else {
            send(res, 404, Map.of("error", "Serial not found"));
        }
    }

    // ── Helpers ──────────────────────────────────────────────────

    private boolean authenticate(ServerRequest req, ServerResponse res) {
        if (apiKey == null || apiKey.isBlank()) return true; // standalone dev mode
        String provided = req.headers()
            .first(io.helidon.http.HeaderNames.create("X-AIGIS-Key"))
            .orElse(req.headers()
                .first(io.helidon.http.HeaderNames.create("Authorization"))
                .map(h -> h.startsWith("Bearer ") ? h.substring(7) : h)
                .orElse(""));
        if (!apiKey.equals(provided)) {
            send(res, 401, Map.of("error", "Authentication required",
                "detail", "Provide X-AIGIS-Key header or Bearer token"));
            return false;
        }
        return true;
    }

    private void send(ServerResponse res, int status, Object data) {
        try {
            res.status(status).send(JSON.writeValueAsString(data));
        } catch (Exception e) {
            res.status(500).send("{\"error\":\"JSON serialization failed\"}");
        }
    }

    private static String str(Map<?, ?> map, String key) {
        return str(map, key, "");
    }

    private static String str(Map<?, ?> map, String key, String def) {
        Object v = map.get(key);
        return v != null ? v.toString() : def;
    }
}
