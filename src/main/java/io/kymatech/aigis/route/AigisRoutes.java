package io.kymatech.aigis.route;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.helidon.http.HeaderNames;
import io.helidon.webserver.http.HttpRules;
import io.helidon.webserver.http.HttpService;
import io.helidon.webserver.http.ServerRequest;
import io.helidon.webserver.http.ServerResponse;
import io.kymatech.aigis.identity.*;
import io.kymatech.aigis.identity.AgentSerializationService.Change;

import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * AIGIS REST API: Serialization &amp; Identification Protocol.
 *
 * Public endpoints (no auth):
 *   GET  /protocol            Protocol summary
 *   GET  /registry?page&size  Public registry, newest first (size 1-100, default 25)
 *   GET  /lookup/{serial}     Look up an agent by AIGIS serial number
 *   GET  /lookup/hash/{h}     Look up an agent by identity hash
 *   GET  /verify/{hash}       Verify an Action Ownership Record's integrity
 *   GET  /stats               Registry counters
 *
 * Authenticated endpoints (X-AIGIS-Key or Authorization: Bearer):
 *   POST /register            Register a model/agent and receive its AIGIS serial
 *   POST /prompter            Register a prompter identity
 *   POST /ownership           Create an Action Ownership Record for one of your agents
 *   GET  /history/agent/{s}   Action history of one of your agents
 *   GET  /history/prompter/{h} Action history of one of your prompters
 *   POST /suspend/{serial}    Suspend one of your agents
 *   POST /revoke/{serial}     Permanently revoke one of your agents
 *
 * Ownership: every agent and prompter belongs to the caller that registered it. A gateway
 * that fronts many users authenticates them itself, calls this service with the service key,
 * and names the user in {@code X-AIGIS-Owner}. A call with the service key and no owner header
 * acts as the administrator.
 */
public class AigisRoutes implements HttpService {
    private static final Logger LOG = Logger.getLogger(AigisRoutes.class.getName());
    private static final ObjectMapper JSON = new ObjectMapper()
        .registerModule(new JavaTimeModule())
        .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    private static final int MAX_FIELD = 200;

    /**
     * Allowed characters for anything that can appear in the public registry or in a verified
     * record: letters, digits, space and a few separators. Rules out markup, control characters,
     * URLs-with-queries and other content an attacker could plant in a public listing.
     */
    private static final Pattern NAME_FIELD = Pattern.compile("^[\\p{L}\\p{N}][\\p{L}\\p{N} ._:/@+()-]{0,99}$");
    private static final Pattern SPIFFE_ID = Pattern.compile("^spiffe://[A-Za-z0-9._-]{1,100}(/[A-Za-z0-9._-]{1,64}){0,8}$");
    private static final Pattern TOKEN_FIELD = Pattern.compile("^[A-Za-z0-9._:-]{1,64}$");
    private static final Pattern HEX = Pattern.compile("^[0-9a-fA-F]{0,128}$");
    private static final Pattern NO_CONTROL = Pattern.compile("^[^\\p{Cntrl}]{0,200}$");

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
            .get("/lookup/hash/{hash}", this::lookupByHash)
            .get("/lookup/{serial}", this::lookupBySerial)
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
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("protocol", "AIGIS: Serialization & Identification Protocol");
        body.put("version", "1.0.0");
        body.put("license", "Apache License 2.0");
        body.put("source", "https://github.com/KrustyNailz/AIGIS");
        body.put("description", "Gives every AI model and agent a permanent serial number and records, for each "
            + "action, which agent performed it, which prompter asked for it, and which provider supplied the model. "
            + "Identity hashes and record hashes are SHA-256, so any later change to a record is detectable.");
        body.put("serialFormat", "AIGIS-{CAT}-{first 8 hex of identity hash}-{6-digit sequence per category}");
        body.put("categories", Map.of("MDL", "Foundation model", "AGT", "Autonomous agent",
            "SYS", "Multi-agent system", "EMB", "Embedded model"));
        body.put("identityHash", "SHA-256(lower(trim(provider))|lower(trim(modelName))|lower(trim(modelVersion))|firstSeen ISO-8601)");
        body.put("ownershipTriple", "Agent serial + prompter hash + provider ID");
        body.put("persistence", service.isPersistent() ? "Append-only registry journal, replayed on restart" : "In memory");
        body.put("auditChain", service.isAuditChainEnabled()
            ? "Enabled: registrations, status changes and ownership records are also appended to an external audit chain"
            : "Not configured");
        body.put("publisher", "KYMA Tech Solutions (kymatech.io)");
        body.put("architect", "Russell \"Sage\" Renison (Kymatech, Inc.)");
        body.put("contributors", "Ed Bratt, Claude Code (Anthropic)");
        send(res, 200, body);
    }

    private void registry(ServerRequest req, ServerResponse res) {
        int size = clamp(intParam(req, "size", 25), 1, 100);
        int page = Math.max(0, intParam(req, "page", 0));
        var entries = service.page(page, size).stream().map(sn -> Map.of(
            "serialNumber", (Object) sn.serialNumber(),
            "provider", sn.provider(),
            "modelName", sn.modelName(),
            "category", sn.category(),
            "status", sn.status().name(),
            "firstSeen", sn.firstSeen().toString()
        )).toList();
        send(res, 200, Map.of(
            "protocol", "AIGIS v1.0.0",
            "totalRegistered", service.totalRegistered(),
            "page", page,
            "size", size,
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
        send(res, 200, describe(result.get()));
    }

    private void lookupByHash(ServerRequest req, ServerResponse res) {
        String hash = req.path().pathParameters().get("hash");
        Optional<AgentSerialNumber> result = service.lookupByHash(hash);
        if (result.isEmpty()) {
            send(res, 404, Map.of("error", "Hash not found"));
            return;
        }
        send(res, 200, describe(result.get()));
    }

    private void verify(ServerRequest req, ServerResponse res) {
        String hash = req.path().pathParameters().get("recordHash");
        Optional<ActionOwnershipRecord> record = service.getOwnershipRecord(hash);
        boolean valid = record.isPresent() && record.get().verifyIntegrity();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("recordHash", hash);
        body.put("integrityVerified", valid);
        record.ifPresent(r -> {
            body.put("agentSerial", r.agentSerial());
            body.put("actionType", r.actionType());
            body.put("timestamp", r.timestamp().toString());
        });
        body.put("message", valid ? "Record found and its hash matches its fields"
            : "Record not found or integrity check failed");
        send(res, valid ? 200 : 404, body);
    }

    private void stats(ServerRequest req, ServerResponse res) {
        send(res, 200, service.getStats());
    }

    // ── Authenticated ────────────────────────────────────────────

    private void register(ServerRequest req, ServerResponse res) {
        String owner = authenticate(req, res);
        if (owner == null) return;
        Map<?, ?> body = readBody(req, res);
        if (body == null) return;
        String provider = str(body, "provider").trim();
        String modelName = str(body, "modelName").trim();
        String modelVersion = str(body, "modelVersion", "unknown").trim();
        String category = str(body, "category", "MDL").trim().toUpperCase();
        String spiffeId = str(body, "spiffeId", "").trim();

        if (provider.isBlank() || modelName.isBlank()) {
            send(res, 400, Map.of("error", "provider and modelName are required"));
            return;
        }
        if (!NAME_FIELD.matcher(provider).matches() || !NAME_FIELD.matcher(modelName).matches()
            || !NAME_FIELD.matcher(modelVersion).matches()) {
            send(res, 400, Map.of("error", "provider, modelName and modelVersion may contain letters, digits, "
                + "spaces and . _ : / @ + ( ) - (up to 100 characters)"));
            return;
        }
        if (!spiffeId.isEmpty() && !SPIFFE_ID.matcher(spiffeId).matches()) {
            send(res, 400, Map.of("error", "spiffeId must be a spiffe:// URI"));
            return;
        }
        if (!AgentSerializationService.CATEGORIES.contains(category)) {
            send(res, 400, Map.of("error", "category must be one of MDL, AGT, SYS, EMB"));
            return;
        }
        try {
            AgentSerialNumber sn = service.registerAgent(owner, provider, modelName, modelVersion,
                category, spiffeId, Map.of());
            Map<String, Object> out = new LinkedHashMap<>(describe(sn));
            out.put("message", "Agent registered. Its AIGIS serial number is permanent.");
            send(res, 201, out);
        } catch (AgentSerializationService.QuotaExceededException e) {
            send(res, 429, Map.of("error", e.getMessage()));
        } catch (AgentSerializationService.CapacityException e) {
            LOG.warning("[AIGIS] " + e.getMessage());
            send(res, 503, Map.of("error", e.getMessage()));
        } catch (Exception e) {
            LOG.warning("[AIGIS] Registration failed: " + e.getMessage());
            send(res, 500, Map.of("error", "Registration failed"));
        }
    }

    private void registerPrompter(ServerRequest req, ServerResponse res) {
        String owner = authenticate(req, res);
        if (owner == null) return;
        Map<?, ?> body = readBody(req, res);
        if (body == null) return;
        String orgId = str(body, "organizationId").trim();
        String authId = str(body, "authenticatedIdentity", "");
        String authMethod = str(body, "authMethod", "api-key");
        String typeStr = str(body, "type", "HUMAN");
        String spiffeId = str(body, "spiffeId", "");

        if (orgId.isBlank()) {
            send(res, 400, Map.of("error", "organizationId is required"));
            return;
        }
        if (!NAME_FIELD.matcher(orgId).matches() || !TOKEN_FIELD.matcher(authMethod).matches()
            || !NO_CONTROL.matcher(authId).matches()) {
            send(res, 400, Map.of("error", "organizationId may contain letters, digits, spaces and . _ : / @ + ( ) -; "
                + "authMethod letters, digits and . _ : -"));
            return;
        }
        if (!spiffeId.isEmpty() && !SPIFFE_ID.matcher(spiffeId).matches()) {
            send(res, 400, Map.of("error", "spiffeId must be a spiffe:// URI"));
            return;
        }
        PrompterIdentity.PrompterType type;
        try { type = PrompterIdentity.PrompterType.valueOf(typeStr.toUpperCase()); }
        catch (IllegalArgumentException e) { type = PrompterIdentity.PrompterType.HUMAN; }

        try {
            PrompterIdentity id = service.registerPrompter(owner, orgId, authId, authMethod, type, spiffeId);
            send(res, 201, Map.of(
                "prompterHash", id.prompterHash(),
                "organizationId", id.organizationId(),
                "type", id.type().name(),
                "actionCount", id.actionCount(),
                "message", "Prompter registered. The hash is one-way: it does not reveal the identity behind it."
            ));
        } catch (SecurityException e) {
            send(res, 403, Map.of("error", e.getMessage()));
        } catch (AgentSerializationService.QuotaExceededException e) {
            send(res, 429, Map.of("error", e.getMessage()));
        } catch (AgentSerializationService.CapacityException e) {
            send(res, 503, Map.of("error", e.getMessage()));
        }
    }

    private void createOwnership(ServerRequest req, ServerResponse res) {
        String owner = authenticate(req, res);
        if (owner == null) return;
        Map<?, ?> body = readBody(req, res);
        if (body == null) return;
        String agentSerial = str(body, "agentSerial");
        String prompterHash = str(body, "prompterHash");
        String providerId = str(body, "providerId");
        String actionType = str(body, "actionType");
        String actionTarget = str(body, "actionTarget", "");
        String payloadHash = str(body, "actionPayloadHash", "");
        String verdict = str(body, "verdict", "PENDING");

        if (agentSerial.isBlank() || prompterHash.isBlank() || providerId.isBlank() || actionType.isBlank()) {
            send(res, 400, Map.of("error", "agentSerial, prompterHash, providerId, and actionType are required"));
            return;
        }
        if (!NAME_FIELD.matcher(providerId).matches() || !TOKEN_FIELD.matcher(actionType).matches()
            || !TOKEN_FIELD.matcher(verdict).matches() || !HEX.matcher(payloadHash).matches()
            || !NO_CONTROL.matcher(actionTarget).matches()) {
            send(res, 400, Map.of("error", "Invalid field: actionType and verdict allow letters, digits and . _ : - "
                + "(up to 64); actionPayloadHash must be hex; no control characters"));
            return;
        }
        ActionOwnershipRecord record;
        try {
            record = service.createOwnershipRecord(owner, agentSerial, prompterHash,
                providerId, actionType, actionTarget, payloadHash, verdict);
        } catch (AgentSerializationService.QuotaExceededException e) {
            send(res, 429, Map.of("error", e.getMessage()));
            return;
        } catch (AgentSerializationService.CapacityException e) {
            send(res, 503, Map.of("error", e.getMessage()));
            return;
        }
        if (record == null) {
            send(res, 403, Map.of("error",
                "Denied: the agent must be one of your active agents and the prompter one you registered"));
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
            "message", "Ownership record created. Anyone can verify it at /verify/{recordHash}."
        ));
    }

    private void agentHistory(ServerRequest req, ServerResponse res) {
        String owner = authenticate(req, res);
        if (owner == null) return;
        String serial = req.path().pathParameters().get("serial");
        if (service.lookupBySerial(serial).isEmpty()) {
            send(res, 404, Map.of("error", "Serial not found"));
            return;
        }
        if (!service.isOwner(serial, owner)) {
            send(res, 403, Map.of("error", "Only the API key that registered this agent can read its history"));
            return;
        }
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
        String owner = authenticate(req, res);
        if (owner == null) return;
        String hash = req.path().pathParameters().get("hash");
        if (!service.isPrompterOwner(hash, owner)) {
            send(res, 403, Map.of("error", "Only the API key that registered this prompter can read its history"));
            return;
        }
        List<ActionOwnershipRecord> records = service.getPrompterHistory(hash);
        var entries = records.stream().limit(100).map(r -> Map.of(
            "recordHash", (Object) r.recordHash(),
            "agentSerial", r.agentSerial(),
            "actionType", r.actionType(),
            "timestamp", r.timestamp().toString()
        )).toList();
        send(res, 200, Map.of("prompterHash", hash, "total", records.size(), "records", entries));
    }

    private void suspend(ServerRequest req, ServerResponse res) {
        String owner = authenticate(req, res);
        if (owner == null) return;
        String serial = req.path().pathParameters().get("serial");
        respondToChange(res, serial, service.suspendAgent(serial, owner),
            Map.of("status", "SUSPENDED", "serial", serial));
    }

    private void revoke(ServerRequest req, ServerResponse res) {
        String owner = authenticate(req, res);
        if (owner == null) return;
        String serial = req.path().pathParameters().get("serial");
        respondToChange(res, serial, service.revokeAgent(serial, owner),
            Map.of("status", "REVOKED", "serial", serial,
                "message", "Permanent. This serial can no longer be attached to new actions."));
    }

    private void respondToChange(ServerResponse res, String serial, Change change, Map<String, Object> ok) {
        switch (change) {
            case OK -> send(res, 200, ok);
            case NOT_FOUND -> send(res, 404, Map.of("error", "Serial not found", "serial", serial));
            case FORBIDDEN -> send(res, 403, Map.of("error", "Only the API key that registered this agent can change it"));
        }
    }

    // ── Helpers ──────────────────────────────────────────────────

    private static Map<String, Object> describe(AgentSerialNumber sn) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("serialNumber", sn.serialNumber());
        m.put("fullHash", sn.fullHash());
        m.put("category", sn.category());
        m.put("provider", sn.provider());
        m.put("modelName", sn.modelName());
        m.put("modelVersion", sn.modelVersion());
        m.put("spiffeId", sn.spiffeId() != null ? sn.spiffeId() : "");
        m.put("firstSeen", sn.firstSeen().toString());
        m.put("lastSeen", sn.lastSeen().toString());
        m.put("status", sn.status().name());
        m.put("integrityVerified", sn.verifyIntegrity());
        return m;
    }

    /**
     * Returns the caller's owner ID, or null after sending 401.
     * No key configured (local dev): everyone is the administrator unless they name an owner.
     */
    private String authenticate(ServerRequest req, ServerResponse res) {
        Optional<String> ownerHeader = req.headers().first(HeaderNames.create("X-AIGIS-Owner"))
            .map(String::trim).filter(o -> !o.isEmpty() && o.length() <= MAX_FIELD);
        if (apiKey == null || apiKey.isBlank()) {
            return ownerHeader.orElse(AgentSerializationService.ADMIN_OWNER);
        }
        String provided = req.headers()
            .first(HeaderNames.create("X-AIGIS-Key"))
            .orElse(req.headers()
                .first(HeaderNames.AUTHORIZATION)
                .map(h -> h.startsWith("Bearer ") ? h.substring(7) : h)
                .orElse(""));
        if (!MessageDigest.isEqual(apiKey.getBytes(StandardCharsets.UTF_8), provided.getBytes(StandardCharsets.UTF_8))) {
            send(res, 401, Map.of("error", "Authentication required",
                "detail", "Provide X-AIGIS-Key header or Bearer token"));
            return null;
        }
        return ownerHeader.orElse(AgentSerializationService.ADMIN_OWNER);
    }

    private Map<?, ?> readBody(ServerRequest req, ServerResponse res) {
        try {
            Map<?, ?> body = JSON.readValue(req.content().as(String.class), Map.class);
            if (body != null) return body;
        } catch (Exception ignored) {
            // fall through
        }
        send(res, 400, Map.of("error", "Request body must be a JSON object"));
        return null;
    }

    private void send(ServerResponse res, int status, Object data) {
        try {
            res.status(status);
            res.header("Content-Type", "application/json");
            res.send(JSON.writeValueAsString(data));
        } catch (Exception e) {
            res.status(500).send("{\"error\":\"JSON serialization failed\"}");
        }
    }

    private static int intParam(ServerRequest req, String name, int def) {
        try {
            return req.query().first(name).map(Integer::parseInt).orElse(def);
        } catch (NumberFormatException e) {
            return def;
        }
    }

    private static int clamp(int v, int lo, int hi) { return Math.max(lo, Math.min(hi, v)); }

    private static String str(Map<?, ?> map, String key) {
        return str(map, key, "");
    }

    private static String str(Map<?, ?> map, String key, String def) {
        Object v = map.get(key);
        return v != null ? v.toString() : def;
    }
}
