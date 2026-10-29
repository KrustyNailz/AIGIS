package io.kymatech.aigis.identity;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Logger;

/**
 * AI-GIS Agent Serialization Service — the central registry that assigns, tracks, and
 * enforces unique identity for every AI model and agent.
 *
 * Standalone: runs independently with zero ICOSA platform dependencies.
 * Integrated: when connected to an ICOSA deployment, AORs are sealed into the
 * Rigel audit chain and tokens are gated by Betelgeuse policy enforcement.
 *
 * AI-GIS: Agent Identity Governance & Identification Serialization
 * Codename: Black Reigns
 * Patent Pending: continuation-in-part of App. No. 63/789,142
 */
public class AgentSerializationService {
    private static final Logger LOG = Logger.getLogger(AgentSerializationService.class.getName());

    private final Map<String, AgentSerialNumber> serialsByHash = new ConcurrentHashMap<>();
    private final Map<String, AgentSerialNumber> serialsByNumber = new ConcurrentHashMap<>();
    private final Map<String, PrompterIdentity> prompters = new ConcurrentHashMap<>();
    private final Map<String, ActionOwnershipRecord> ownershipRecords = new ConcurrentHashMap<>();
    private final AtomicLong modelSeq = new AtomicLong(0);
    private final AtomicLong agentSeq = new AtomicLong(0);
    private final AtomicLong systemSeq = new AtomicLong(0);
    private final AtomicLong embeddedSeq = new AtomicLong(0);

    private final String auditChainUrl;
    private final HttpClient http;

    public AgentSerializationService(String auditChainUrl) {
        this.auditChainUrl = auditChainUrl;
        this.http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();
    }

    public AgentSerialNumber registerAgent(String provider, String modelName,
                                            String modelVersion, String category,
                                            String spiffeId, Map<String, String> metadata) {
        Instant now = Instant.now();
        String fullHash = AgentSerialNumber.computeIdentityHash(provider, modelName, modelVersion, now);
        long seq = nextSequence(category);
        String serial = AgentSerialNumber.formatSerial(category, fullHash, seq);

        AgentSerialNumber sn = new AgentSerialNumber(
            serial, fullHash, category, provider, modelName, modelVersion,
            spiffeId, now, now, seq,
            AgentSerialNumber.SerializationStatus.ACTIVE,
            metadata != null ? metadata : Map.of());

        serialsByHash.put(fullHash, sn);
        serialsByNumber.put(serial, sn);
        sealToAuditChain("AGENT_REGISTRATION", sn.toAuditPayload());

        LOG.info("[AI-GIS] Registered " + serial + " | provider=" + provider + " | model=" + modelName);
        return sn;
    }

    public Optional<AgentSerialNumber> lookupBySerial(String serial) {
        return Optional.ofNullable(serialsByNumber.get(serial));
    }

    public Optional<AgentSerialNumber> lookupByHash(String hash) {
        return Optional.ofNullable(serialsByHash.get(hash));
    }

    public PrompterIdentity registerPrompter(String orgId, String authIdentity,
                                              String authMethod,
                                              PrompterIdentity.PrompterType type,
                                              String spiffeId) {
        String hash = PrompterIdentity.computePrompterHash(orgId, authIdentity, authMethod);
        PrompterIdentity existing = prompters.get(hash);
        Instant firstSeen = existing != null ? existing.firstSeen() : Instant.now();
        long count = existing != null ? existing.actionCount() : 0;

        PrompterIdentity id = new PrompterIdentity(
            hash, orgId, authMethod, spiffeId, firstSeen, Instant.now(), count, type, Map.of());
        prompters.put(hash, id);
        return id;
    }

    public ActionOwnershipRecord createOwnershipRecord(String agentSerial, String prompterHash,
                                                        String providerId, String actionType,
                                                        String actionTarget, String payloadHash,
                                                        String verdict) {
        Optional<AgentSerialNumber> agent = lookupBySerial(agentSerial);
        if (agent.isEmpty() || !agent.get().isActive()) {
            LOG.warning("[AI-GIS] DENIED — agent not found/inactive: " + agentSerial);
            return null;
        }
        if (!prompters.containsKey(prompterHash)) {
            LOG.warning("[AI-GIS] DENIED — prompter not registered: " + prompterHash);
            return null;
        }

        Instant now = Instant.now();
        ActionOwnershipRecord record = new ActionOwnershipRecord(
            null, agentSerial, agent.get().fullHash(), prompterHash, providerId,
            actionType, actionTarget, payloadHash, "", now, now.plusSeconds(5),
            "", verdict != null ? verdict : "PENDING", Map.of());

        ownershipRecords.put(record.recordHash(), record);
        sealToAuditChain("ACTION_OWNERSHIP", record.toAuditPayload());

        // Update prompter action count
        PrompterIdentity p = prompters.get(prompterHash);
        if (p != null) {
            prompters.put(prompterHash, new PrompterIdentity(
                p.prompterHash(), p.organizationId(), p.authenticationType(),
                p.spiffeId(), p.firstSeen(), now, p.actionCount() + 1,
                p.type(), p.metadata()));
        }

        // Update agent last-seen
        AgentSerialNumber a = agent.get();
        AgentSerialNumber updated = new AgentSerialNumber(
            a.serialNumber(), a.fullHash(), a.category(), a.provider(),
            a.modelName(), a.modelVersion(), a.spiffeId(), a.firstSeen(),
            now, a.sequenceNumber(), a.status(), a.metadata());
        serialsByHash.put(a.fullHash(), updated);
        serialsByNumber.put(a.serialNumber(), updated);

        LOG.info("[AI-GIS] AOR sealed | agent=" + agentSerial + " | action=" + actionType);
        return record;
    }

    public boolean suspendAgent(String serial) {
        AgentSerialNumber existing = serialsByNumber.get(serial);
        if (existing == null) return false;
        AgentSerialNumber suspended = new AgentSerialNumber(
            existing.serialNumber(), existing.fullHash(), existing.category(),
            existing.provider(), existing.modelName(), existing.modelVersion(),
            existing.spiffeId(), existing.firstSeen(), Instant.now(),
            existing.sequenceNumber(), AgentSerialNumber.SerializationStatus.SUSPENDED,
            existing.metadata());
        serialsByNumber.put(serial, suspended);
        serialsByHash.put(existing.fullHash(), suspended);
        sealToAuditChain("AGENT_SUSPENDED", Map.of("serialNumber", serial, "at", Instant.now().toString()));
        LOG.info("[AI-GIS] SUSPENDED " + serial);
        return true;
    }

    public boolean revokeAgent(String serial) {
        AgentSerialNumber existing = serialsByNumber.get(serial);
        if (existing == null) return false;
        AgentSerialNumber revoked = new AgentSerialNumber(
            existing.serialNumber(), existing.fullHash(), existing.category(),
            existing.provider(), existing.modelName(), existing.modelVersion(),
            existing.spiffeId(), existing.firstSeen(), Instant.now(),
            existing.sequenceNumber(), AgentSerialNumber.SerializationStatus.REVOKED,
            existing.metadata());
        serialsByNumber.put(serial, revoked);
        serialsByHash.put(existing.fullHash(), revoked);
        sealToAuditChain("AGENT_REVOKED", Map.of("serialNumber", serial, "at", Instant.now().toString()));
        LOG.info("[AI-GIS] REVOKED " + serial);
        return true;
    }

    public boolean verifyOwnershipRecord(String recordHash) {
        ActionOwnershipRecord r = ownershipRecords.get(recordHash);
        return r != null && r.verifyIntegrity();
    }

    public List<ActionOwnershipRecord> getAgentHistory(String serial) {
        return ownershipRecords.values().stream()
            .filter(r -> r.agentSerial().equals(serial))
            .sorted(Comparator.comparing(ActionOwnershipRecord::timestamp).reversed())
            .toList();
    }

    public List<ActionOwnershipRecord> getPrompterHistory(String hash) {
        return ownershipRecords.values().stream()
            .filter(r -> r.prompterHash().equals(hash))
            .sorted(Comparator.comparing(ActionOwnershipRecord::timestamp).reversed())
            .toList();
    }

    public List<AgentSerialNumber> listAll() {
        return serialsByNumber.values().stream()
            .sorted(Comparator.comparing(AgentSerialNumber::firstSeen).reversed())
            .toList();
    }

    public Map<String, Object> getStats() {
        long active = serialsByNumber.values().stream().filter(AgentSerialNumber::isActive).count();
        long suspended = serialsByNumber.values().stream()
            .filter(s -> s.status() == AgentSerialNumber.SerializationStatus.SUSPENDED).count();
        long revoked = serialsByNumber.values().stream()
            .filter(s -> s.status() == AgentSerialNumber.SerializationStatus.REVOKED).count();
        return Map.of(
            "totalRegistered", serialsByNumber.size(),
            "active", active, "suspended", suspended, "revoked", revoked,
            "promptersTracked", prompters.size(),
            "ownershipRecords", ownershipRecords.size());
    }

    private long nextSequence(String category) {
        return switch (category.toUpperCase()) {
            case "MDL" -> modelSeq.incrementAndGet();
            case "AGT" -> agentSeq.incrementAndGet();
            case "SYS" -> systemSeq.incrementAndGet();
            case "EMB" -> embeddedSeq.incrementAndGet();
            default -> modelSeq.incrementAndGet();
        };
    }

    private void sealToAuditChain(String eventType, Map<String, Object> payload) {
        if (auditChainUrl == null || auditChainUrl.isBlank()) return;
        try {
            String json = "{\"verdict\":\"ALLOW\",\"modelId\":\"aigis-serialization\",\"vendorId\":\"aigis\","
                + "\"inputHash\":\"" + sha256(eventType + payload) + "\","
                + "\"outputHash\":\"" + sha256(payload.toString()) + "\","
                + "\"metadata\":{\"eventType\":\"" + eventType + "\"}}";
            http.sendAsync(
                HttpRequest.newBuilder()
                    .uri(URI.create(auditChainUrl + "/append"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json))
                    .timeout(Duration.ofSeconds(5))
                    .build(),
                HttpResponse.BodyHandlers.ofString()
            ).exceptionally(ex -> { LOG.fine("[AI-GIS] Audit chain unreachable"); return null; });
        } catch (Exception e) {
            LOG.fine("[AI-GIS] Audit chain error: " + e.getMessage());
        }
    }

    private static String sha256(String input) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(h);
        } catch (Exception e) { return "hash-error"; }
    }
}
