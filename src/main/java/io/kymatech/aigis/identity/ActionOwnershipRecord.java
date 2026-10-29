package io.kymatech.aigis.identity;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;

/**
 * AI-GIS Action Ownership Record (AOR) — the triple-bind that links every agentic
 * action to exactly three accountable parties:
 *
 *   1. AGENT    — the model/agent that performed the action (AgentSerialNumber)
 *   2. PROMPTER — the human/system that initiated it (PrompterIdentity)
 *   3. PROVIDER — the organization hosting/serving the agent
 *
 * No AOR = no token = no action. The audit chain proves WHO did WHAT via WHICH
 * agent, and that proof is tamper-evident (Ed25519 signed, Merkle anchored).
 *
 * AI-GIS: Agent Identity Governance & Identification Serialization
 * Codename: Black Reigns
 */
public record ActionOwnershipRecord(
        String recordHash,
        String agentSerial,
        String agentFullHash,
        String prompterHash,
        String providerId,
        String actionType,
        String actionTarget,
        String actionPayloadHash,
        String capabilityTokenHash,
        Instant timestamp,
        Instant tokenExpiry,
        String auditChainSequence,
        String verdict,
        Map<String, String> metadata
) {

    public ActionOwnershipRecord {
        if (agentSerial == null || agentSerial.isBlank())
            throw new IllegalArgumentException("agentSerial required");
        if (prompterHash == null || prompterHash.isBlank())
            throw new IllegalArgumentException("prompterHash required");
        if (providerId == null || providerId.isBlank())
            throw new IllegalArgumentException("providerId required");
        if (actionType == null || actionType.isBlank())
            throw new IllegalArgumentException("actionType required");
        if (timestamp == null) timestamp = Instant.now();
        if (verdict == null) verdict = "PENDING";
        if (metadata == null) metadata = Map.of();
        if (actionTarget == null) actionTarget = "";
        if (actionPayloadHash == null) actionPayloadHash = "";
        if (capabilityTokenHash == null) capabilityTokenHash = "";
        if (auditChainSequence == null) auditChainSequence = "";
        if (tokenExpiry == null) tokenExpiry = timestamp.plusSeconds(5);
        if (recordHash == null || recordHash.isBlank()) {
            recordHash = computeRecordHash(agentSerial, prompterHash, providerId,
                actionType, actionTarget, timestamp);
        }
    }

    public static String computeRecordHash(String agentSerial, String prompterHash,
                                            String providerId, String actionType,
                                            String actionTarget, Instant timestamp) {
        String canonical = String.join("|",
            agentSerial, prompterHash, providerId, actionType,
            actionTarget != null ? actionTarget : "", timestamp.toString());
        return sha256(canonical);
    }

    public boolean verifyIntegrity() {
        return computeRecordHash(agentSerial, prompterHash, providerId,
            actionType, actionTarget, timestamp).equals(recordHash);
    }

    public Map<String, Object> toAuditPayload() {
        return Map.ofEntries(
            Map.entry("recordHash", recordHash),
            Map.entry("agentSerial", agentSerial),
            Map.entry("agentFullHash", agentFullHash != null ? agentFullHash : ""),
            Map.entry("prompterHash", prompterHash),
            Map.entry("providerId", providerId),
            Map.entry("actionType", actionType),
            Map.entry("actionTarget", actionTarget),
            Map.entry("actionPayloadHash", actionPayloadHash),
            Map.entry("capabilityTokenHash", capabilityTokenHash),
            Map.entry("verdict", verdict),
            Map.entry("timestamp", timestamp.toString()),
            Map.entry("tokenExpiry", tokenExpiry.toString())
        );
    }

    private static String sha256(String input) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256")
                .digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
