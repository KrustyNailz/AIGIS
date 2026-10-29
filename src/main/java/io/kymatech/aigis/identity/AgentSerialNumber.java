package io.kymatech.aigis.identity;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;

/**
 * AI-GIS Agent Serial Number — a globally unique, deterministic, tamper-evident identifier
 * assigned to every AI model and agent encountered by the protocol.
 *
 * The serial number is a SHA-256 hash of the canonical identity tuple:
 *   (provider, modelName, modelVersion, firstSeenTimestamp)
 *
 * Format: AIGIS-{category}-{shortHash}-{sequence}
 *   Example: AIGIS-MDL-a3f7b219-000042
 *            AIGIS-AGT-e81c0d5f-000007
 *
 * Categories:
 *   MDL — Foundation model (e.g., GPT-4, Claude, Llama)
 *   AGT — Autonomous agent built on a model
 *   SYS — Multi-agent system or orchestrator
 *   EMB — Embedded model in a product/device
 *
 * AI-GIS: Agent Identity Governance & Identification Serialization
 * Codename: Black Reigns
 * Patent Pending: continuation-in-part of App. No. 63/789,142
 * Open Source Protocol — freely available for global adoption.
 */
public record AgentSerialNumber(
        String serialNumber,
        String fullHash,
        String category,
        String provider,
        String modelName,
        String modelVersion,
        String spiffeId,
        Instant firstSeen,
        Instant lastSeen,
        long sequenceNumber,
        SerializationStatus status,
        Map<String, String> metadata
) {

    public enum SerializationStatus {
        ACTIVE,
        SUSPENDED,
        REVOKED,
        EXPIRED,
        PENDING_VERIFICATION
    }

    public AgentSerialNumber {
        if (serialNumber == null || serialNumber.isBlank())
            throw new IllegalArgumentException("serialNumber required");
        if (fullHash == null || fullHash.isBlank())
            throw new IllegalArgumentException("fullHash required");
        if (category == null || category.isBlank())
            throw new IllegalArgumentException("category required");
        if (provider == null || provider.isBlank())
            throw new IllegalArgumentException("provider required");
        if (modelName == null || modelName.isBlank())
            throw new IllegalArgumentException("modelName required");
        if (firstSeen == null) firstSeen = Instant.now();
        if (lastSeen == null) lastSeen = firstSeen;
        if (status == null) status = SerializationStatus.ACTIVE;
        if (metadata == null) metadata = Map.of();
        if (modelVersion == null) modelVersion = "unknown";
    }

    public static String computeIdentityHash(String provider, String modelName,
                                              String modelVersion, Instant firstSeen) {
        String canonical = String.join("|",
            normalize(provider), normalize(modelName),
            normalize(modelVersion), firstSeen.toString());
        return sha256(canonical);
    }

    public static String formatSerial(String category, String fullHash, long sequence) {
        return String.format("AIGIS-%s-%s-%06d", category, fullHash.substring(0, 8), sequence);
    }

    public boolean isActive() { return status == SerializationStatus.ACTIVE; }

    public boolean verifyIntegrity() {
        return computeIdentityHash(provider, modelName, modelVersion, firstSeen).equals(fullHash);
    }

    public Map<String, Object> toAuditPayload() {
        return Map.of(
            "serialNumber", serialNumber,
            "fullHash", fullHash,
            "category", category,
            "provider", provider,
            "modelName", modelName,
            "modelVersion", modelVersion,
            "spiffeId", spiffeId != null ? spiffeId : "",
            "firstSeen", firstSeen.toString(),
            "status", status.name()
        );
    }

    private static String normalize(String input) {
        return input == null ? "" : input.trim().toLowerCase();
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
