package io.kymatech.aigis.identity;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;

/**
 * AI-GIS Prompter Identity — the human or system that initiates an agentic action.
 *
 * The identity hash is a one-way SHA-256 of verifiable credentials. It cannot be
 * reversed to reveal PII, but the prompter can prove ownership by reproducing the
 * hash from their original credentials. A court order or organizational lookup can
 * map the hash back to the individual.
 *
 * Solves: "who told the agent to do that?"
 *
 * AI-GIS: Agent Identity Governance & Identification Serialization
 * Codename: Black Reigns
 */
public record PrompterIdentity(
        String prompterHash,
        String organizationId,
        String authenticationType,
        String spiffeId,
        Instant firstSeen,
        Instant lastAction,
        long actionCount,
        PrompterType type,
        Map<String, String> metadata
) {

    public enum PrompterType {
        HUMAN,
        SYSTEM,
        AGENT_UPSTREAM,
        API_CLIENT,
        SCHEDULED_TASK
    }

    public PrompterIdentity {
        if (prompterHash == null || prompterHash.isBlank())
            throw new IllegalArgumentException("prompterHash required");
        if (organizationId == null || organizationId.isBlank())
            throw new IllegalArgumentException("organizationId required");
        if (authenticationType == null) authenticationType = "none";
        if (firstSeen == null) firstSeen = Instant.now();
        if (lastAction == null) lastAction = firstSeen;
        if (type == null) type = PrompterType.HUMAN;
        if (metadata == null) metadata = Map.of();
    }

    public static String computePrompterHash(String organizationId,
                                              String authenticatedIdentity,
                                              String authMethod) {
        String canonical = String.join("|",
            normalize(organizationId), normalize(authenticatedIdentity),
            normalize(authMethod));
        return sha256(canonical);
    }

    public Map<String, Object> toAuditPayload() {
        return Map.of(
            "prompterHash", prompterHash,
            "organizationId", organizationId,
            "authenticationType", authenticationType,
            "spiffeId", spiffeId != null ? spiffeId : "",
            "type", type.name(),
            "actionCount", actionCount,
            "lastAction", lastAction.toString()
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
