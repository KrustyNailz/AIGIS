package io.kymatech.aigis.identity;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import java.io.BufferedWriter;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Logger;

/**
 * AIGIS registry: assigns permanent serial numbers to AI models and agents, records which
 * prompter and provider own each action, and answers public lookups.
 *
 * Every registration belongs to an owner (the API key that created it). Only that owner can
 * suspend, revoke, attach actions to, or read the action history of its agents.
 *
 * Persistence: when a data directory is given, every change is appended to
 * {@code registry.jsonl} and replayed on startup, so the registry survives restarts.
 * Without one, the registry is in memory only (tests, quick experiments).
 *
 * Optional audit chain: when {@code auditChainUrl} is set (e.g. an ICOSA deployment's
 * {@code /api/v1/audit}), each registration, status change and ownership record is also
 * appended to that chain via {@code POST {auditChainUrl}/record}.
 */
public class AgentSerializationService {
    private static final Logger LOG = Logger.getLogger(AgentSerializationService.class.getName());

    public static final Set<String> CATEGORIES = Set.of("MDL", "AGT", "SYS", "EMB");
    /** Owner used when the API is called with the service key and no per-user owner. */
    public static final String ADMIN_OWNER = "admin";

    /** Thrown when an owner already holds the maximum number of serials. */
    public static class QuotaExceededException extends RuntimeException {
        public QuotaExceededException(int limit) {
            super("Registration limit reached (" + limit + " agents per API key)");
        }
    }

    /** Thrown when the registry as a whole is at capacity; the API answers 503 instead of running out of memory. */
    public static class CapacityException extends RuntimeException {
        public CapacityException(String what) {
            super("The registry is at capacity for " + what + "; try again later");
        }
    }

    public enum Change { OK, NOT_FOUND, FORBIDDEN }

    /** Per-owner ceilings on prompters and ownership records (agents use maxAgentsPerOwner). */
    public static final int MAX_PROMPTERS_PER_OWNER = 1_000;
    public static final int MAX_RECORDS_PER_OWNER = 100_000;

    private static final ObjectMapper JSON = new ObjectMapper()
        .registerModule(new JavaTimeModule())
        .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
        .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES); // e.g. "active" from isActive()

    private final Map<String, AgentSerialNumber> serialsByHash = new ConcurrentHashMap<>();
    private final Map<String, AgentSerialNumber> serialsByNumber = new ConcurrentHashMap<>();
    private final Map<String, String> agentOwners = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> ownerCounts = new ConcurrentHashMap<>();
    /** Serials in registration order, for newest-first paging without sorting the registry. */
    private final List<String> registrationOrder = Collections.synchronizedList(new ArrayList<>());

    private final Map<String, PrompterIdentity> prompters = new ConcurrentHashMap<>();
    private final Map<String, String> prompterOwners = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> ownerPrompterCounts = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> ownerRecordCounts = new ConcurrentHashMap<>();
    private long maxTotalAgents = Long.MAX_VALUE;
    private long maxTotalPrompters = Long.MAX_VALUE;
    private long maxTotalRecords = Long.MAX_VALUE;

    private final Map<String, ActionOwnershipRecord> ownershipRecords = new ConcurrentHashMap<>();
    private final Map<String, List<String>> recordsByAgent = new ConcurrentHashMap<>();
    private final Map<String, List<String>> recordsByPrompter = new ConcurrentHashMap<>();

    private final Map<String, AtomicLong> sequences = new ConcurrentHashMap<>();
    private final Map<AgentSerialNumber.SerializationStatus, AtomicLong> statusCounts =
        new EnumMap<>(AgentSerialNumber.SerializationStatus.class);

    private final String auditChainUrl;
    private final int maxAgentsPerOwner;
    private final Path journal;
    private final HttpClient http;
    private BufferedWriter journalWriter;
    private boolean replaying;

    /** In-memory registry with no audit chain and no quota (tests, experiments). */
    public AgentSerializationService(String auditChainUrl) {
        this(auditChainUrl, null, Integer.MAX_VALUE);
    }

    public AgentSerializationService(String auditChainUrl, Path dataDir, int maxAgentsPerOwner) {
        this.auditChainUrl = auditChainUrl == null ? "" : auditChainUrl.replaceAll("/+$", "");
        this.maxAgentsPerOwner = maxAgentsPerOwner;
        this.journal = dataDir == null ? null : dataDir.resolve("registry.jsonl");
        for (AgentSerialNumber.SerializationStatus s : AgentSerialNumber.SerializationStatus.values()) {
            statusCounts.put(s, new AtomicLong());
        }
        for (String c : CATEGORIES) sequences.put(c, new AtomicLong());
        this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
        if (journal != null) openJournal(dataDir);
    }

    /** Registry-wide ceilings, sized to the heap so a flood of registrations cannot crash the service. */
    public AgentSerializationService withCapacity(long agents, long prompters, long records) {
        this.maxTotalAgents = agents;
        this.maxTotalPrompters = prompters;
        this.maxTotalRecords = records;
        return this;
    }

    public boolean isPersistent() { return journal != null; }

    public boolean isAuditChainEnabled() { return !auditChainUrl.isBlank(); }

    // ── Agents ───────────────────────────────────────────────────

    public AgentSerialNumber registerAgent(String provider, String modelName,
                                           String modelVersion, String category,
                                           String spiffeId, Map<String, String> metadata) {
        return registerAgent(ADMIN_OWNER, provider, modelName, modelVersion, category, spiffeId, metadata);
    }

    public synchronized AgentSerialNumber registerAgent(String owner, String provider, String modelName,
                                                        String modelVersion, String category,
                                                        String spiffeId, Map<String, String> metadata) {
        String cat = category == null ? "" : category.trim().toUpperCase();
        if (!CATEGORIES.contains(cat)) throw new IllegalArgumentException("category must be one of " + CATEGORIES);
        AtomicLong held = ownerCounts.computeIfAbsent(owner, o -> new AtomicLong());
        if (!ADMIN_OWNER.equals(owner) && held.get() >= maxAgentsPerOwner) {
            throw new QuotaExceededException(maxAgentsPerOwner);
        }
        if (registrationOrder.size() >= maxTotalAgents) throw new CapacityException("agents");

        Instant now = Instant.now();
        String fullHash = AgentSerialNumber.computeIdentityHash(provider, modelName, modelVersion, now);
        long seq = sequences.get(cat).incrementAndGet();
        String serial = AgentSerialNumber.formatSerial(cat, fullHash, seq);

        AgentSerialNumber sn = new AgentSerialNumber(
            serial, fullHash, cat, provider, modelName, modelVersion,
            spiffeId, now, now, seq,
            AgentSerialNumber.SerializationStatus.ACTIVE,
            metadata != null ? metadata : Map.of());

        indexAgent(sn, owner);
        journal("agent", Map.of("owner", owner, "v", sn));
        sealToAuditChain("AGENT_REGISTRATION", serial, sn.toAuditPayload());

        LOG.info("[AIGIS] Registered " + serial + " | provider=" + provider + " | model=" + modelName);
        return sn;
    }

    public Optional<AgentSerialNumber> lookupBySerial(String serial) {
        return Optional.ofNullable(serialsByNumber.get(serial));
    }

    public Optional<AgentSerialNumber> lookupByHash(String hash) {
        return Optional.ofNullable(serialsByHash.get(hash));
    }

    /** True when {@code owner} registered {@code serial}, or is the service administrator. */
    public boolean isOwner(String serial, String owner) {
        return ADMIN_OWNER.equals(owner) || Objects.equals(agentOwners.get(serial), owner);
    }

    public boolean suspendAgent(String serial) {
        return suspendAgent(serial, ADMIN_OWNER) == Change.OK;
    }

    public boolean revokeAgent(String serial) {
        return revokeAgent(serial, ADMIN_OWNER) == Change.OK;
    }

    public Change suspendAgent(String serial, String owner) {
        return changeStatus(serial, owner, AgentSerialNumber.SerializationStatus.SUSPENDED, "AGENT_SUSPENDED");
    }

    public Change revokeAgent(String serial, String owner) {
        return changeStatus(serial, owner, AgentSerialNumber.SerializationStatus.REVOKED, "AGENT_REVOKED");
    }

    private synchronized Change changeStatus(String serial, String owner,
                                             AgentSerialNumber.SerializationStatus status, String event) {
        AgentSerialNumber existing = serialsByNumber.get(serial);
        if (existing == null) return Change.NOT_FOUND;
        if (!isOwner(serial, owner)) return Change.FORBIDDEN;
        if (existing.status() == AgentSerialNumber.SerializationStatus.REVOKED) return Change.OK; // permanent
        Instant at = Instant.now();
        applyStatus(existing, status, at);
        journal("status", Map.of("serial", serial, "status", status.name(), "at", at.toString()));
        sealToAuditChain(event, serial, Map.of("serialNumber", serial, "at", at.toString()));
        LOG.info("[AIGIS] " + status + " " + serial);
        return Change.OK;
    }

    // ── Prompters and ownership records ──────────────────────────

    public PrompterIdentity registerPrompter(String orgId, String authIdentity, String authMethod,
                                             PrompterIdentity.PrompterType type, String spiffeId) {
        return registerPrompter(ADMIN_OWNER, orgId, authIdentity, authMethod, type, spiffeId);
    }

    public synchronized PrompterIdentity registerPrompter(String owner, String orgId, String authIdentity,
                                                          String authMethod, PrompterIdentity.PrompterType type,
                                                          String spiffeId) {
        String hash = PrompterIdentity.computePrompterHash(orgId, authIdentity, authMethod);
        String existingOwner = prompterOwners.get(hash);
        if (existingOwner != null && !existingOwner.equals(owner) && !ADMIN_OWNER.equals(owner)) {
            throw new SecurityException("Prompter is registered under another API key");
        }
        PrompterIdentity existing = prompters.get(hash);
        if (existing == null) {
            if (prompters.size() >= maxTotalPrompters) throw new CapacityException("prompters");
            if (!ADMIN_OWNER.equals(owner)
                && ownerPrompterCounts.computeIfAbsent(owner, o -> new AtomicLong()).get() >= MAX_PROMPTERS_PER_OWNER) {
                throw new QuotaExceededException(MAX_PROMPTERS_PER_OWNER);
            }
        }
        Instant firstSeen = existing != null ? existing.firstSeen() : Instant.now();
        long count = existing != null ? existing.actionCount() : 0;

        PrompterIdentity id = new PrompterIdentity(
            hash, orgId, authMethod, spiffeId, firstSeen, Instant.now(), count, type, Map.of());
        prompters.put(hash, id);
        if (prompterOwners.putIfAbsent(hash, owner) == null) {
            ownerPrompterCounts.computeIfAbsent(owner, o -> new AtomicLong()).incrementAndGet();
        }
        journal("prompter", Map.of("owner", prompterOwners.get(hash), "v", id));
        return id;
    }

    public ActionOwnershipRecord createOwnershipRecord(String agentSerial, String prompterHash,
                                                       String providerId, String actionType,
                                                       String actionTarget, String payloadHash,
                                                       String verdict) {
        return createOwnershipRecord(ADMIN_OWNER, agentSerial, prompterHash, providerId,
            actionType, actionTarget, payloadHash, verdict);
    }

    /** Returns null when the agent is unknown, inactive or not the caller's, or the prompter is not the caller's. */
    public synchronized ActionOwnershipRecord createOwnershipRecord(String owner, String agentSerial,
                                                                    String prompterHash, String providerId,
                                                                    String actionType, String actionTarget,
                                                                    String payloadHash, String verdict) {
        AgentSerialNumber agent = serialsByNumber.get(agentSerial);
        if (agent == null || !agent.isActive() || !isOwner(agentSerial, owner)) {
            LOG.fine("[AIGIS] DENIED: agent not found, inactive or not owned: " + agentSerial);
            return null;
        }
        if (!prompters.containsKey(prompterHash)
            || !(ADMIN_OWNER.equals(owner) || owner.equals(prompterOwners.get(prompterHash)))) {
            LOG.fine("[AIGIS] DENIED: prompter not registered by caller: " + prompterHash);
            return null;
        }

        if (ownershipRecords.size() >= maxTotalRecords) throw new CapacityException("ownership records");
        if (!ADMIN_OWNER.equals(owner)
            && ownerRecordCounts.computeIfAbsent(owner, o -> new AtomicLong()).get() >= MAX_RECORDS_PER_OWNER) {
            throw new QuotaExceededException(MAX_RECORDS_PER_OWNER);
        }

        Instant now = Instant.now();
        ActionOwnershipRecord record = new ActionOwnershipRecord(
            null, agentSerial, agent.fullHash(), prompterHash, providerId,
            actionType, actionTarget, payloadHash, "", now, now.plusSeconds(5),
            "", verdict != null && !verdict.isBlank() ? verdict : "PENDING", Map.of());

        indexRecord(record);
        ownerRecordCounts.computeIfAbsent(owner, o -> new AtomicLong()).incrementAndGet();
        journal("aor", Map.of("owner", owner, "v", record));
        sealToAuditChain("ACTION_OWNERSHIP", agentSerial, record.toAuditPayload());
        return record;
    }

    public boolean verifyOwnershipRecord(String recordHash) {
        ActionOwnershipRecord r = ownershipRecords.get(recordHash);
        return r != null && r.verifyIntegrity();
    }

    public Optional<ActionOwnershipRecord> getOwnershipRecord(String recordHash) {
        return Optional.ofNullable(ownershipRecords.get(recordHash));
    }

    public boolean isPrompterOwner(String prompterHash, String owner) {
        return ADMIN_OWNER.equals(owner) || Objects.equals(prompterOwners.get(prompterHash), owner);
    }

    public List<ActionOwnershipRecord> getAgentHistory(String serial) {
        return history(recordsByAgent.get(serial));
    }

    public List<ActionOwnershipRecord> getPrompterHistory(String hash) {
        return history(recordsByPrompter.get(hash));
    }

    private List<ActionOwnershipRecord> history(List<String> hashes) {
        if (hashes == null) return List.of();
        List<String> copy;
        synchronized (hashes) { copy = new ArrayList<>(hashes); }
        Collections.reverse(copy); // newest first
        return copy.stream().map(ownershipRecords::get).filter(Objects::nonNull).toList();
    }

    // ── Registry views ───────────────────────────────────────────

    public int totalRegistered() { return registrationOrder.size(); }

    /** One page of the registry, newest registration first. */
    public List<AgentSerialNumber> page(int page, int size) {
        List<AgentSerialNumber> out = new ArrayList<>(Math.max(0, Math.min(size, 100)));
        if (page < 0 || size <= 0) return out;
        synchronized (registrationOrder) {
            long skip = (long) page * size; // long: a huge page number must not overflow into a valid index
            if (skip >= registrationOrder.size()) return out;
            int end = (int) (registrationOrder.size() - 1 - skip);
            for (int i = end; i >= 0 && i > end - size; i--) {
                AgentSerialNumber sn = serialsByNumber.get(registrationOrder.get(i));
                if (sn != null) out.add(sn);
            }
        }
        return out;
    }

    /** Every registration, newest first. Use {@link #page} for anything user-facing. */
    public List<AgentSerialNumber> listAll() {
        return page(0, Math.max(1, totalRegistered()));
    }

    /** Constant-time counters; safe to call on every request at any registry size. */
    public Map<String, Object> getStats() {
        return Map.of(
            "totalRegistered", (long) registrationOrder.size(),
            "active", statusCounts.get(AgentSerialNumber.SerializationStatus.ACTIVE).get(),
            "suspended", statusCounts.get(AgentSerialNumber.SerializationStatus.SUSPENDED).get(),
            "revoked", statusCounts.get(AgentSerialNumber.SerializationStatus.REVOKED).get(),
            "promptersTracked", (long) prompters.size(),
            "ownershipRecords", (long) ownershipRecords.size());
    }

    // ── Indexing (shared by live writes and journal replay) ──────

    private void indexAgent(AgentSerialNumber sn, String owner) {
        serialsByHash.put(sn.fullHash(), sn);
        serialsByNumber.put(sn.serialNumber(), sn);
        agentOwners.put(sn.serialNumber(), owner);
        ownerCounts.computeIfAbsent(owner, o -> new AtomicLong()).incrementAndGet();
        registrationOrder.add(sn.serialNumber());
        statusCounts.get(sn.status()).incrementAndGet();
        sequences.get(sn.category()).accumulateAndGet(sn.sequenceNumber(), Math::max);
    }

    private void applyStatus(AgentSerialNumber a, AgentSerialNumber.SerializationStatus status, Instant at) {
        AgentSerialNumber updated = new AgentSerialNumber(
            a.serialNumber(), a.fullHash(), a.category(), a.provider(), a.modelName(), a.modelVersion(),
            a.spiffeId(), a.firstSeen(), at, a.sequenceNumber(), status, a.metadata());
        serialsByNumber.put(a.serialNumber(), updated);
        serialsByHash.put(a.fullHash(), updated);
        statusCounts.get(a.status()).decrementAndGet();
        statusCounts.get(status).incrementAndGet();
    }

    private void indexRecord(ActionOwnershipRecord record) {
        ownershipRecords.put(record.recordHash(), record);
        recordsByAgent.computeIfAbsent(record.agentSerial(), k -> Collections.synchronizedList(new ArrayList<>()))
            .add(record.recordHash());
        recordsByPrompter.computeIfAbsent(record.prompterHash(), k -> Collections.synchronizedList(new ArrayList<>()))
            .add(record.recordHash());

        PrompterIdentity p = prompters.get(record.prompterHash());
        if (p != null) {
            prompters.put(p.prompterHash(), new PrompterIdentity(
                p.prompterHash(), p.organizationId(), p.authenticationType(), p.spiffeId(),
                p.firstSeen(), record.timestamp(), p.actionCount() + 1, p.type(), p.metadata()));
        }
        AgentSerialNumber a = serialsByNumber.get(record.agentSerial());
        if (a != null) {
            AgentSerialNumber seen = new AgentSerialNumber(
                a.serialNumber(), a.fullHash(), a.category(), a.provider(), a.modelName(), a.modelVersion(),
                a.spiffeId(), a.firstSeen(), record.timestamp(), a.sequenceNumber(), a.status(), a.metadata());
            serialsByNumber.put(a.serialNumber(), seen);
            serialsByHash.put(a.fullHash(), seen);
        }
    }

    // ── Journal ──────────────────────────────────────────────────

    private void openJournal(Path dataDir) {
        try {
            Files.createDirectories(dataDir);
            if (Files.exists(journal)) replay();
            journalWriter = Files.newBufferedWriter(journal, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            LOG.info("[AIGIS] Registry loaded from " + journal + ": " + totalRegistered() + " agents");
        } catch (IOException e) {
            throw new IllegalStateException("Cannot open AIGIS registry journal " + journal, e);
        }
    }

    private void replay() throws IOException {
        replaying = true;
        long lineNo = 0;
        try (var lines = Files.lines(journal, StandardCharsets.UTF_8)) {
            for (Iterator<String> it = lines.iterator(); it.hasNext(); ) {
                String line = it.next();
                lineNo++;
                if (line.isBlank()) continue;
                try {
                    replayLine(JSON.readTree(line));
                } catch (Exception e) {
                    // A torn final line after a crash is expected; anything else is worth a warning.
                    LOG.warning("[AIGIS] Skipping unreadable journal line " + lineNo + ": " + e.getMessage());
                }
            }
        } finally {
            replaying = false;
        }
    }

    private void replayLine(JsonNode n) throws IOException {
        switch (n.path("t").asText()) {
            case "agent" -> indexAgent(JSON.treeToValue(n.get("v"), AgentSerialNumber.class), n.path("owner").asText());
            case "status" -> {
                AgentSerialNumber a = serialsByNumber.get(n.path("serial").asText());
                if (a != null) applyStatus(a, AgentSerialNumber.SerializationStatus.valueOf(n.path("status").asText()),
                    Instant.parse(n.path("at").asText()));
            }
            case "prompter" -> {
                PrompterIdentity p = JSON.treeToValue(n.get("v"), PrompterIdentity.class);
                prompters.put(p.prompterHash(), p);
                String owner = n.path("owner").asText();
                if (prompterOwners.putIfAbsent(p.prompterHash(), owner) == null) {
                    ownerPrompterCounts.computeIfAbsent(owner, o -> new AtomicLong()).incrementAndGet();
                }
            }
            case "aor" -> {
                indexRecord(JSON.treeToValue(n.get("v"), ActionOwnershipRecord.class));
                if (n.hasNonNull("owner")) {
                    ownerRecordCounts.computeIfAbsent(n.get("owner").asText(), o -> new AtomicLong()).incrementAndGet();
                }
            }
            default -> LOG.warning("[AIGIS] Unknown journal entry type: " + n.path("t").asText());
        }
    }

    private void journal(String type, Map<String, Object> fields) {
        if (journalWriter == null || replaying) return;
        try {
            ObjectNode line = JSON.createObjectNode().put("t", type);
            fields.forEach((k, v) -> line.set(k, JSON.valueToTree(v)));
            journalWriter.write(JSON.writeValueAsString(line));
            journalWriter.newLine();
            journalWriter.flush();
        } catch (IOException e) {
            LOG.severe("[AIGIS] Failed to persist " + type + ": " + e.getMessage());
        }
    }

    // ── Audit chain ──────────────────────────────────────────────

    private void sealToAuditChain(String eventType, String serial, Map<String, Object> payload) {
        if (auditChainUrl.isBlank() || replaying) return;
        try {
            String json = JSON.writeValueAsString(Map.of(
                "verdict", "ALLOW",
                "modelId", "aigis-serialization",
                "vendorId", "aigis",
                "inputHash", sha256(eventType + "|" + serial),
                "outputHash", sha256(JSON.writeValueAsString(new TreeMap<>(payload))),
                "metadata", Map.of("eventType", eventType, "serialNumber", serial)));
            http.sendAsync(
                HttpRequest.newBuilder()
                    .uri(URI.create(auditChainUrl + "/record"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json))
                    .timeout(Duration.ofSeconds(5))
                    .build(),
                HttpResponse.BodyHandlers.discarding()
            ).exceptionally(ex -> { LOG.fine("[AIGIS] Audit chain unreachable"); return null; });
        } catch (Exception e) {
            LOG.fine("[AIGIS] Audit chain error: " + e.getMessage());
        }
    }

    private static String sha256(String input) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(h);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
