package io.kymatech.aigis.identity;

import io.kymatech.aigis.identity.AgentSerializationService.Change;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AgentSerializationServiceTest {

    private final AgentSerializationService service = new AgentSerializationService("");

    @TempDir Path dir;

    @Test
    void serialFollowsProtocolFormat() {
        AgentSerialNumber sn = service.registerAgent("anthropic", "claude", "5", "AGT", "", Map.of());
        assertTrue(sn.serialNumber().matches("AIGIS-AGT-[0-9a-f]{8}-\\d{6}"), sn.serialNumber());
        assertEquals(sn.fullHash().substring(0, 8), sn.serialNumber().split("-")[2]);
        assertTrue(sn.verifyIntegrity());
    }

    @Test
    void sequencesAreIndependentPerCategory() {
        AgentSerialNumber m1 = service.registerAgent("p", "m", "1", "MDL", "", Map.of());
        AgentSerialNumber a1 = service.registerAgent("p", "a", "1", "AGT", "", Map.of());
        AgentSerialNumber m2 = service.registerAgent("p", "m", "2", "MDL", "", Map.of());
        assertEquals(1, m1.sequenceNumber());
        assertEquals(1, a1.sequenceNumber());
        assertEquals(2, m2.sequenceNumber());
    }

    @Test
    void unknownCategoryIsRejected() {
        assertThrows(IllegalArgumentException.class,
            () -> service.registerAgent("p", "m", "1", "XYZ", "", Map.of()));
    }

    @Test
    void identityHashIsDeterministicAndNormalized() {
        Instant t = Instant.parse("2026-10-29T05:00:00Z");
        assertEquals(
            AgentSerialNumber.computeIdentityHash("Anthropic", " Claude ", "5", t),
            AgentSerialNumber.computeIdentityHash("anthropic", "claude", "5", t));
    }

    @Test
    void ownershipRecordRequiresActiveAgentAndKnownPrompter() {
        AgentSerialNumber sn = service.registerAgent("p", "m", "1", "AGT", "", Map.of());
        PrompterIdentity prompter = service.registerPrompter("org-1", "user@example.com", "oidc",
            PrompterIdentity.PrompterType.HUMAN, "");

        assertNull(service.createOwnershipRecord(sn.serialNumber(), "unknown", "prov", "act", "", "", null));

        ActionOwnershipRecord record = service.createOwnershipRecord(
            sn.serialNumber(), prompter.prompterHash(), "prov", "web-search", "target", "", null);
        assertNotNull(record);
        assertTrue(service.verifyOwnershipRecord(record.recordHash()));

        assertTrue(service.revokeAgent(sn.serialNumber()));
        assertNull(service.createOwnershipRecord(
            sn.serialNumber(), prompter.prompterHash(), "prov", "web-search", "target", "", null));
    }

    @Test
    void onlyTheOwnerCanChangeOrUseAnAgent() {
        AgentSerialNumber sn = service.registerAgent("alice", "p", "m", "1", "AGT", "", Map.of());
        PrompterIdentity bobPrompter = service.registerPrompter("bob", "org", "id", "oidc",
            PrompterIdentity.PrompterType.HUMAN, "");

        assertEquals(Change.FORBIDDEN, service.revokeAgent(sn.serialNumber(), "bob"));
        assertEquals(Change.FORBIDDEN, service.suspendAgent(sn.serialNumber(), "bob"));
        assertNull(service.createOwnershipRecord("bob", sn.serialNumber(), bobPrompter.prompterHash(),
            "prov", "act", "", "", null), "bob cannot attach actions to alice's agent");
        assertTrue(service.lookupBySerial(sn.serialNumber()).orElseThrow().isActive());

        assertEquals(Change.NOT_FOUND, service.revokeAgent("AIGIS-AGT-00000000-000999", "alice"));
        assertEquals(Change.OK, service.revokeAgent(sn.serialNumber(), "alice"));
        assertEquals(Change.OK, service.suspendAgent(sn.serialNumber(), "alice"));
        assertEquals(AgentSerialNumber.SerializationStatus.REVOKED,
            service.lookupBySerial(sn.serialNumber()).orElseThrow().status(), "revocation is permanent");
    }

    @Test
    void perOwnerQuotaIsEnforced() {
        AgentSerializationService limited = new AgentSerializationService("", null, 2);
        limited.registerAgent("alice", "p", "a", "1", "AGT", "", Map.of());
        limited.registerAgent("alice", "p", "b", "1", "AGT", "", Map.of());
        assertThrows(AgentSerializationService.QuotaExceededException.class,
            () -> limited.registerAgent("alice", "p", "c", "1", "AGT", "", Map.of()));
        assertDoesNotThrow(() -> limited.registerAgent("bob", "p", "c", "1", "AGT", "", Map.of()));
    }

    @Test
    void registryPagesNewestFirstAndStatsStayCurrent() {
        for (int i = 0; i < 5; i++) service.registerAgent("p", "m" + i, "1", "AGT", "", Map.of());
        assertEquals("m4", service.page(0, 2).get(0).modelName());
        assertEquals("m2", service.page(1, 2).get(0).modelName());
        assertEquals(1, service.page(2, 2).size());
        assertTrue(service.page(3, 2).isEmpty());

        service.suspendAgent(service.page(0, 1).get(0).serialNumber());
        Map<String, Object> stats = service.getStats();
        assertEquals(5L, stats.get("totalRegistered"));
        assertEquals(4L, stats.get("active"));
        assertEquals(1L, stats.get("suspended"));
    }

    @Test
    void registrySurvivesRestart() {
        AgentSerializationService first = new AgentSerializationService("", dir, 100);
        AgentSerialNumber a = first.registerAgent("alice", "p", "a", "1", "AGT", "", Map.of());
        AgentSerialNumber b = first.registerAgent("alice", "p", "b", "1", "AGT", "", Map.of());
        PrompterIdentity pr = first.registerPrompter("alice", "org", "id", "oidc",
            PrompterIdentity.PrompterType.HUMAN, "");
        ActionOwnershipRecord rec = first.createOwnershipRecord("alice", a.serialNumber(), pr.prompterHash(),
            "prov", "act", "", "", null);
        first.revokeAgent(b.serialNumber(), "alice");

        AgentSerializationService restarted = new AgentSerializationService("", dir, 100);
        assertEquals(2, restarted.totalRegistered());
        assertEquals(AgentSerialNumber.SerializationStatus.REVOKED,
            restarted.lookupBySerial(b.serialNumber()).orElseThrow().status());
        assertTrue(restarted.verifyOwnershipRecord(rec.recordHash()));
        assertEquals(1, restarted.getAgentHistory(a.serialNumber()).size());
        assertEquals(Change.FORBIDDEN, restarted.revokeAgent(a.serialNumber(), "mallory"), "ownership survives restart");

        AgentSerialNumber c = restarted.registerAgent("alice", "p", "c", "1", "AGT", "", Map.of());
        assertEquals(3, c.sequenceNumber(), "sequence continues after restart");
    }

    @Test
    void registryWideCapacityIsEnforced() {
        AgentSerializationService small = new AgentSerializationService("", null, 100).withCapacity(2, 1, 1);
        AgentSerialNumber a = small.registerAgent("alice", "p", "a", "1", "AGT", "", Map.of());
        small.registerAgent("bob", "p", "b", "1", "AGT", "", Map.of());
        assertThrows(AgentSerializationService.CapacityException.class,
            () -> small.registerAgent("carol", "p", "c", "1", "AGT", "", Map.of()));

        PrompterIdentity p = small.registerPrompter("alice", "org", "id", "oidc", PrompterIdentity.PrompterType.HUMAN, "");
        assertThrows(AgentSerializationService.CapacityException.class,
            () -> small.registerPrompter("alice", "org2", "id", "oidc", PrompterIdentity.PrompterType.HUMAN, ""));
        assertNotNull(small.createOwnershipRecord("alice", a.serialNumber(), p.prompterHash(), "prov", "act", "", "", null));
        assertThrows(AgentSerializationService.CapacityException.class,
            () -> small.createOwnershipRecord("alice", a.serialNumber(), p.prompterHash(), "prov", "act2", "", "", null));
    }

    @Test
    void hugeOrNegativePagesAreEmptyNotErrors() {
        service.registerAgent("p", "m", "1", "AGT", "", Map.of());
        assertTrue(service.page(Integer.MAX_VALUE, 100).isEmpty());
        assertTrue(service.page(21_474_837, 100).isEmpty());
        assertTrue(service.page(-1, 10).isEmpty());
        assertEquals(1, service.page(0, 100).size());
    }
}
