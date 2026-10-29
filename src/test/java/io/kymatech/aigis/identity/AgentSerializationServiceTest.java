package io.kymatech.aigis.identity;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AgentSerializationServiceTest {

    private final AgentSerializationService service = new AgentSerializationService("");

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
}
