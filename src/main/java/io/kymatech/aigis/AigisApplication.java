package io.kymatech.aigis;

import io.helidon.config.Config;
import io.helidon.cors.CrossOriginConfig;
import io.helidon.webserver.WebServer;
import io.helidon.webserver.cors.CorsSupport;
import io.helidon.webserver.http.HttpRouting;
import io.kymatech.aigis.identity.AgentSerializationService;
import io.kymatech.aigis.route.AigisRoutes;

import java.util.logging.Logger;

/**
 * AI-GIS — Agent Identity Governance & Identification Serialization
 *
 * Standalone open-source application for deterministic, tamper-evident identity
 * and accountability of AI models and autonomous agents.
 *
 * Runs independently or integrates with the ICOSA platform for full governance
 * enforcement (Betelgeuse policy engine, Rigel audit chain, SPIFFE/SPIRE mTLS).
 *
 * Modes:
 *   STANDALONE — Self-contained identity registry with local audit log.
 *                No ICOSA dependency. Ships as a single JAR.
 *   INTEGRATED — Connected to ICOSA's Rigel audit chain and Betelgeuse
 *                governance layer. AORs are sealed into the production chain.
 *
 * Codename: Black Reigns
 * Patent Pending: U.S. Provisional App. No. 64/186,696
 * Open Source — the AI-GIS serialization protocol is offered freely for global adoption.
 * Reference Implementation by Kymatech, Inc.
 *
 * Usage:
 *   java -jar aigis.jar                          # standalone, port 8097
 *   java -jar aigis.jar --port 9090              # custom port
 *   AIGIS_API_KEY=secret java -jar aigis.jar     # with auth
 *   AUDIT_CHAIN_URL=http://rigel:8095/api/v1/audit java -jar aigis.jar  # ICOSA integration
 */
public class AigisApplication {
    private static final Logger LOG = Logger.getLogger(AigisApplication.class.getName());
    public static final int DEFAULT_PORT = 8097;

    public static void main(String[] args) {
        Config config = Config.create();
        int port = config.get("server.port").asInt().orElse(DEFAULT_PORT);

        // CLI override
        for (int i = 0; i < args.length - 1; i++) {
            if ("--port".equals(args[i])) {
                port = Integer.parseInt(args[i + 1]);
            }
        }

        // Env var override
        String envPort = System.getenv("AIGIS_PORT");
        if (envPort != null && !envPort.isBlank()) {
            port = Integer.parseInt(envPort);
        }

        // Audit chain URL (optional — ICOSA integration)
        String auditChainUrl = config.get("aigis.audit-chain-url").asString().orElse("");
        String envAuditUrl = System.getenv("AUDIT_CHAIN_URL");
        if (envAuditUrl != null && !envAuditUrl.isBlank()) auditChainUrl = envAuditUrl;

        // API key (optional — standalone dev mode runs without auth)
        String apiKey = config.get("aigis.api-key").asString().orElse("");
        String envApiKey = System.getenv("AIGIS_API_KEY");
        if (envApiKey != null && !envApiKey.isBlank()) apiKey = envApiKey;

        String mode = auditChainUrl.isBlank() ? "STANDALONE" : "INTEGRATED";

        AgentSerializationService service = new AgentSerializationService(auditChainUrl);

        // CORS — open for standalone (it's an open protocol), tightened per deployment
        CorsSupport cors = CorsSupport.builder()
            .addCrossOrigin(CrossOriginConfig.builder()
                .allowOrigins("*")
                .allowMethods("GET", "POST", "OPTIONS")
                .allowHeaders("Content-Type", "X-AIGIS-Key", "Authorization")
                .build())
            .build();

        HttpRouting.Builder routing = HttpRouting.builder()
            .register("/", cors)
            .register("/api/v1/aigis", new AigisRoutes(service, apiKey))
            .get("/health", (req, res) -> res.send(
                "{\"status\":\"UP\",\"service\":\"aigis\",\"mode\":\"" + mode + "\"}"))
            .get("/", (req, res) -> res.send(
                "{\"service\":\"AI-GIS: Agent Identity Governance & Identification Serialization\","
                + "\"version\":\"1.0.0\","
                + "\"codename\":\"Black Reigns\","
                + "\"mode\":\"" + mode + "\","
                + "\"protocol\":\"/api/v1/aigis/protocol\","
                + "\"registry\":\"/api/v1/aigis/registry\","
                + "\"openSource\":true,"
                + "\"patent\":\"U.S. Provisional App. No. 64/186,696\","
                + "\"referenceImplementation\":\"ICOSA Platform by Kymatech, Inc.\"}"));

        WebServer server = WebServer.builder()
            .host(config.get("server.host").asString().orElse("0.0.0.0"))
            .port(port)
            .routing(routing)
            .build()
            .start();

        LOG.info("╔═══════════════════════════════════════════════════════════╗");
        LOG.info("║  AI-GIS: Agent Identity Governance & ID Serialization    ║");
        LOG.info("║  Codename: Black Reigns                                  ║");
        LOG.info("║  Open Source Protocol — Reference Implementation         ║");
        LOG.info("╠═══════════════════════════════════════════════════════════╣");
        LOG.info("║  Port:       " + String.format("%-44s", server.port()) + "║");
        LOG.info("║  Mode:       " + String.format("%-44s", mode) + "║");
        LOG.info("║  Auth:       " + String.format("%-44s", (apiKey.isBlank() ? "DISABLED (dev)" : "ENABLED")) + "║");
        LOG.info("║  Audit Chain:" + String.format("%-44s", (auditChainUrl.isBlank() ? "LOCAL ONLY" : auditChainUrl)) + "║");
        LOG.info("║  Protocol:   /api/v1/aigis/protocol                      ║");
        LOG.info("║  Registry:   /api/v1/aigis/registry                      ║");
        LOG.info("╚═══════════════════════════════════════════════════════════╝");

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            LOG.info("[AI-GIS] shutting down");
            server.stop();
        }));
    }
}
