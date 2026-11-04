package io.kymatech.aigis;

import io.helidon.config.Config;
import io.helidon.cors.CrossOriginConfig;
import io.helidon.webserver.WebServer;
import io.helidon.webserver.cors.CorsSupport;
import io.helidon.webserver.http.HttpRouting;
import io.kymatech.aigis.identity.AgentSerializationService;
import io.kymatech.aigis.route.AigisRoutes;

import java.nio.file.Path;
import java.util.logging.Logger;

/**
 * AIGIS: Serialization &amp; Identification Protocol, reference implementation.
 *
 * Gives every AI model and agent a permanent serial number and records which agent,
 * prompter and provider stand behind each action. Runs as a single self-contained jar.
 *
 * Configuration (environment variables; all optional):
 *   AIGIS_PORT                  listen port (default 8097; also --port N)
 *   AIGIS_API_KEY               key required for write endpoints (unset = open, local dev only)
 *   AIGIS_DATA_DIR              registry journal directory (default ./data; "none" = in memory)
 *   AIGIS_MAX_AGENTS_PER_OWNER  registrations allowed per owner (default 10000)
 *   AUDIT_CHAIN_URL             optional audit chain base URL; events are POSTed to {url}/record
 *
 * Published by KYMA Tech Solutions (kymatech.io) under the Apache License 2.0.
 * Patent pending: U.S. Provisional App. No. 64/186,696.
 */
public class AigisApplication {
    private static final Logger LOG = Logger.getLogger(AigisApplication.class.getName());
    public static final int DEFAULT_PORT = 8097;

    public static void main(String[] args) {
        Config config = Config.create();
        int port = config.get("server.port").asInt().orElse(DEFAULT_PORT);
        for (int i = 0; i < args.length - 1; i++) {
            if ("--port".equals(args[i])) port = Integer.parseInt(args[i + 1]);
        }
        String envPort = env("AIGIS_PORT");
        if (!envPort.isBlank()) port = Integer.parseInt(envPort);

        // Read from the environment only: Helidon 4.1.6 does not resolve ${VAR:} placeholders in YAML.
        String auditChainUrl = env("AUDIT_CHAIN_URL");
        String apiKey = env("AIGIS_API_KEY");
        String dataDir = env("AIGIS_DATA_DIR");
        if (dataDir.isBlank()) dataDir = "data";
        String maxPerOwner = env("AIGIS_MAX_AGENTS_PER_OWNER");

        AgentSerializationService service = new AgentSerializationService(
            auditChainUrl,
            "none".equalsIgnoreCase(dataDir) ? null : Path.of(dataDir),
            maxPerOwner.isBlank() ? 10_000 : Integer.parseInt(maxPerOwner));
        String mode = auditChainUrl.isBlank() ? "STANDALONE" : "INTEGRATED";

        // Open CORS: the protocol is public; writes still require the API key.
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
                "{\"service\":\"AIGIS: Serialization & Identification Protocol\","
                + "\"version\":\"1.0.0\","
                + "\"mode\":\"" + mode + "\","
                + "\"protocol\":\"/api/v1/aigis/protocol\","
                + "\"registry\":\"/api/v1/aigis/registry\","
                + "\"license\":\"Apache-2.0\","
                + "\"source\":\"https://github.com/KrustyNailz/AIGIS\"}"));

        WebServer server = WebServer.builder()
            .host(config.get("server.host").asString().orElse("0.0.0.0"))
            .port(port)
            .routing(routing)
            .build()
            .start();

        LOG.info("AIGIS: Serialization & Identification Protocol");
        LOG.info("  Port:        " + server.port());
        LOG.info("  Mode:        " + mode);
        LOG.info("  Auth:        " + (apiKey.isBlank() ? "DISABLED (local dev only)" : "ENABLED"));
        LOG.info("  Registry:    " + (service.isPersistent() ? Path.of(dataDir).toAbsolutePath() : "in memory")
            + " (" + service.totalRegistered() + " agents)");
        LOG.info("  Audit chain: " + (auditChainUrl.isBlank() ? "not configured" : auditChainUrl));

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            LOG.info("[AIGIS] shutting down");
            server.stop();
        }));
    }

    private static String env(String name) {
        String v = System.getenv(name);
        return v == null ? "" : v.trim();
    }
}
