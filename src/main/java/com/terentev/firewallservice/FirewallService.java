package com.terentev.firewallservice;

import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.channels.Channels;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

public final class FirewallService {
    private static final System.Logger LOG = System.getLogger(FirewallService.class.getName());
    private static final Pattern TOKEN = Pattern.compile("[0-9a-f]{64}");
    private static final int MAX_PASSWORD_LENGTH = 512;
    private static final int MAX_QUERY_LENGTH = 8192;
    private static final JsonMapper JSON = JsonMapper.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .build();

    private final Path config;
    private final byte[] proxyTokenHash;
    private final List<String> allowCommand;

    FirewallService(Path config, String proxyToken, List<String> allowCommand) {
        this.config = config;
        this.proxyTokenHash = hash(proxyToken);
        this.allowCommand = List.copyOf(allowCommand);
    }

    public static void main(String[] args) {
        boolean initialize = args.length == 2 && "--init-config".equals(args[1]);
        boolean checkOnly = args.length == 2 && "--check-config".equals(args[1]);
        boolean renderNginx = args.length == 3 && "--render-nginx".equals(args[1]);
        if (args.length != 1 && !initialize && !checkOnly && !renderNginx) {
            System.err.println("Usage: firewallservice CONFIG [--init-config | --check-config | --render-nginx TEMPLATE]");
            System.exit(2);
            return;
        }

        Path config = Path.of(args[0]);
        if (initialize) {
            try {
                initializeConfig(config);
            } catch (IOException e) {
                LOG.log(System.Logger.Level.ERROR, "Cannot create config.json", e);
                System.exit(1);
            }
            return;
        }

        Config settings;
        try {
            settings = loadConfig(config);
        } catch (IOException e) {
            // Parsing exceptions may contain excerpts from the configuration.
            LOG.log(System.Logger.Level.ERROR, "Cannot read or validate config.json");
            System.exit(1);
            return;
        }
        if (checkOnly) {
            return;
        }
        if (renderNginx) {
            try {
                String template = Files.readString(Path.of(args[2]));
                System.out.print(template.replace("@PROXY_TOKEN@", settings.proxyToken()));
                if (System.out.checkError()) {
                    throw new IOException("Cannot write nginx snippet");
                }
            } catch (IOException e) {
                LOG.log(System.Logger.Level.ERROR, "Cannot render nginx snippet", e);
                System.exit(1);
            }
            return;
        }

        FirewallService service = new FirewallService(config, settings.proxyToken(),
                List.of("/usr/bin/sudo", "-n", "--", "/usr/local/lib/firewallservice/java",
                        "-cp", "/usr/local/lib/firewallservice/firewallservice.jar", AllowFrom.class.getName()));
        try {
            service.start(new InetSocketAddress("127.0.0.1", 8765));
            LOG.log(System.Logger.Level.INFO, "Listening on 127.0.0.1:8765");
        } catch (IOException e) {
            LOG.log(System.Logger.Level.ERROR, "Cannot bind to 127.0.0.1:8765", e);
            System.exit(1);
        }
    }

    HttpServer start(InetSocketAddress address) throws IOException {
        HttpServer server = HttpServer.create(address, 32);
        server.setExecutor(new ThreadPoolExecutor(4, 4, 0, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(32), new ThreadPoolExecutor.CallerRunsPolicy()));
        server.createContext("/", this::handle);
        server.start();
        return server;
    }

    private void handle(HttpExchange exchange) throws IOException {
        try (exchange) {
            if (!"/firewall".equals(exchange.getRequestURI().getRawPath())) {
                send(exchange, 404, "Not found");
                return;
            }

            String proxyToken = singleHeader(exchange, "X-Firewall-Proxy-Token");
            if (proxyToken == null || !TOKEN.matcher(proxyToken).matches()
                    || !MessageDigest.isEqual(proxyTokenHash, hash(proxyToken))) {
                send(exchange, 403, "Forbidden");
                return;
            }
            if (!"GET".equals(exchange.getRequestMethod())) {
                exchange.getResponseHeaders().set("Allow", "GET");
                send(exchange, 405, "GET required");
                return;
            }

            String clientIp = singleHeader(exchange, "X-Firewall-Client-IP");
            if (clientIp == null || !AllowFrom.isNumericAddress(clientIp)) {
                send(exchange, 400, "Invalid client IP");
                return;
            }

            Map<String, String> params;
            try {
                params = parseQuery(exchange.getRequestURI().getRawQuery());
            } catch (IllegalArgumentException e) {
                send(exchange, 400, "Expected one name and one password");
                return;
            }

            String name = params.get("name");
            String password = params.get("password");
            Map<String, String> users;
            try {
                users = loadConfig(config).users();
            } catch (IOException e) {
                LOG.log(System.Logger.Level.ERROR, "Cannot read or validate config.json");
                send(exchange, 503, "Configuration unavailable");
                return;
            }
            if (!users.containsKey(name)
                    || !MessageDigest.isEqual(users.get(name).getBytes(StandardCharsets.UTF_8),
                            password.getBytes(StandardCharsets.UTF_8))) {
                send(exchange, 401, "Invalid name or password");
                return;
            }

            int exitCode;
            try {
                exitCode = allowFrom(clientIp, name);
            } catch (IOException e) {
                LOG.log(System.Logger.Level.ERROR, "Cannot complete UFW command", e);
                send(exchange, 502, "UFW command failed");
                return;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                send(exchange, 503, "UFW command interrupted");
                return;
            }
            switch (exitCode) {
                case 0 -> send(exchange, 200, "OK " + clientIp);
                case 75 -> send(exchange, 503, "UFW is busy, try again");
                default -> {
                    LOG.log(System.Logger.Level.ERROR, "UFW command exited with status {0}", exitCode);
                    send(exchange, 502, "UFW command failed");
                }
            }
        }
    }

    private record Config(String proxyToken, Map<String, String> users) {}

    private static void initializeConfig(Path path) throws IOException {
        SecureRandom random = new SecureRandom();
        var config = JSON.createObjectNode();
        config.put("proxy.token", randomSecret(random));
        config.putObject("users").put("evg", randomSecret(random));
        String json = JSON.writerWithDefaultPrettyPrinter().writeValueAsString(config);
        var options = Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        var permissions = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"));
        try (var output = Channels.newOutputStream(Files.newByteChannel(path, options, permissions))) {
            output.write((json + "\n").getBytes(StandardCharsets.UTF_8));
        }
    }

    private static String randomSecret(SecureRandom random) {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }

    private static Config loadConfig(Path path) throws IOException {
        Map<String, String> users = new HashMap<>();
        try (var input = Files.newInputStream(path)) {
            JsonNode root = JSON.readTree(input);
            if (root == null || !root.isObject()) {
                throw new IOException("Expected a JSON object");
            }
            String proxyToken = root.path("proxy.token").textValue();
            JsonNode usersNode = root.path("users");
            if (root.size() != 2 || proxyToken == null || !TOKEN.matcher(proxyToken).matches()
                    || !usersNode.isObject()) {
                throw new IOException("Expected a valid proxy.token and a users object");
            }
            for (var entry : usersNode.properties()) {
                JsonNode value = entry.getValue();
                if (!AllowFrom.NAME.matcher(entry.getKey()).matches() || !value.isTextual()
                        || !validPassword(value.textValue())) {
                    throw new IOException("Invalid user entry");
                }
                users.put(entry.getKey(), value.textValue());
            }
            return new Config(proxyToken, users);
        }
    }

    private static Map<String, String> parseQuery(String query) {
        if (query == null || query.length() > MAX_QUERY_LENGTH) {
            throw new IllegalArgumentException();
        }
        Map<String, String> params = new HashMap<>();
        for (String item : query.split("&", -1)) {
            int equals = item.indexOf('=');
            if (equals < 1) {
                throw new IllegalArgumentException();
            }
            String key = URLDecoder.decode(item.substring(0, equals), StandardCharsets.UTF_8);
            String value = URLDecoder.decode(item.substring(equals + 1), StandardCharsets.UTF_8);
            if ((!"name".equals(key) && !"password".equals(key)) || params.putIfAbsent(key, value) != null) {
                throw new IllegalArgumentException();
            }
        }
        if (params.size() != 2 || !AllowFrom.NAME.matcher(params.get("name")).matches()
                || !validPassword(params.get("password"))) {
            throw new IllegalArgumentException();
        }
        return params;
    }

    private static boolean validPassword(String password) {
        return !password.isEmpty() && password.length() <= MAX_PASSWORD_LENGTH
                && StandardCharsets.UTF_8.newEncoder().canEncode(password);
    }

    private int allowFrom(String clientIp, String name) throws IOException, InterruptedException {
        Process process = new ProcessBuilder(allowCommand)
                .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .redirectError(ProcessBuilder.Redirect.INHERIT)
                .start();
        try {
            try (var input = process.getOutputStream()) {
                input.write((clientIp + "\n" + name + "\n").getBytes(StandardCharsets.US_ASCII));
            }
            if (!process.waitFor(20, TimeUnit.SECONDS)) {
                throw new IOException("Timed out waiting for the UFW helper");
            }
            return process.exitValue();
        } finally {
            if (process.isAlive()) {
                process.destroyForcibly();
            }
        }
    }

    private static String singleHeader(HttpExchange exchange, String name) {
        List<String> values = exchange.getRequestHeaders().get(name);
        return values != null && values.size() == 1 ? values.getFirst() : null;
    }

    private static byte[] hash(String value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void send(HttpExchange exchange, int status, String message) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        if ("HEAD".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(status, -1);
            return;
        }
        byte[] body = (message + "\n").getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, body.length);
        exchange.getResponseBody().write(body);
    }
}
