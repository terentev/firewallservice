package com.terentev.firewallservice;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Pattern;

public final class AllowFrom {
    static final Pattern NAME = Pattern.compile("[A-Za-z0-9_.-]{1,64}");
    private static final Pattern ADDRESS = Pattern.compile("[0-9A-Fa-f:.]{1,45}");
    private static final Pattern IPV4 = Pattern.compile("(?:0|[1-9][0-9]{0,2})(?:\\.(?:0|[1-9][0-9]{0,2})){3}");
    private static final int MAX_INPUT_BYTES = 45 + 64 + 2;

    public static void main(String[] args) {
        if (args.length != 0) {
            System.exit(2);
            return;
        }

        var input = new FutureTask<>(() -> System.in.readNBytes(MAX_INPUT_BYTES + 1));
        Thread.startVirtualThread(input);
        try {
            byte[] request = input.get(5, TimeUnit.SECONDS);
            System.exit(apply(request, Path.of("/run/firewallservice-ufw.lock"), Path.of("/usr/sbin/ufw")));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.exit(1);
        } catch (IOException | ExecutionException | TimeoutException e) {
            System.err.println("Firewall helper failed: " + e);
            System.exit(1);
        }
    }

    static int apply(byte[] input, Path lockPath, Path ufw) throws IOException, InterruptedException {
        if (input.length > MAX_INPUT_BYTES) {
            return 2;
        }
        String[] lines = new String(input, StandardCharsets.US_ASCII).split("\n", -1);
        if (lines.length != 3 || !lines[2].isEmpty() || !isNumericAddress(lines[0])
                || !NAME.matcher(lines[1]).matches()) {
            return 2;
        }

        var privatePermissions = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"));
        var lockOptions = Set.of(StandardOpenOption.CREATE, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
        try (var channel = FileChannel.open(lockPath, lockOptions, privatePermissions);
             var lock = channel.tryLock()) {
            if (lock == null) {
                return 75;
            }

            String comment = "firewallservice " + lines[1] + " " + Instant.now().truncatedTo(ChronoUnit.SECONDS);
            Process process = new ProcessBuilder(ufw.toString(), "allow", "from", lines[0], "comment", comment)
                    .redirectInput(new File("/dev/null"))
                    .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                    .redirectError(ProcessBuilder.Redirect.INHERIT)
                    .start();
            try {
                if (!process.waitFor(15, TimeUnit.SECONDS)) {
                    process.destroyForcibly().waitFor(1, TimeUnit.SECONDS);
                    throw new IOException("Timed out waiting for ufw");
                }
                return process.exitValue() == 0 ? 0 : 1;
            } finally {
                if (process.isAlive()) {
                    process.destroyForcibly();
                }
            }
        }
    }

    static boolean isNumericAddress(String address) {
        if (!ADDRESS.matcher(address).matches()) {
            return false;
        }
        int lastColon = address.lastIndexOf(':');
        if (lastColon < 0) {
            return isIpv4(address);
        }
        if (address.indexOf('.') >= 0 && !isIpv4(address.substring(lastColon + 1))) {
            return false;
        }
        try {
            // A colon makes the JDK parse the address as a literal without DNS.
            InetAddress.getByName(address);
            return true;
        } catch (UnknownHostException e) {
            return false;
        }
    }

    private static boolean isIpv4(String address) {
        if (!IPV4.matcher(address).matches()) {
            return false;
        }
        for (String octet : address.split("\\.")) {
            if (Integer.parseInt(octet) > 255) {
                return false;
            }
        }
        return true;
    }
}
