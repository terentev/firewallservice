package com.terentev.firewallservice;

import java.util.LinkedHashMap;
import java.util.concurrent.TimeUnit;

public final class RequestLimiter {
    private static final int MAX_IPS = 1024;
    private static final long WINDOW_NANOS = TimeUnit.SECONDS.toNanos(30);

    private final LinkedHashMap<String, Long> lastRequestByIp = new LinkedHashMap<>();

    /** Records the request and returns true if the IP already requested within the window. */
    public synchronized boolean isManyRequest(String ip) {
        long now = System.nanoTime();
        var entries = lastRequestByIp.entrySet().iterator();
        while (entries.hasNext()) {
            var entry = entries.next();
            if (now - entry.getValue() < WINDOW_NANOS) {
                break;
            }
            entries.remove();
        }

        boolean repeated = lastRequestByIp.containsKey(ip);
        if (!repeated && lastRequestByIp.size() == MAX_IPS) {
            lastRequestByIp.pollFirstEntry();
        }
        lastRequestByIp.putLast(ip, now);
        return repeated;
    }
}
