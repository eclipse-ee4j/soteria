/*
 * Copyright (c) 2026 Contributors to the Eclipse Foundation.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0, which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * This Source Code may also be made available under the following Secondary
 * Licenses when the conditions for such availability set forth in the
 * Eclipse Public License v. 2.0 are satisfied: GNU General Public License,
 * version 2 with the GNU Classpath Exception, which is available at
 * https://www.gnu.org/software/classpath/license.html.
 *
 * SPDX-License-Identifier: EPL-2.0 OR GPL-2.0 WITH Classpath-exception-2.0
 */
package org.glassfish.soteria.identitystores.jwt.keystore;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.Charset;
import java.nio.charset.IllegalCharsetNameException;
import java.time.Duration;
import java.util.Objects;
import java.util.logging.Logger;
import java.util.stream.Stream;

import org.glassfish.soteria.identitystores.jwt.keystore.Cache.CacheItem;

import static java.lang.Character.isWhitespace;
import static java.lang.Long.parseLong;
import static java.lang.System.lineSeparator;
import static java.lang.Thread.currentThread;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.stream.Collectors.joining;

public class RawKeyLoader {

    private static final Logger LOGGER = Logger.getLogger(RawKeyLoader.class.getName());

    private final String keyLocation;
    private final Cache<String> cache;

    public RawKeyLoader(String keyLocation, Duration defaultCacheTTL) {
        this.keyLocation = keyLocation;
        cache = new Cache<String>(defaultCacheTTL);
    }

    public String readRawPublicKey() {
        return cache.computeIfAbsentOrExpired(() -> readKeyFromLocation(keyLocation));
    }

    private CacheItem<String> readKeyFromLocation(String keyLocation) {
        // Try if keyLocation refers to the classpath, e.g. "publicKey.pem"
        URL keyURL = currentThread().getContextClassLoader().getResource(keyLocation);

        if (keyURL == null) {
            try {
                keyURL = new URL(keyLocation);
            } catch (MalformedURLException ex) {
                keyURL = null;
            }
        }
        if (keyURL == null) {
            return new CacheItem<>(null, null);
        }

        try {
            return readKeyFromURL(keyURL);
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to read key.", ex);
        }
    }

    private CacheItem<String> readKeyFromURL(URL keyURL) throws IOException {
        URLConnection connection = keyURL.openConnection();

        Charset charset = resolveCharset(connection);
        Duration cacheTTL = resolveCacheTTL(connection);

        try (InputStream inputStream = connection.getInputStream();
             BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, charset))) {

            return CacheItem.of(reader.lines().collect(joining(lineSeparator())), cacheTTL);
        }
    }

    private Charset resolveCharset(URLConnection connection) {
        String charsetName = getCharacterEncoding(connection.getContentType());
        if (charsetName == null) {
            return UTF_8;
        }

        try {
            if (!Charset.isSupported(charsetName)) {
                LOGGER.warning("Charset " + charsetName + " for remote key not supported, using UTF-8 instead");
                return UTF_8;
            }

            return Charset.forName(charsetName);
        } catch (IllegalCharsetNameException ex) {
            LOGGER.severe(
                "Illegal charset name " + ex.getCharsetName() +
                " for remote key, using UTF-8 instead. Cause: " + ex.getMessage());
            return UTF_8;
        }
    }

    private Duration resolveCacheTTL(URLConnection connection) {
        return connection.getHeaderFields().entrySet().stream()
                .filter(entry -> entry.getKey() != null)
                .filter(entry -> "Cache-Control".equalsIgnoreCase(entry.getKey().trim()))
                .flatMap(entry -> entry.getValue().stream())
                .flatMap(value -> Stream.of(value.split(",")))
                .map(String::trim)
                .map(this::parseMaxAgeDirective)
                .filter(Objects::nonNull)
                .min(Duration::compareTo)
                .orElse(null);
    }

    private Duration parseMaxAgeDirective(String directive) {
        if (!directive.startsWith("max-age")) {
            return null;
        }

        String[] keyValue = directive.split("=", 2);
        if (keyValue.length != 2) {
            return null;
        }

        try {
            return Duration.ofSeconds(parseLong(keyValue[1].trim()));
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static String getCharacterEncoding(String type) {
        if (type == null || type.isEmpty()) {
            return null;
        }

        int index = type.indexOf(';');
        while (index != -1) {
            int len = type.length();
            index++;

            while (index < len && isWhitespace(type.charAt(index))) {
                index++;
            }

            int eq = type.indexOf('=', index);
            if (eq == -1) {
                break;
            }

            String name = type.substring(index, eq).trim();
            if ("charset".equalsIgnoreCase(name)) {
                int valueStart = eq + 1;
                int nextParam = type.indexOf(';', valueStart);
                String value = (nextParam != -1 ? type.substring(valueStart, nextParam) : type.substring(valueStart)).trim();

                if (value.isEmpty()) {
                    return null;
                }

                if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
                    value = value.substring(1, value.length() - 1).trim();
                }

                return value.isEmpty() ? null : value;
            }

            index = type.indexOf(';', eq);
        }

        return null;
    }

}

final class Cache<T> {

    private final Duration defaultTTL;
    private volatile State<T> state = State.uninitialized();

    public Cache(Duration defaultTTL) {
        this.defaultTTL = defaultTTL;
    }

    public <E extends Exception> T computeIfAbsentOrExpired(ThrowingItemSupplier<? extends T, E> supplier) throws E {
        State<T> current = state;
        long now = System.nanoTime();

        if (current.isExpired(now)) {
            refresh(now, supplier);
            current = state;
        }

        return current.value;
    }

    private <E extends Exception> void refresh(long now, ThrowingItemSupplier<? extends T, E> supplier) throws E {
        synchronized (this) {
            if (!state.isExpired(now)) {
                return;
            }

            CacheItem<? extends T> item = supplier.get();
            Duration ttl = item.ttl() != null ? item.ttl() : defaultTTL;

            state = new State<>(item.payload(), System.nanoTime() + ttl.toNanos(), true);
        }
    }

    @FunctionalInterface
    public interface ThrowingItemSupplier<T, E extends Exception> {
        CacheItem<T> get() throws E;
    }

    /**
     * ttl == null means: use the cache's default TTL.
     */
    public static record CacheItem<T>(T payload, Duration ttl) {
        public static <T> CacheItem<T> of(T payload, Duration ttl) {
            return new CacheItem<>(payload, ttl);
        }

        public static <T> CacheItem<T> withDefaultTTL(T payload) {
            return new CacheItem<>(payload, null);
        }
    }

    private static final class State<T> {
        private final T value;
        private final long expiresAtNanos;
        private final boolean initialized;

        private State(T value, long expiresAtNanos, boolean initialized) {
            this.value = value;
            this.expiresAtNanos = expiresAtNanos;
            this.initialized = initialized;
        }

        private static <T> State<T> uninitialized() {
            return new State<>(null, 0L, false);
        }

        private boolean isExpired(long nowNanos) {
            return !initialized || nowNanos >= expiresAtNanos;
        }
    }
}
