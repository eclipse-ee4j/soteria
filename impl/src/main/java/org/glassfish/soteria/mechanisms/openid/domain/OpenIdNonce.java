/*
 * Copyright (c) 2021 Contributors to the Eclipse Foundation
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
 * Contributors:
 *   2021 : Payara Foundation and/or its affiliates
 *      Initially authored in Security Connectors
 */
package org.glassfish.soteria.mechanisms.openid.domain;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.isNull;
import static org.glassfish.soteria.Utils.isEmpty;

import java.io.Serializable;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;

/**
 * Creates a random nonce as a character sequence of the specified byte length
 * and base64 url encoded.
 *
 * @author Gaurav Gupta
 * @author Rudy De Busscher
 */
public class OpenIdNonce implements Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * The default byte length of randomly generated nonce.
     */
    private static final int DEFAULT_BYTE_LENGTH = 32;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final String value;

    public OpenIdNonce() {
        this(DEFAULT_BYTE_LENGTH);
    }

    /**
     * Creates a new nonce with the given nonce value.
     *
     * @param value The nonce value. Must not be {@code null} or empty.
     */
    public OpenIdNonce(String value) {
        if (isEmpty(value)) {
            throw new IllegalArgumentException("The nonce value can't be null or empty");
        }
        this.value = value;
    }

    /**
     * @param byteLength The byte length of the randomly generated value.
     */
    public OpenIdNonce(int byteLength) {
        if (byteLength < 1) {
            throw new IllegalArgumentException("The byte length value must be greater than one");
        }
        byte[] array = new byte[byteLength];
        SECURE_RANDOM.nextBytes(array);
        value = new String(Base64.getUrlEncoder().withoutPadding().encode(array), UTF_8);
    }

    /**
     *
     * @return The generated random nonce.
     */
    public String getValue() {
        return value;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 29 * hash + Objects.hashCode(this.value);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (isNull(obj)) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final OpenIdNonce other = (OpenIdNonce) obj;
        return Objects.equals(this.value, other.value);
    }

    @Override
    public String toString() {
        return getValue();
    }

}
