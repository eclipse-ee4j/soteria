/*
 * Copyright (c) 2015, 2018 Oracle and/or its affiliates. All rights reserved.
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

package org.glassfish.soteria.identitystores.hash;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import static java.util.Arrays.asList;
import java.util.Base64;
import static java.util.Collections.unmodifiableSet;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import jakarta.enterprise.context.Dependent;
import jakarta.security.enterprise.identitystore.Pbkdf2PasswordHash;

@Dependent
public class Pbkdf2PasswordHashImpl implements Pbkdf2PasswordHash {

    private static final Set<String> SUPPORTED_ALGORITHMS = unmodifiableSet(new HashSet<>(asList(
            "PBKDF2WithHmacSHA224",
            "PBKDF2WithHmacSHA256",
            "PBKDF2WithHmacSHA384",
            "PBKDF2WithHmacSHA512"
            )));

    private static final String DEFAULT_ALGORITHM = "PBKDF2WithHmacSHA256";

    private static final int DEFAULT_ITERATIONS = 2048;
    private static final int DEFAULT_SALT_SIZE  = 32;         // 32-byte/256-bit salt
    private static final int DEFAULT_KEY_SIZE   = 32;         // 32-byte/256-bit key/hash

    private static final int MIN_ITERATIONS = 1024;
    private static final int MIN_SALT_SIZE  = 16;             // 16-byte/128-bit minimum salt
    private static final int MIN_KEY_SIZE   = 16;             // 16-byte/128-bit minimum key/hash

    private static final String PROPERTY_ALGORITHM  = "Pbkdf2PasswordHash.Algorithm";
    private static final String PROPERTY_ITERATIONS = "Pbkdf2PasswordHash.Iterations";
    private static final String PROPERTY_SALTSIZE   = "Pbkdf2PasswordHash.SaltSizeBytes";
    private static final String PROPERTY_KEYSIZE    = "Pbkdf2PasswordHash.KeySizeBytes";

    private String configuredAlgorithm  = DEFAULT_ALGORITHM;   // PBKDF2 algorithm to use
    private int configuredIterations    = DEFAULT_ITERATIONS;  // number of iterations
    private int configuredSaltSizeBytes = DEFAULT_SALT_SIZE;   // salt size in bytes
    private int configuredKeySizeBytes  = DEFAULT_KEY_SIZE;    // derived key (i.e., password hash) size in bytes
    
    private final SecureRandom random = new SecureRandom();

    @Override
    public void initialize(Map<String, String> parameters) {
        for (Map.Entry<String, String> entry : parameters.entrySet()) {
            if (entry.getKey().equals(PROPERTY_ALGORITHM)) {
                if (!SUPPORTED_ALGORITHMS.contains(entry.getValue())) {
                    throw new IllegalArgumentException("Bad Algorithm parameter: " + entry.getValue());
                }
                configuredAlgorithm = entry.getValue();
            }
            else if (entry.getKey().equals(PROPERTY_ITERATIONS)) {
                try {
                    configuredIterations = Integer.parseInt(entry.getValue());
                }
                catch (Exception e) {
                    throw new IllegalArgumentException("Bad Iterations parameter: " + entry.getValue());
                }
                if (configuredIterations < MIN_ITERATIONS) {
                    throw new IllegalArgumentException("Bad Iterations parameter: " + entry.getValue());
                }
            }
            else if (entry.getKey().equals(PROPERTY_SALTSIZE)) {
                try {
                    configuredSaltSizeBytes = Integer.parseInt(entry.getValue());
                }
                catch (Exception e) {
                    throw new IllegalArgumentException("Bad SaltSizeBytes parameter: " + entry.getValue());
                }
                if (configuredSaltSizeBytes < MIN_SALT_SIZE) {
                    throw new IllegalArgumentException("Bad SaltSizeBytes parameter: " + entry.getValue());
                }
            }
            else if (entry.getKey().equals(PROPERTY_KEYSIZE)) {
                try {
                    configuredKeySizeBytes = Integer.parseInt(entry.getValue());
                }
                catch (Exception e) {
                    throw new IllegalArgumentException("Bad KeySizeBytes parameter: " + entry.getValue());
                }
                if (configuredKeySizeBytes < MIN_KEY_SIZE) {
                    throw new IllegalArgumentException("Bad KeySizeBytes parameter: " + entry.getValue());
                }
            }
            else {
                throw new IllegalArgumentException("Unrecognized parameter for Pbkdf2PasswordHash");
            }
        }
    }

    @Override
    public String generate(char[] password) {
        byte[] salt = getRandomSalt(new byte[configuredSaltSizeBytes]);
        byte[] hash = pbkdf2(password, salt, configuredAlgorithm, configuredIterations, configuredKeySizeBytes);
        return new EncodedPasswordHash(hash, salt, configuredAlgorithm, configuredIterations).getEncoded();
    }

    @Override
    public boolean verify(char[] password, String hashedPassword) {
        EncodedPasswordHash encodedPasswordHash = new EncodedPasswordHash(hashedPassword);
        byte[] hashToVerify = pbkdf2(
                password,
                encodedPasswordHash.getSalt(),
                encodedPasswordHash.getAlgorithm(),
                encodedPasswordHash.getIterations(),
                encodedPasswordHash.getHash().length);
        return PasswordHashCompare.compareBytes(hashToVerify, encodedPasswordHash.getHash());
    }

    private byte[] pbkdf2(char[] password, byte[] salt, String algorithm, int iterations, int keySizeBytes) {
        try {
            return SecretKeyFactory.getInstance(algorithm).generateSecret(
                    new PBEKeySpec(password, salt, iterations, keySizeBytes * 8)).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException(e);
        }
    }

    private synchronized byte[] getRandomSalt(byte[] salt) {
        random.nextBytes(salt);
        return salt;
    }

    private static class EncodedPasswordHash {

        private String algorithm;
        private int iterations;
        private byte[] salt;
        private byte[] hash;
        private String encoded;

        private EncodedPasswordHash() {};

        EncodedPasswordHash(byte[] hash, byte[] salt, String algorithm, int iterations) {
            this.algorithm = algorithm;
            this.iterations = iterations;
            this.salt = salt;
            this.hash = hash;
            encode();
        }

        EncodedPasswordHash(String encoded) {
            this.encoded = encoded;
            decode();
        }

        String getAlgorithm() { return algorithm; }
        int getIterations() { return iterations; }
        byte[] getSalt() { return salt; }
        byte[] getHash() { return hash; }
        String getEncoded() { return encoded; }

        private void encode() {
            encoded = algorithm + ":" + iterations + ":" +
                    Base64.getEncoder().encodeToString(salt) + ":" +
                    Base64.getEncoder().encodeToString(hash);
        }

        private void decode() {
            String[] tokens = encoded.split(":");
            if (tokens.length != 4) {
                throw new IllegalArgumentException("Bad hash encoding");
            }
            if (!SUPPORTED_ALGORITHMS.contains(tokens[0])) {
                throw new IllegalArgumentException("Bad hash encoding");
            }
            algorithm = tokens[0];
            try {
                iterations = Integer.parseInt(tokens[1]);
                salt = Base64.getDecoder().decode(tokens[2]);
                hash = Base64.getDecoder().decode(tokens[3]);
            }
            catch (Exception e) {
                throw new IllegalArgumentException("Bad hash encoding", e);
            }
        }
    }

}
