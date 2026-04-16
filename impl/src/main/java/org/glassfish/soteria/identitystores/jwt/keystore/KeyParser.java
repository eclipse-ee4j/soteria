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

import jakarta.enterprise.inject.spi.DeploymentException;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.json.JsonValue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;
import java.util.logging.Logger;

import static java.util.stream.Collectors.joining;

/**
 * This class focused on the raw "materials" (turning strings into cryptographic keys)
 */
public class KeyParser {

    private static final Logger LOGGER = Logger.getLogger(KeyParser.class.getName());

    private static final String RSA_ALGORITHM = "RSA";
    private static final String EC_ALGORITHM = "EC";

    enum KeyFormat {
        PEM,
        JSON_JWK_OR_JWKS,
        BASE64_JSON_JWK_OR_JWKS,
        BASE64_DER,
        UNKNOWN
    }

    public PublicKey createPublicKey(String key, String keyId) {
        try {
            return switch (detectKeyFormat(key)) {
                case PEM, BASE64_DER -> createPublicKeyFromPem(key);
                case JSON_JWK_OR_JWKS, BASE64_JSON_JWK_OR_JWKS -> createPublicKeyFromJWKS(key, keyId);
                default -> throw new DeploymentException("Unrecognized public key format");
            };
        } catch (DeploymentException e) {
            throw e;
        } catch (Exception e) {
            throw new DeploymentException(e);
        }
    }

    public PrivateKey createPrivateKey(String key, String keyId) {
        try {
            return switch (detectKeyFormat(key)) {
                case PEM, BASE64_DER -> createPrivateKeyFromPem(key);
                case JSON_JWK_OR_JWKS, BASE64_JSON_JWK_OR_JWKS -> createPrivateKeyFromJWKS(key, keyId);
                default -> throw new DeploymentException("Unrecognized private key format");
            };
        } catch (DeploymentException e) {
            throw e;
        } catch (Exception e) {
            throw new DeploymentException(e);
        }
    }

    private PublicKey createPublicKeyFromPem(String key) throws Exception {
       X509EncodedKeySpec publicKeySpec =
           new X509EncodedKeySpec(
               Base64.getDecoder()
                     .decode(trimPem(key)));

       try {
           return KeyFactory.getInstance(RSA_ALGORITHM)
                            .generatePublic(publicKeySpec);
       } catch (InvalidKeySpecException invalidKeySpecException) {
           // Try ECDSA
           LOGGER.finer("Caught InvalidKeySpecException creating public key from PEM using RSA algorithm, " +
                   "attempting again using ECDSA");

           return KeyFactory.getInstance(EC_ALGORITHM)
                            .generatePublic(publicKeySpec);
       }
   }

   private PublicKey createPublicKeyFromJWKS(String jwksValue, String keyId) throws Exception {
       JsonObject jwk = parseJwk(jwksValue, keyId);
       String kty = getKty(jwk);

       var decoder = Base64.getUrlDecoder();

       if (kty.equals("RSA")) {
           return KeyFactory.getInstance(RSA_ALGORITHM)
                            .generatePublic(
                                new RSAPublicKeySpec(
                                    new BigInteger(1, decoder.decode(jwk.getString("n"))),
                                    new BigInteger(1, decoder.decode(jwk.getString("e")))));

       } else if (kty.equals("EC")) {
           // Get parameters
           AlgorithmParameters parameters = AlgorithmParameters.getInstance(EC_ALGORITHM);

           // Check CRV
           String crv = jwk.getString("crv", null);
           if (!"P-256".equals(crv)) {
               throw new DeploymentException("Could not get EC key from JWKS: crv does not equal P-256");
           }

           parameters.init(new ECGenParameterSpec("secp256r1"));

           return KeyFactory.getInstance(EC_ALGORITHM)
                   .generatePublic(
                       new ECPublicKeySpec(
                           new ECPoint(
                               new BigInteger(1, decoder.decode(jwk.getString("x"))),
                               new BigInteger(1, decoder.decode(jwk.getString("y")))),
                           parameters.getParameterSpec(ECParameterSpec.class)));
       } else {
           throw new DeploymentException("Could not determine key type - JWKS kty field does not equal RSA or EC");
       }
    }

    private PrivateKey createPrivateKeyFromPem(String key) throws Exception {
        return
            KeyFactory.getInstance(RSA_ALGORITHM)
                      .generatePrivate(
                          new PKCS8EncodedKeySpec(
                              Base64.getDecoder()
                                    .decode(trimPem(key))));
    }

    private PrivateKey createPrivateKeyFromJWKS(String jwksValue, String keyId) throws Exception {
        JsonObject jwk = parseJwk(jwksValue, keyId);

        if (getKty(jwk).equals(RSA_ALGORITHM)) {
            var decoder = Base64.getUrlDecoder();

            return KeyFactory.getInstance(RSA_ALGORITHM)
                             .generatePrivate(
                                 new RSAPrivateKeySpec(
                                     new BigInteger(1, decoder.decode(jwk.getString("n"))),
                                     new BigInteger(1, decoder.decode(jwk.getString("d")))));
        } else {
            throw new DeploymentException("Could not determine key type - JWKS kty field does not equal RSA");
        }
    }

    private static KeyFormat detectKeyFormat(String key) {
        if (key == null || key.isBlank()) {
            return KeyFormat.UNKNOWN;
        }

        String trimmed = key.trim();

        // PEM armor
        if (trimmed.startsWith("-----BEGIN ") && trimmed.contains("-----END ")) {
            return KeyFormat.PEM;
        }

        // Plain JSON JWK/JWKS
        if (looksLikeJwkJson(trimmed)) {
            return KeyFormat.JSON_JWK_OR_JWKS;
        }

        // Base64-decoded JSON JWK/JWKS
        try {
            byte[] decoded = Base64.getDecoder().decode(trimmed);
            String decodedText = new String(decoded, java.nio.charset.StandardCharsets.UTF_8).trim();

            if (looksLikeJwkJson(decodedText)) {
                return KeyFormat.BASE64_JSON_JWK_OR_JWKS;
            }

            // If it decoded but is not JSON, assume it may be DER-encoded key material
            return KeyFormat.BASE64_DER;
        } catch (IllegalArgumentException e) {
            return KeyFormat.UNKNOWN;
        }
    }

    private static boolean looksLikeJwkJson(String s) {
        if (!s.startsWith("{")) {
            return false;
        }

        try (JsonReader reader = Json.createReader(new StringReader(s))) {
            JsonObject obj = reader.readObject();
            return obj.containsKey("keys") || obj.containsKey("kty");
        } catch (Exception e) {
            return false;
        }
    }

    private static JsonObject parseJwk(String jwksValue, String keyId) throws IOException {
        JsonObject jwks = parseJwks(jwksValue);
        JsonArray keys = jwks.getJsonArray("keys");

        return keys != null ? findJwk(keys, keyId) : jwks;
    }

    private static JsonObject parseJwks(String jwksValue) throws IOException {
        JsonObject jwks;
        try (JsonReader reader = Json.createReader(new StringReader(jwksValue))) {
            jwks = reader.readObject();
        } catch (Exception ex) {
            byte[] jwksDecodedValue = Base64.getDecoder().decode(jwksValue);
            try (InputStream jwksStream = new ByteArrayInputStream(jwksDecodedValue);
                    JsonReader reader = Json.createReader(jwksStream)) {
                jwks = reader.readObject();
            }
        }

        return jwks;
    }

    private static JsonObject findJwk(JsonArray keys, String keyID) {
        if (Objects.isNull(keyID) && keys.size() > 0) {
            return keys.getJsonObject(0);
        }

        for (JsonValue value : keys) {
            JsonObject jwk = value.asJsonObject();
            if (Objects.equals(keyID, jwk.getString("kid", null))) {
                return jwk;
            }
        }

        throw new IllegalStateException("No matching JWK for KeyID.");
    }

    private static String getKty(JsonObject jwk) {
        String kty = jwk.getString("kty", null);
        if (kty == null) {
            throw new DeploymentException("Could not determine key type - kty field not present");
        }

        return kty;
    }

    private static String trimPem(String key) {
        if (key == null) {
            return null;
        }

        return
            key.lines()
               .map(String::trim)
               .filter(line -> !line.isEmpty())
               .filter(line -> !(line.startsWith("-----BEGIN ") && line.endsWith("-----")))
               .filter(line -> !(line.startsWith("-----END ") && line.endsWith("-----")))
               .collect(joining());
    }

}
