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
package org.glassfish.soteria.identitystores.jwt.token;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.SignedJWT;

import jakarta.json.Json;
import jakarta.json.JsonNumber;
import jakarta.json.JsonReader;
import jakarta.json.JsonString;
import jakarta.json.JsonValue;

import java.io.StringReader;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.glassfish.soteria.identitystores.jwt.JsonWebTokenImpl;
import org.glassfish.soteria.identitystores.jwt.keystore.PrivateKeyStore;
import org.glassfish.soteria.identitystores.jwt.keystore.PublicKeyStore;

import static com.nimbusds.jose.JWEAlgorithm.RSA_OAEP;
import static com.nimbusds.jose.JWEAlgorithm.RSA_OAEP_256;
import static com.nimbusds.jose.JWSAlgorithm.ES256;
import static com.nimbusds.jose.JWSAlgorithm.RS256;
import static org.glassfish.soteria.identitystores.jwt.token.JwtTokenParser.JwtType.detectType;

public class JwtTokenParser {

    private static String exp = "exp";
    private static String iat = "iat";
    private static String iss = "iss";
    private static String preferred_username = "preferred_username";
    private static String raw_token = "raw_token";
    private static String sub = "sub";
    private static String upn = "upn";

    private static final List<String> REQUIRED_CLAIMS = List.of(iss, exp, iat);

    private final boolean enableNamespacedClaims;
    private final String customNamespace;

    public enum JwtType {
        SIGNED, ENCRYPTED, INVALID;

        public static JwtType detectType(String token) {
            if (token == null) {
                return INVALID;
            }

            return switch (token.length() - token.replace(".", "").length()) {
            case 2 -> SIGNED; // 3 parts = 2 dots
            case 4 -> ENCRYPTED; // 5 parts = 4 dots
            default -> INVALID;
            };
        }
    }

    public JwtTokenParser() {
        this(false, null, false);
    }

    public JwtTokenParser(boolean enableNamespacedClaims, String customNamespace, boolean disableTypeVerification) {
        this.enableNamespacedClaims = enableNamespacedClaims;
        this.customNamespace = customNamespace;
    }

    public JsonWebTokenImpl parse(String bearerToken, boolean encryptionRequired, PublicKeyStore publicKeyStore, String acceptedIssuer,
            PrivateKeyStore privateKeyStore, long tokenAge, long clockSkew, String keyAlgorithm) {
        try {
            return switch (detectType(bearerToken)) {
                case SIGNED -> {
                    if (encryptionRequired) {
                        throw new IllegalStateException("JWT expected to be encrypted (JWE), but a signed token (JWS) was provided.");
                    }
                    yield processSignedToken(bearerToken, SignedJWT.parse(bearerToken), publicKeyStore, acceptedIssuer, tokenAge, clockSkew);
                }
                case ENCRYPTED ->
                    processEncryptedToken(bearerToken, EncryptedJWT.parse(bearerToken), publicKeyStore, privateKeyStore, acceptedIssuer, tokenAge, clockSkew, keyAlgorithm);
                case INVALID ->
                    throw new IllegalStateException("Invalid JWT token");
            };
        } catch (ParseException | JOSEException e) {
            throw new IllegalStateException("Failed to parse or decrypt JWT", e);
        }
    }


    // Handle the signed token

    private JsonWebTokenImpl processSignedToken(String rawToken, SignedJWT signedJWT, PublicKeyStore pubStore, String issuer, long age,
            long skew) {

        validateSignatureAlgorithm(signedJWT);

        try (JsonReader reader = Json.createReader(new StringReader(signedJWT.getPayload().toString()))) {
            Map<String, JsonValue> claims = handleNamespacedClaims(new HashMap<>(reader.readObject()));
            String principal = resolvePrincipal(claims);

            validateClaims(claims, signedJWT, issuer, principal, pubStore.getPublicKey(signedJWT.getHeader().getKeyID()), age, skew);

            // Inject the raw token into the claims map
            claims.put(raw_token, Json.createValue(rawToken));

            return new JsonWebTokenImpl(principal, claims);
        }
    }


    // Handle the encryped token

    private JsonWebTokenImpl processEncryptedToken(String rawToken, EncryptedJWT encryptedJWT, PublicKeyStore pubStore,
            PrivateKeyStore privStore, String issuer, long age, long skew, String alg)
            throws JOSEException, ParseException {

        validateEncryptionHeader(encryptedJWT, alg);

        String kid = encryptedJWT.getHeader().getKeyID();
        encryptedJWT.decrypt(new RSADecrypter(privStore.getPrivateKey(kid)));

        SignedJWT nestedSignedJWT = encryptedJWT.getPayload().toSignedJWT();
        if (nestedSignedJWT == null) {
            throw new IllegalStateException("JWE payload is not a valid Signed JWT");
        }

        return processSignedToken(rawToken, nestedSignedJWT, pubStore, issuer, age, skew);
    }

    private void validateClaims(Map<String, JsonValue> claims, SignedJWT signedJWT, String expectedIssuer, String principal, PublicKey key,
            long maxAge, long skew) {

        if (!claims.keySet().containsAll(REQUIRED_CLAIMS)) {
            throw new IllegalStateException("Missing required MP-JWT claims");
        }

        if (principal == null) {
            throw new IllegalStateException("No valid principal found (upn, preferred_username, or sub required)");
        }

        if (!checkIssuer(claims, expectedIssuer)) {
            throw new IllegalStateException("Issuer mismatch");
        }

        long now = Instant.now().getEpochSecond();
        long expTime = getLongClaim(claims, exp);
        long iatTime = getLongClaim(claims, iat);

        if (now - skew > expTime || iatTime > expTime) {
            throw new IllegalStateException("Token has expired");
        }

        if (maxAge > 0 && (now - skew - iatTime > maxAge)) {
            throw new IllegalStateException("Token exceeds maximum allowed age");
        }

        verifySignature(signedJWT, key);
    }

    private void verifySignature(SignedJWT signedJWT, PublicKey key) {
        try {
            boolean verified = signedJWT.getHeader().getAlgorithm().equals(RS256)
                    ? signedJWT.verify(new RSASSAVerifier((RSAPublicKey) key))
                    : signedJWT.verify(new ECDSAVerifier((ECPublicKey) key));

            if (!verified) {
                throw new IllegalStateException("Invalid JWT signature");
            }
        } catch (JOSEException e) {
            throw new IllegalStateException("Cryptographic error during verification", e);
        }
    }

    private String resolvePrincipal(Map<String, JsonValue> claims) {
        return Stream.of(upn, preferred_username, sub)
                     .map(c -> claims.get(c))
                     .filter(v -> v instanceof JsonString)
                     .map(v -> ((JsonString) v).getString())
                     .findFirst()
                     .orElse(null);
    }

    private Map<String, JsonValue> handleNamespacedClaims(Map<String, JsonValue> claims) {
        if (enableNamespacedClaims || customNamespace == null) {
            return claims;
        }

        Map<String, JsonValue> processed = new HashMap<>();
        claims.forEach((key, value) -> {
            String newKey = key.startsWith(customNamespace) ? key.substring(customNamespace.length()) : key;
            processed.put(newKey, value);
        });

        return processed;
    }

    @SuppressWarnings("deprecation")
    private void validateEncryptionHeader(EncryptedJWT jwt, String requiredAlg) {
        String cty = jwt.getHeader().getContentType();
        if (!"JWT".equals(cty)) {
            throw new IllegalStateException("No 'cty' header is set for encrypyted JWE");
        }

        String alg = jwt.getHeader().getAlgorithm().getName();
        if (!List.of(RSA_OAEP.getName(), RSA_OAEP_256.getName()).contains(alg)) {
            throw new IllegalStateException("Unsupported encryption algorithm: " + alg);
        }

        if (!requiredAlg.isEmpty() && !alg.equals(requiredAlg)) {
            throw new IllegalStateException("Algorithm " + alg + " does not match required " + requiredAlg);
        }
    }

    private void validateSignatureAlgorithm(SignedJWT jwt) {
        JOSEObjectType type = jwt.getHeader().getType();
        if (type == null || !type.toString().equals("JWT")) {
            throw new IllegalStateException("Type of header is not JWT for signed JWE");
        }

        JWSAlgorithm alg = jwt.getHeader().getAlgorithm();
        if (!alg.equals(RS256) && !alg.equals(ES256)) {
            throw new IllegalStateException("Unsupported signing algorithm: " + alg);
        }
    }

    private boolean checkIssuer(Map<String, JsonValue> claims, String expected) {
        return
            claims.get(iss) instanceof JsonString issClaimString &&
            issClaimString.getString().equals(expected);
    }

    private long getLongClaim(Map<String, JsonValue> claims, String claim) {
        return ((JsonNumber) claims.get(claim)).longValue();
    }
}