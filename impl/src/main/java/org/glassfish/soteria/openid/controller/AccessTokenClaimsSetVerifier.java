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
package org.glassfish.soteria.openid.controller;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import jakarta.security.enterprise.identitystore.openid.AccessToken;
import jakarta.security.enterprise.identitystore.openid.OpenIdConstant;
import org.glassfish.soteria.openid.domain.OpenIdConfiguration;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Map;

import static java.nio.charset.StandardCharsets.US_ASCII;

/**
 * Validates the Access token
 *
 * @author Gaurav Gupta
 * @author Rudy De Busscher
 */
public class AccessTokenClaimsSetVerifier extends TokenClaimsSetVerifier {

    private final AccessToken accessToken;

    private final Algorithm idTokenAlgorithm;

    private final Map<String, Object> idTokenClaims;

    public AccessTokenClaimsSetVerifier(
            AccessToken accessToken,
            Algorithm idTokenAlgorithm,
            Map<String, Object> idTokenClaims,
            OpenIdConfiguration configuration) {
        super(configuration);
        this.accessToken = accessToken;
        this.idTokenAlgorithm = idTokenAlgorithm;
        this.idTokenClaims = idTokenClaims;
    }

    @Override
    public void verify(JWTClaimsSet claims) throws BadJWTException {
        validateAccessToken();
    }

    public void validateAccessToken() {
        if (idTokenClaims.containsKey(OpenIdConstant.ACCESS_TOKEN_HASH)) {

            //Get the message digest for the JWS algorithm value used in the header(alg) of the ID Token
            MessageDigest md = getMessageDigest(idTokenAlgorithm);

            // Hash the octets of the ASCII representation of the access_token with the hash algorithm
            md.update(accessToken.toString().getBytes(US_ASCII));
            byte[] hash = md.digest();

            // Take the left-most half of the hash and base64url encode it.
            byte[] leftHalf = Arrays.copyOf(hash, hash.length / 2);
            String accessTokenHash = Base64URL.encode(leftHalf).toString();

            // The value of at_hash in the ID Token MUST match the value produced
            if (!idTokenClaims.get(OpenIdConstant.ACCESS_TOKEN_HASH).equals(accessTokenHash)) {
                throw new IllegalStateException("Invalid access token hash (at_hash) value");
            }
        }
    }

    /**
     * Get the message digest instance for the given JWS algorithm value.
     *
     * @param algorithm The JSON Web Signature (JWS) algorithm.
     *
     * @return The message digest instance
     */
    private MessageDigest getMessageDigest(Algorithm algorithm) {
        String mdAlgorithm = "SHA-" + algorithm.getName().substring(2);

        try {
            return MessageDigest.getInstance(mdAlgorithm);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("No MessageDigest instance found with the specified algorithm : " + mdAlgorithm, ex);
        }
    }

}
