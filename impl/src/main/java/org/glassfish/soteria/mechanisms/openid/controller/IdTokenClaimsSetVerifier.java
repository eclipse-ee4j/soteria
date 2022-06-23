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
package org.glassfish.soteria.mechanisms.openid.controller;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;

import jakarta.security.enterprise.authentication.mechanism.http.openid.OpenIdConstant;

import static java.util.Objects.isNull;

import org.glassfish.soteria.mechanisms.openid.domain.OpenIdConfiguration;

/**
 * Validates the ID token
 *
 * @author Gaurav Gupta
 * @author Rudy De Busscher
 */
public class IdTokenClaimsSetVerifier extends TokenClaimsSetVerifier {

    private final String expectedNonceHash;

    public IdTokenClaimsSetVerifier(String expectedNonceHash, OpenIdConfiguration configuration) {
        super(configuration);
        this.expectedNonceHash = expectedNonceHash;
    }

    /**
     * Validate ID Token's claims
     *
     * @param claims
     * @throws com.nimbusds.jwt.proc.BadJWTException
     */
    @Override
    public void verify(JWTClaimsSet claims) throws BadJWTException {

        /*
         * If a nonce was sent in the authentication request, a nonce claim must
         * be present and its value checked to verify that it is the same value
         * as the one that was sent in the authentication request to detect
         * replay attacks.
         */
        if (configuration.isUseNonce()) {

            final String nonce;

            try {
                nonce = claims.getStringClaim(OpenIdConstant.NONCE);
            } catch (java.text.ParseException ex) {
                throw new IllegalStateException("Invalid nonce claim", ex);
            }

            if (isNull(nonce)) {
                throw new IllegalStateException("Missing nonce claim");
            }
            if (isNull(expectedNonceHash)) {
                throw new IllegalStateException("Missing expected nonce claim");
            }
            if (!expectedNonceHash.equals(nonce)) {
                throw new IllegalStateException("Invalid nonce claim : " + nonce);
            }
        }

//      5.5.1.  Individual Claims Requests
//      If the acr Claim was requested, the Client SHOULD check that the asserted Claim Value is appropriate. The meaning and processing of acr Claim Values is out of scope for this specification. ??
//      If the auth_time Claim was requested, either through a specific request for this Claim or by using the max_age parameter, the Client SHOULD check the auth_time Claim value and request re-authentication if it determines too much time has elapsed since the last End-User authentication.
    }

}
