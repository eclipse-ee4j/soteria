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

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import jakarta.security.enterprise.identitystore.openid.IdentityToken;
import jakarta.security.enterprise.identitystore.openid.OpenIdConstant;
import org.glassfish.soteria.openid.domain.OpenIdConfiguration;

import java.util.List;

import static java.util.Objects.isNull;

/**
 * Validates the ID token received from the Refresh token response
 *
 * @author Gaurav Gupta
 * @author Rudy De Busscher
 */
public class RefreshedIdTokenClaimsSetVerifier extends TokenClaimsSetVerifier {

    private final IdentityToken previousIdToken;

    public RefreshedIdTokenClaimsSetVerifier(IdentityToken previousIdToken, OpenIdConfiguration configuration) {
        super(configuration);
        this.previousIdToken = previousIdToken;
    }

    /**
     * Validate ID Token's claims received from the Refresh token response
     *
     * @param claims
     * @throws com.nimbusds.jwt.proc.BadJWTException
     */
    @Override
    public void verify(JWTClaimsSet claims) throws BadJWTException {

        String previousIssuer = previousIdToken.getJwtClaims().getIssuer().orElse(null);
        String newIssuer = claims.getIssuer();
        if (newIssuer == null || !newIssuer.equals(previousIssuer)) {
            throw new IllegalStateException("iss Claim Value MUST be the same as in the ID Token issued when the original authentication occurred.");
        }

        String previousSubject = previousIdToken.getJwtClaims().getSubject().orElse(null);
        String newSubject = claims.getSubject();
        if (newSubject == null || !newSubject.equals(previousSubject)) {
            throw new IllegalStateException("sub Claim Value MUST be the same as in the ID Token issued when the original authentication occurred.");
        }

        List<String> previousAudience = previousIdToken.getJwtClaims().getAudience();
        List<String> newAudience = claims.getAudience();
        if (newAudience == null || !newAudience.equals(previousAudience)) {
            throw new IllegalStateException("aud Claim Value MUST be the same as in the ID Token issued when the original authentication occurred.");
        }

        if (isNull(claims.getIssueTime())) {
            throw new IllegalStateException("iat Claim Value must not be null.");
        }

        String previousAzp = (String) previousIdToken.getClaims().get(OpenIdConstant.AUTHORIZED_PARTY);
        String newAzp = (String) claims.getClaim(OpenIdConstant.AUTHORIZED_PARTY);
        if (previousAzp == null ? newAzp != null : !previousAzp.equals(newAzp)) {
            throw new IllegalStateException("azp Claim Value MUST be the same as in the ID Token issued when the original authentication occurred.");
        }

        // if the ID Token contains an auth_time Claim, its value MUST represent the time of the original authentication - not the time that the new ID token is issued,
    }

}
