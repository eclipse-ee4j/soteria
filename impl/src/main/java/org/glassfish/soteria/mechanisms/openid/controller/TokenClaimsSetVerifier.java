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

import static java.util.Objects.isNull;

import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.glassfish.soteria.mechanisms.openid.domain.OpenIdConfiguration;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier;

import jakarta.security.enterprise.identitystore.openid.OpenIdConstant;

/**
 *
 * @author Gaurav Gupta
 * @author Rudy De Busscher
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation">OpenID Connect core 1.0, section 3.1.3.7</a>
 */
public abstract class TokenClaimsSetVerifier implements JWTClaimsSetVerifier {

    protected final OpenIdConfiguration configuration;

    public TokenClaimsSetVerifier(OpenIdConfiguration configuration) {
        this.configuration = configuration;
    }

    protected static class StandardVerifications {
        private final OpenIdConfiguration configuration;
        private final JWTClaimsSet claims;

        public StandardVerifications(OpenIdConfiguration configuration, JWTClaimsSet claims) {
            this.configuration = configuration;
            this.claims = claims;
        }

        /**
         * The Issuer Identifier for the OpenID Provider (which is typically
         * obtained during Discovery) must exactly match the value of the iss
         * (issuer) Claim.
         */
        public void requireSameIssuer() {
            if (isNull(claims.getIssuer())) {
                throw new IllegalStateException("Missing issuer (iss) claim");
            }
            if (!claims.getIssuer().equals(configuration.getProviderMetadata().getIssuerURI())) {
                throw new IllegalStateException("Invalid issuer : " + configuration.getProviderMetadata().getIssuerURI());
            }
        }

        /**
         * Subject Identifier is locally unique and never reassigned identifier
         * within the Issuer for the End-User.
         */
        public void requireSubject() {
            if (isNull(claims.getSubject())) {
                throw new IllegalStateException("Missing subject (sub) claim");
            }

        }

        /**
         * Audience(s) claim (that this ID Token is intended for) must contains
         * the client_id of the Client (Relying Party) as an audience value.
         *
         * Other use cases may allow different audience than client Id, but generally require one.
         */
        public void requireAudience(String requiredAudience) {
            final List<String> audience = claims.getAudience();
            if (isNull(audience) || audience.isEmpty()) {
                throw new IllegalStateException("Missing audience (aud) claim");
            }
            if (requiredAudience != null && !audience.contains(requiredAudience)) {
                throw new IllegalStateException("Invalid audience (aud) claim " + audience);
            }
        }


        /**
         * If the ID Token contains multiple audiences, the Client should verify
         * that an azp (authorized party) claim is present.
         *
         * If an azp (authorized party) claim is present, the Client should
         * verify that its client_id is the claim Value
         */
        public void assureAuthorizedParty(String clientId) {
            Object authorizedParty = claims.getClaim(OpenIdConstant.AUTHORIZED_PARTY);
            List<String> audience = claims.getAudience();
            if (audience.size() > 1 && isNull(authorizedParty)) {
                throw new IllegalStateException("Missing authorized party (azp) claim");
            }

            if (audience.size() > 1
                    && !authorizedParty.equals(clientId)) {
                throw new IllegalStateException("Invalid authorized party (azp) claim " + authorizedParty);
            }
        }

        /**
         * The current time must be before the time represented by the exp
         * Claim.
         *
         * The current time must be after the time represented by the iat Claim.
         *
         * The current time must be after the time represented by nbf claim
         */
        public void requireValidTimestamp() {
            long clockSkewInMillis = TimeUnit.MINUTES.toMillis(1);
            long currentTime = System.currentTimeMillis();
            Date exp = claims.getExpirationTime();
            if (isNull(exp)) {
                throw new IllegalStateException("Missing expiration time (exp) claim");
            }
            if ((exp.getTime() + clockSkewInMillis) < currentTime) {
                throw new IllegalStateException("Token is expired " + exp);
            }

            Date iat = claims.getIssueTime();
            if (isNull(iat)) {
                throw new IllegalStateException("Missing issue time (iat) claim");
            }
            if ((iat.getTime() - clockSkewInMillis) > currentTime) {
                throw new IllegalStateException("Issue time must be after current time " + iat);
            }

            Date nbf = claims.getNotBeforeTime();
            if (!isNull(nbf) && (nbf.getTime() - clockSkewInMillis) > currentTime) {
                throw new IllegalStateException("Token is not valid before " + nbf);
            }
        }
    }

    @Override
    public void verify(JWTClaimsSet claims, SecurityContext c) throws BadJWTException {
        StandardVerifications standardVerifications = new StandardVerifications(configuration, claims);

        standardVerifications.requireSameIssuer();
        standardVerifications.requireSubject();
        standardVerifications.requireAudience(configuration.getClientId());
        standardVerifications.assureAuthorizedParty(configuration.getClientId());
        standardVerifications.requireValidTimestamp();

        verify(claims);
    }

    public abstract void verify(JWTClaimsSet jwtcs) throws BadJWTException;

}
