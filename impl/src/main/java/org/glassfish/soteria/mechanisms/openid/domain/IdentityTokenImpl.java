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

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import jakarta.security.enterprise.identitystore.openid.IdentityToken;
import jakarta.security.enterprise.identitystore.openid.JwtClaims;

import java.text.ParseException;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;


/**
 * @author Gaurav Gupta
 * @author Rudy De Busscher
 */
public class IdentityTokenImpl implements IdentityToken {

    private final String token;
    private final long tokenMinValidity;

    private final JWT tokenJWT;

    private final JWTClaimsSet claims;

    public IdentityTokenImpl(String token, long tokenMinValidity) {
        this.token = token;
        this.tokenMinValidity = tokenMinValidity;
        try {
            this.tokenJWT = JWTParser.parse(token);
            this.claims = tokenJWT.getJWTClaimsSet();
        } catch (ParseException ex) {
            throw new IllegalStateException("Error in parsing the Token", ex);
        }
    }

    private IdentityTokenImpl(JWT token, JWTClaimsSet verifiedClaims, long tokenMinValidity) {
        this.token = token.getParsedString();
        this.tokenJWT = token;
        this.claims = verifiedClaims;
        this.tokenMinValidity = tokenMinValidity;
    }

    public JWT getTokenJWT() {
        return tokenJWT;
    }

    @Override
    public String getToken() {
        return token;
    }

    @Override
    public JwtClaims getJwtClaims() {
        return NimbusJwtClaims.ifPresent(this.claims);
    }

    @Override
    public boolean isExpired() {
        boolean expired;
        Optional<Instant> expirationTime = this.getJwtClaims().getExpirationTime();
        if (expirationTime.isPresent()) {
            expired = System.currentTimeMillis() + tokenMinValidity > expirationTime.get().toEpochMilli();
        } else {
            throw new IllegalStateException("Missing expiration time (exp) claim in identity token");
        }
        return expired;
    }

    @Override
    public Map<String, Object> getClaims() {
        return claims.getClaims();
    }

    @Override
    public String toString() {
        return token;
    }

    public IdentityToken withClaims(JWTClaimsSet verifiedClaims) {
        return new IdentityTokenImpl(tokenJWT, verifiedClaims, tokenMinValidity);
    }
}
