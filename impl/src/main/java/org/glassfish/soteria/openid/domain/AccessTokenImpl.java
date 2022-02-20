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
package org.glassfish.soteria.openid.domain;

import com.nimbusds.jwt.*;
import jakarta.security.enterprise.identitystore.openid.AccessToken;
import jakarta.security.enterprise.identitystore.openid.JwtClaims;
import jakarta.security.enterprise.identitystore.openid.OpenIdConstant;
import jakarta.security.enterprise.identitystore.openid.Scope;

import java.text.ParseException;
import java.util.Date;
import java.util.Map;

import static java.util.Collections.emptyMap;
import static java.util.Objects.nonNull;

/**
 * @author Gaurav Gupta
 * @author Rudy De Busscher
 */
public class AccessTokenImpl implements AccessToken {

    private final String token;
    private final long tokenMinValidity;

    private final AccessToken.Type type;

    private final JwtClaims jwtClaims;

    private JWT tokenJWT;

    private Map<String, Object> claims;

    private final Long expiresIn;

    private final Scope scope;

    private final long createdAt;

    public AccessTokenImpl(String tokenType, String token, Long expiresIn, String scopeValue, long tokenMinValidity) {
        this.token = token;
        this.tokenMinValidity = tokenMinValidity;
        JWTClaimsSet jwtClaimsSet = null;
        try {
            this.tokenJWT = JWTParser.parse(token);
            jwtClaimsSet = tokenJWT.getJWTClaimsSet();
            this.claims = jwtClaimsSet.getClaims();
        } catch (ParseException ex) {
            // Access token doesn't need to be JWT at all
        }
        this.jwtClaims = NimbusJwtClaims.ifPresent(jwtClaimsSet);

        this.type = Type.valueOf(tokenType.toUpperCase());
        this.expiresIn = expiresIn;
        this.createdAt = System.currentTimeMillis();
        this.scope = Scope.parse(scopeValue);
    }

    @Override
    public boolean isExpired() {
        boolean expired;
        Date exp;
        if (nonNull(expiresIn)) {
            expired = System.currentTimeMillis() + tokenMinValidity > createdAt + (expiresIn * 1000);
        } else if (nonNull(exp = (Date) this.getClaim(OpenIdConstant.EXPIRATION_IDENTIFIER))) {
            expired = System.currentTimeMillis() + tokenMinValidity > exp.getTime();
        } else {
            throw new IllegalStateException("Missing expiration time (exp) claim in access token");
        }
        return expired;
    }

    @Override
    public Type getType() {
        return type;
    }

    @Override
    public String getToken() {
        return token;
    }

    @Override
    public Map<String, Object> getClaims() {
        if (claims == null) {
            return emptyMap();
        }
        return claims;
    }

    public void setClaims(Map<String, Object> claims) {
        this.claims = claims;
    }

    @Override
    public Object getClaim(String key) {
        return getClaims().get(key);
    }

    @Override
    public Long getExpirationTime() {
        return expiresIn;
    }

    @Override
    public Scope getScope() {
        return scope;
    }

    @Override
    public boolean isJWT() {
        return tokenJWT != null;
    }

    @Override
    public JwtClaims getJwtClaims() {
        return jwtClaims;
    }

    @Override
    public String toString() {
        return token;
    }

}
