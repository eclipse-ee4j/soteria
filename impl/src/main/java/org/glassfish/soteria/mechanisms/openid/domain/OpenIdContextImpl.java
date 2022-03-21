/*
 * Copyright (c) 2021, 2022 Contributors to the Eclipse Foundation
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

import java.util.Optional;

import org.glassfish.soteria.mechanisms.openid.controller.AuthenticationController;
import org.glassfish.soteria.mechanisms.openid.controller.UserInfoController;
import org.glassfish.soteria.servlet.HttpStorageController;

import jakarta.enterprise.context.SessionScoped;
import jakarta.inject.Inject;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.security.enterprise.identitystore.openid.AccessToken;
import jakarta.security.enterprise.identitystore.openid.IdentityToken;
import jakarta.security.enterprise.identitystore.openid.OpenIdClaims;
import jakarta.security.enterprise.identitystore.openid.OpenIdContext;
import jakarta.security.enterprise.identitystore.openid.RefreshToken;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * An injectable interface that provides access to access token, identity token,
 * claims and OpenId Connect provider related information.
 *
 * @author Gaurav Gupta
 * @author Rudy De Busscher
 */
@SessionScoped
public class OpenIdContextImpl implements OpenIdContext {
    private static final long serialVersionUID = 1L;

    private String tokenType;
    private AccessToken accessToken;
    private IdentityToken identityToken;
    private RefreshToken refreshToken;
    private Long expiresIn;
    private JsonObject claims;

    @Inject
    private UserInfoController userInfoController;

    @Inject
    private OpenIdConfiguration configuration;

    @Inject
    private AuthenticationController authenticationController;

    @Override
    public String getSubject() {
        return getIdentityToken().getJwtClaims().getSubject().orElse(null);
    }

    @Override
    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    @Override
    public AccessToken getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(AccessToken token) {
        this.accessToken = token;
    }

    @Override
    public IdentityToken getIdentityToken() {
        return identityToken;
    }

    public void setIdentityToken(IdentityToken identityToken) {
        this.identityToken = identityToken;
    }

    @Override
    public Optional<RefreshToken> getRefreshToken() {
        return Optional.ofNullable(refreshToken);
    }

    public void setRefreshToken(RefreshToken refreshToken) {
        this.refreshToken = refreshToken;
    }

    @Override
    public Optional<Long> getExpiresIn() {
        return Optional.ofNullable(expiresIn);
    }

    public void setExpiresIn(Long expiresIn) {
        this.expiresIn = expiresIn;
    }

    @Override
    public JsonObject getClaimsJson() {
        if (claims == null) {
            if (configuration != null && accessToken != null) {
                claims = userInfoController.getUserInfo(configuration, accessToken);
            } else {
                claims = Json.createObjectBuilder().build();
            }
        }
        return claims;
    }

    @Override
    public OpenIdClaims getClaims() {
        return new JsonClaims(getClaimsJson());
    }

    @Override
    public JsonObject getProviderMetadata() {
        return configuration.getProviderMetadata().getDocument();
    }

    @Override
    public <T> Optional<T> getStoredValue(HttpServletRequest request,
                                          HttpServletResponse response,
                                          String key) {
        return HttpStorageController.getInstance(configuration, request, response).get(key);
    }
}
