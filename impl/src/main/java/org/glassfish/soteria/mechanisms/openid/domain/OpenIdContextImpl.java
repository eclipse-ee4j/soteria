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

import static java.util.logging.Level.WARNING;

import java.io.IOException;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Logger;

import org.glassfish.soteria.Utils;
import org.glassfish.soteria.mechanisms.openid.controller.AuthenticationController;
import org.glassfish.soteria.mechanisms.openid.controller.UserInfoController;
import org.glassfish.soteria.mechanisms.openid.http.HttpStorageController;

import jakarta.enterprise.context.SessionScoped;
import jakarta.inject.Inject;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.security.enterprise.authentication.mechanism.http.openid.OpenIdConstant;
import jakarta.security.enterprise.identitystore.openid.AccessToken;
import jakarta.security.enterprise.identitystore.openid.IdentityToken;
import jakarta.security.enterprise.identitystore.openid.OpenIdClaims;
import jakarta.security.enterprise.identitystore.openid.OpenIdContext;
import jakarta.security.enterprise.identitystore.openid.RefreshToken;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.ws.rs.core.UriBuilder;

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

    private static final Logger LOGGER = Logger.getLogger(OpenIdContextImpl.class.getName());

    private String callerName;
    private Set<String> callerGroups;
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
    public String getCallerName() {
        return callerName;
    }

    public void setCallerName(String callerName) {
        this.callerName = callerName;
    }

    @Override
    public Set<String> getCallerGroups() {
        return callerGroups;
    }

    public void setCallerGroups(Set<String> callerGroups) {
        this.callerGroups = callerGroups;
    }

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
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        LogoutConfiguration logout = configuration.getLogoutConfiguration();
        try {
            request.logout();
        } catch (ServletException ex) {
            LOGGER.log(WARNING, "Failed to logout the user.", ex);
        }
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }

        if (logout == null) {
            LOGGER.log(WARNING, "Logout invoked on session without OpenID session");
            redirect(response, request.getContextPath());
            return;
        }
        /*
         * See section 5. RP-Initiated Logout
         * https://openid.net/specs/openid-connect-session-1_0.html#RPLogout
         */
        if (logout.isNotifyProvider()
                && !Utils.isEmpty(configuration.getProviderMetadata().getEndSessionEndpoint())) {
            UriBuilder logoutURI = UriBuilder.fromUri(configuration.getProviderMetadata().getEndSessionEndpoint())
                    .queryParam(OpenIdConstant.ID_TOKEN_HINT, getIdentityToken().getToken());
            if (!Utils.isEmpty(logout.getRedirectURI())) {
                // User Agent redirected to POST_LOGOUT_REDIRECT_URI after a logout operation performed in OP.
                logoutURI.queryParam(OpenIdConstant.POST_LOGOUT_REDIRECT_URI, logout.buildRedirectURI(request));
            }
            redirect(response, logoutURI.toString());
        } else if (!Utils.isEmpty(logout.getRedirectURI())) {
            redirect(response, logout.buildRedirectURI(request));
        } else {
            // Redirect user to OpenID connect provider for re-authentication
            authenticationController.authenticateUser(request, response);
        }
    }

    private static void redirect(HttpServletResponse response, String uri) {
        try {
            response.sendRedirect(uri);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public <T> Optional<T> getStoredValue(HttpServletRequest request,
                                          HttpServletResponse response,
                                          String key) {
        return HttpStorageController.getInstance(configuration, request, response).get(key);
    }
}
