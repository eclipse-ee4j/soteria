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
package org.glassfish.soteria.openid;


import static jakarta.security.enterprise.AuthenticationStatus.SEND_FAILURE;
import static jakarta.security.enterprise.AuthenticationStatus.SUCCESS;
import static jakarta.security.enterprise.identitystore.CredentialValidationResult.INVALID_RESULT;
import static jakarta.security.enterprise.identitystore.CredentialValidationResult.NOT_VALIDATED_RESULT;
import static jakarta.security.enterprise.identitystore.openid.OpenIdConstant.ERROR_DESCRIPTION_PARAM;
import static jakarta.security.enterprise.identitystore.openid.OpenIdConstant.ERROR_PARAM;
import static jakarta.security.enterprise.identitystore.openid.OpenIdConstant.EXPIRES_IN;
import static jakarta.security.enterprise.identitystore.openid.OpenIdConstant.REFRESH_TOKEN;
import static jakarta.security.enterprise.identitystore.openid.OpenIdConstant.STATE;
import static jakarta.security.enterprise.identitystore.openid.OpenIdConstant.TOKEN_TYPE;
import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;
import static java.util.logging.Level.INFO;
import static java.util.logging.Level.WARNING;

import java.io.IOException;
import java.io.Serializable;
import java.io.StringReader;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.glassfish.soteria.Utils;
import org.glassfish.soteria.openid.controller.AuthenticationController;
import org.glassfish.soteria.openid.controller.StateController;
import org.glassfish.soteria.openid.controller.TokenController;
import org.glassfish.soteria.openid.domain.LogoutConfiguration;
import org.glassfish.soteria.openid.domain.OpenIdConfiguration;
import org.glassfish.soteria.openid.domain.OpenIdContextImpl;
import org.glassfish.soteria.openid.domain.RefreshTokenImpl;

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.enterprise.inject.Typed;
import jakarta.inject.Inject;
import jakarta.json.Json;
import jakarta.json.JsonNumber;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.security.auth.message.callback.CallerPrincipalCallback;
import jakarta.security.enterprise.AuthenticationException;
import jakarta.security.enterprise.AuthenticationStatus;
import jakarta.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism;
import jakarta.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import jakarta.security.enterprise.identitystore.CredentialValidationResult;
import jakarta.security.enterprise.identitystore.IdentityStoreHandler;
import jakarta.security.enterprise.identitystore.openid.RefreshToken;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;

/**
 * The AuthenticationMechanism used to authenticate users using the OpenId
 * Connect protocol
 * <br/>
 * Specification Implemented :
 * http://openid.net/specs/openid-connect-core-1_0.html
 *
 * @author Gaurav Gupta
 * @author Rudy De Busscher
 */
//  +--------+                                                       +--------+
//  |        |                                                       |        |
//  |        |---------------(1) Authentication Request------------->|        |
//  |        |                                                       |        |
//  |        |       +--------+                                      |        |
//  |        |       |  End-  |<--(2) Authenticates the End-User---->|        |
//  |   RP   |       |  User  |                                      |   OP   |
//  |        |       +--------+                                      |        |
//  |        |                                                       |        |
//  |        |<---------(3) returns Authorization code---------------|        |
//  |        |                                                       |        |
//  |        |                                                       |        |
//  |        |------------------------------------------------------>|        |
//  |        |   (4) Request to TokenEndpoint for Access / Id Token  |        |
//  | OpenId |<------------------------------------------------------| OpenId |
//  | Connect|                                                       | Connect|
//  | Client | ----------------------------------------------------->|Provider|
//  |        |   (5) Fetch JWKS to validate ID Token                 |        |
//  |        |<------------------------------------------------------|        |
//  |        |                                                       |        |
//  |        |------------------------------------------------------>|        |
//  |        |   (6) Request to UserInfoEndpoint for End-User Claims |        |
//  |        |<------------------------------------------------------|        |
//  |        |                                                       |        |
//  +--------+                                                       +--------+
@ApplicationScoped
@Typed(OpenIdAuthenticationMechanism.class)
public class OpenIdAuthenticationMechanism implements HttpAuthenticationMechanism {

    @Inject
    private OpenIdConfiguration configuration;

    @Inject
    private OpenIdContextImpl context;

    private IdentityStoreHandler identityStoreHandler;

    @Inject
    private AuthenticationController authenticationController;

    @Inject
    private TokenController tokenController;

    @Inject
    private StateController stateController;

    @Inject
    Instance<IdentityStoreHandler> storeHandlerInstance;

    private static final Logger LOGGER = Logger.getLogger(OpenIdAuthenticationMechanism.class.getName());

    private static class Lock implements Serializable {
        private static final long serialVersionUID = 1L;
    }

    private static final String SESSION_LOCK_NAME = OpenIdAuthenticationMechanism.class.getName();

    @PostConstruct
    void init() {
        if (storeHandlerInstance.isResolvable()) {
            identityStoreHandler = storeHandlerInstance.get();
            return;
        }

        throw new IllegalStateException("Cannot get instance of IdentityStoreHandler\n" +
                "@Inject IdentityStoreHandler is unsatisfied.");
    }

    @Override
    public AuthenticationStatus validateRequest(
            HttpServletRequest request,
            HttpServletResponse response,
            HttpMessageContext httpContext) throws AuthenticationException {

        if (isNull(request.getUserPrincipal())) {
            LOGGER.fine("UserPrincipal is not set, authenticate user using OpenId Connect protocol.");

            // User is not authenticated
            // Perform steps (1) to (6)
            return this.authenticate(request, response, httpContext);
        } else {
            // User has been authenticated in request before

            // Try-catch-block taken from AutoApplySessionInterceptor
            // We cannot use @AutoApplySession, because validateRequest(...) must be called on every request
            // to handle re-authentication (refreshing tokens)
            // https://stackoverflow.com/questions/51678821/soteria-httpmessagecontext-setregistersession-not-working-as-expected/51819055
            // https://github.com/javaee/security-soteria/blob/master/impl/src/main/java/org/glassfish/soteria/cdi/AutoApplySessionInterceptor.java
            try {
                httpContext.getHandler().handle(new Callback[]{
                        new CallerPrincipalCallback(httpContext.getClientSubject(), request.getUserPrincipal())}
                );
            } catch (IOException | UnsupportedCallbackException ex) {
                throw new AuthenticationException("Failed to register CallerPrincipalCallback.", ex);
            }

            LogoutConfiguration logout = configuration.getLogoutConfiguration();
            boolean accessTokenExpired = this.context.getAccessToken().isExpired();
            boolean identityTokenExpired = this.context.getIdentityToken().isExpired();
            if (logout.isIdentityTokenExpiry()) {
                LOGGER.log(Level.FINE, "UserPrincipal is set, check if Identity Token is valid.");
            }
            if (logout.isAccessTokenExpiry()) {
                LOGGER.log(Level.FINE, "UserPrincipal is set, check if Access Token is valid.");
            }

            if ((accessTokenExpired || identityTokenExpired) && configuration.isTokenAutoRefresh()) {
                if (accessTokenExpired) {
                    LOGGER.fine("Access Token is expired. Request new Access Token with Refresh Token.");
                }
                if (identityTokenExpired) {
                    LOGGER.fine("Identity Token is expired. Request new Identity Token with Refresh Token.");
                }
                return this.reAuthenticate(httpContext);
            } else if ((logout.isAccessTokenExpiry() && accessTokenExpired)
                    || (logout.isIdentityTokenExpiry() && identityTokenExpired)) {
                context.logout(request, response);
                return SEND_FAILURE;
            } else {
                return SUCCESS;
            }
        }
    }

    private AuthenticationStatus authenticate(
            HttpServletRequest request,
            HttpServletResponse response,
            HttpMessageContext httpContext) {

        if (httpContext.isProtected() && isNull(request.getUserPrincipal())) {
            // (1) The End-User is not authenticated.
            return authenticationController.authenticateUser(request, response);
        }

        Optional<OpenIdState> receivedState = OpenIdState.from(request.getParameter(STATE));
        String redirectURI = configuration.buildRedirectURI(request);
        if (receivedState.isPresent()) {
            if (!request.getRequestURL().toString().equals(redirectURI)) {
                LOGGER.log(INFO, "OpenID Redirect URL {0} not matched with request URL {1}", new Object[]{redirectURI, request.getRequestURL().toString()});
                return httpContext.notifyContainerAboutLogin(NOT_VALIDATED_RESULT);
            }
            Optional<OpenIdState> expectedState = stateController.get(request, response);
            if (!expectedState.isPresent()) {
                LOGGER.fine("Expected state not found");
                return httpContext.notifyContainerAboutLogin(NOT_VALIDATED_RESULT);
            }
            if (!expectedState.equals(receivedState)) {
                LOGGER.fine("Inconsistent received state, value not matched");
                return httpContext.notifyContainerAboutLogin(INVALID_RESULT);
            }
            // (3) Successful Authentication Response : redirect_uri?code=abc&state=123
            return validateAuthorizationCode(httpContext);
        }
        return httpContext.doNothing();
    }

    /**
     * (3) & (4-6) An Authorization Code returned to Client (RP) via
     * Authorization Code Flow must be validated and exchanged for an ID Token,
     * an Access Token and optionally a Refresh Token directly.
     *
     * @param httpContext the {@link HttpMessageContext} to validate
     *                    authorization code from
     * @return the authentication status.
     */
    private AuthenticationStatus validateAuthorizationCode(HttpMessageContext httpContext) {
        HttpServletRequest request = httpContext.getRequest();
        HttpServletResponse response = httpContext.getResponse();
        String error = request.getParameter(ERROR_PARAM);
        String errorDescription = request.getParameter(ERROR_DESCRIPTION_PARAM);
        if (!Utils.isEmpty(error)) {
            // Error responses sent to the redirect_uri
            LOGGER.log(WARNING, "Error occurred in receiving Authorization Code : {0} caused by {1}", new Object[]{error, errorDescription});
            return httpContext.notifyContainerAboutLogin(INVALID_RESULT);
        }
        stateController.remove(request, response);

        LOGGER.finer("Authorization Code received, now fetching Access token & Id token");

        Response tokenResponse = tokenController.getTokens(request);
        JsonObject tokensObject = readJsonObject(tokenResponse.readEntity(String.class));
        if (tokenResponse.getStatus() == Status.OK.getStatusCode()) {
            // Successful Token Response
            updateContext(tokensObject);
            OpenIdCredential credential = new OpenIdCredential(tokensObject, httpContext, configuration.getTokenMinValidity());
            CredentialValidationResult validationResult = identityStoreHandler.validate(credential);

            // Register session manually (if @AutoApplySession used, this would be done by its interceptor)
            httpContext.setRegisterSession(validationResult.getCallerPrincipal().getName(), validationResult.getCallerGroups());
            return httpContext.notifyContainerAboutLogin(validationResult);
        } else {
            // Token Request is invalid or unauthorized
            error = tokensObject.getString(ERROR_PARAM, "Unknown Error");
            errorDescription = tokensObject.getString(ERROR_DESCRIPTION_PARAM, "Unknown");
            LOGGER.log(WARNING, "Error occurred in validating Authorization Code : {0} caused by {1}", new Object[]{error, errorDescription});
            return httpContext.notifyContainerAboutLogin(INVALID_RESULT);
        }
    }

    private AuthenticationStatus reAuthenticate(HttpMessageContext httpContext) throws AuthenticationException {
        HttpServletRequest request = httpContext.getRequest();
        HttpServletResponse response = httpContext.getResponse();
        synchronized (this.getSessionLock(httpContext.getRequest())) {
            boolean accessTokenExpired = this.context.getAccessToken().isExpired();
            boolean identityTokenExpired = this.context.getIdentityToken().isExpired();
            if (accessTokenExpired || identityTokenExpired) {

                if (accessTokenExpired) {
                    LOGGER.fine("Access Token is expired. Request new Access Token with Refresh Token.");
                }
                if (identityTokenExpired) {
                    LOGGER.fine("Identity Token is expired. Request new Identity Token with Refresh Token.");
                }

                AuthenticationStatus refreshStatus = this.context.getRefreshToken()
                        .map(rt -> this.refreshTokens(httpContext, rt))
                        .orElse(AuthenticationStatus.SEND_FAILURE);

                if (refreshStatus != AuthenticationStatus.SUCCESS) {
                    LOGGER.log(Level.FINE, "Failed to refresh token (Refresh Token might be invalid).");
                    context.logout(request, response);
                }
                return refreshStatus;
            }
        }

        return SUCCESS;
    }

    private AuthenticationStatus refreshTokens(HttpMessageContext httpContext, RefreshToken refreshToken) {
        Response response = tokenController.refreshTokens(refreshToken);
        JsonObject tokensObject = readJsonObject(response.readEntity(String.class));

        if (response.getStatus() == Response.Status.OK.getStatusCode()) {
            // Successful Token Response
            updateContext(tokensObject);
            OpenIdCredential credential = new OpenIdCredential(tokensObject, httpContext, configuration.getTokenMinValidity());
            CredentialValidationResult validationResult = identityStoreHandler.validate(credential);

            // Do not register session, as this will invalidate the currently active session (destroys session beans and removes attributes set in session)!
            // httpContext.setRegisterSession(validationResult.getCallerPrincipal().getName(), validationResult.getCallerGroups());
            return httpContext.notifyContainerAboutLogin(validationResult);
        } else {
            // Token Request is invalid (refresh token invalid or expired)
            String error = tokensObject.getString(ERROR_PARAM, "Unknown Error");
            String errorDescription = tokensObject.getString(ERROR_DESCRIPTION_PARAM, "Unknown");
            LOGGER.log(Level.FINE, "Error occurred in refreshing Access Token and Refresh Token : {0} caused by {1}", new Object[]{error, errorDescription});
            return AuthenticationStatus.SEND_FAILURE;
        }
    }

    private JsonObject readJsonObject(String tokensBody) {
        try (JsonReader reader = Json.createReader(new StringReader(tokensBody))) {
            return reader.readObject();
        }
    }

    private void updateContext(JsonObject tokensObject) {
        context.setTokenType(tokensObject.getString(TOKEN_TYPE, null));

        String refreshToken = tokensObject.getString(REFRESH_TOKEN, null);
        if (nonNull(refreshToken)) {
            context.setRefreshToken(new RefreshTokenImpl(refreshToken));
        }
        JsonNumber expiresIn = tokensObject.getJsonNumber(EXPIRES_IN);
        if (nonNull(expiresIn)) {
            context.setExpiresIn(expiresIn.longValue());
        }
    }

    private Object getSessionLock(HttpServletRequest request) {
        HttpSession session = request.getSession();
        Object lock = session.getAttribute(SESSION_LOCK_NAME);
        if (isNull(lock)) {
            synchronized (OpenIdAuthenticationMechanism.class) {
                lock = session.getAttribute(SESSION_LOCK_NAME);
                if (isNull(lock)) {
                    lock = new Lock();
                    session.setAttribute(SESSION_LOCK_NAME, lock);
                }

            }
        }

        return lock;
    }

}
