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

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.security.enterprise.AuthenticationStatus;
import jakarta.security.enterprise.identitystore.openid.OpenIdConstant;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.core.UriBuilder;
import org.glassfish.soteria.Utils;
import org.glassfish.soteria.openid.OpenIdState;
import org.glassfish.soteria.openid.domain.OpenIdConfiguration;
import org.glassfish.soteria.openid.domain.OpenIdNonce;
import org.glassfish.soteria.openid.http.HttpStorageController;

import java.io.IOException;
import java.util.logging.Logger;

import static java.util.logging.Level.FINEST;
import static jakarta.security.enterprise.AuthenticationStatus.SEND_CONTINUE;

/**
 * Controller for Authentication endpoint
 *
 * @author Gaurav Gupta
 * @author Rudy De Busscher
 */
@ApplicationScoped
public class AuthenticationController {

    @Inject
    private StateController stateController;

    @Inject
    private NonceController nonceController;

    @Inject
    private OpenIdConfiguration configuration;

    private static final Logger LOGGER = Logger.getLogger(AuthenticationController.class.getName());

    /**
     * (1) The RP (Client) sends a request to the OpenId Connect Provider (OP)
     * to authenticates the End-User using the Authorization Code Flow and
     * authorization Code is returned from the Authorization Endpoint.
     * <br>
     * (2) Authorization Server authenticates the End-User, obtains End-User
     * Consent/Authorization and sends the End-User back to the Client with an
     * Authorization Code.
     *
     *
     * @param request
     * @param response
     * @return
     */
    public AuthenticationStatus authenticateUser(
            HttpServletRequest request,
            HttpServletResponse response) {

        /*
         * Client prepares an authentication request and redirect to the
         * Authorization Server. if query param value is invalid then OpenId
         * Connect provider redirect to error page (hosted in OP domain).
         */
        UriBuilder authRequest
                = UriBuilder.fromUri(configuration.getProviderMetadata().getAuthorizationEndpoint())
                        .queryParam(OpenIdConstant.SCOPE, configuration.getScopes())
                        .queryParam(OpenIdConstant.RESPONSE_TYPE, configuration.getResponseType())
                        .queryParam(OpenIdConstant.CLIENT_ID, configuration.getClientId())
                        .queryParam(OpenIdConstant.REDIRECT_URI, configuration.buildRedirectURI(request));

        OpenIdState state = new OpenIdState();
        authRequest.queryParam(OpenIdConstant.STATE, state.getValue());
        stateController.store(state, configuration, request, response);

        storeRequestURL(request, response);

        // add nonce for replay attack prevention
        if (configuration.isUseNonce()) {
            OpenIdNonce nonce = new OpenIdNonce();
            // use a cryptographic hash of the value as the nonce parameter
            String nonceHash = nonceController.getNonceHash(nonce);
            authRequest.queryParam(OpenIdConstant.NONCE, nonceHash);
            nonceController.store(nonce, configuration, request, response);

        }
        if (!Utils.isEmpty(configuration.getResponseMode())) {
            authRequest.queryParam(OpenIdConstant.RESPONSE_MODE, configuration.getResponseMode());
        }
        if (!Utils.isEmpty(configuration.getDisplay())) {
            authRequest.queryParam(OpenIdConstant.DISPLAY, configuration.getDisplay());
        }
        if (!Utils.isEmpty(configuration.getPrompt())) {
            authRequest.queryParam(OpenIdConstant.PROMPT, configuration.getPrompt());
        }

        configuration.getExtraParameters().forEach(authRequest::queryParam);

        String authUrl = authRequest.toString();
        LOGGER.log(FINEST, "Redirecting for authentication to {0}", authUrl);
        try {
            response.sendRedirect(authUrl);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return SEND_CONTINUE;
    }

    private void storeRequestURL(HttpServletRequest request,
                                 HttpServletResponse response) {
        HttpStorageController storage = HttpStorageController.getInstance(configuration, request, response);

        storage.store(OpenIdConstant.ORIGINAL_REQUEST, getFullURL(request), null);

    }

    private  String getFullURL(HttpServletRequest request) {
        StringBuilder requestURL = new StringBuilder(request.getRequestURL().toString());
        String queryString = request.getQueryString();

        if (queryString == null) {
            return requestURL.toString();
        } else {
            return requestURL.append('?').append(queryString).toString();
        }
    }
}
