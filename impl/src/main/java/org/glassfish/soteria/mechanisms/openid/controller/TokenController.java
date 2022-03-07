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

import static jakarta.ws.rs.core.MediaType.APPLICATION_JSON;
import static java.util.Collections.emptyMap;

import java.util.Map;

import org.glassfish.soteria.mechanisms.openid.domain.AccessTokenImpl;
import org.glassfish.soteria.mechanisms.openid.domain.IdentityTokenImpl;
import org.glassfish.soteria.mechanisms.openid.domain.OpenIdConfiguration;
import org.glassfish.soteria.mechanisms.openid.domain.OpenIdNonce;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jwt.JWTClaimsSet;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import jakarta.security.enterprise.identitystore.openid.IdentityToken;
import jakarta.security.enterprise.identitystore.openid.OpenIdConstant;
import jakarta.security.enterprise.identitystore.openid.RefreshToken;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.Form;
import jakarta.ws.rs.core.Response;

/**
 * Controller for Token endpoint
 *
 * @author Gaurav Gupta
 * @author Rudy De Busscher
 */
@ApplicationScoped
public class TokenController {

    @Inject
    private NonceController nonceController;

    @Inject
    private OpenIdConfiguration configuration;

    @Inject
    private JWTValidator validator;

    /**
     * (4) A Client makes a token request to the token endpoint and the OpenId
     * Provider responds with an ID Token and an Access Token.
     *
     * @param request
     * @return a JSON object representation of OpenID Connect token response
     * from the Token endpoint.
     */
    public Response getTokens(HttpServletRequest request) {
        /*
         * one-time authorization code that RP exchange for an Access / Id token
         */
        String authorizationCode = request.getParameter(OpenIdConstant.CODE);

        /*
         * The Client sends the parameters to the Token Endpoint using the Form
         * Serialization with all parameters to :
         *
         * 1. Authenticate client using CLIENT_ID & CLIENT_SECRET <br>
         * 2. Verify that the Authorization Code is valid <br>
         * 3. Ensure that the redirect_uri parameter value is identical to the
         * initial authorization request's redirect_uri parameter value.
         */
        Form form = new Form()
                .param(OpenIdConstant.CLIENT_ID, configuration.getClientId())
                .param(OpenIdConstant.CLIENT_SECRET, new String(configuration.getClientSecret()))
                .param(OpenIdConstant.GRANT_TYPE, OpenIdConstant.AUTHORIZATION_CODE)
                .param(OpenIdConstant.CODE, authorizationCode)
                .param(OpenIdConstant.REDIRECT_URI, configuration.buildRedirectURI(request));

        //  ID Token and Access Token Request
        Client client = ClientBuilder.newClient();
        WebTarget target = client.target(configuration.getProviderMetadata().getTokenEndpoint());
        return target.request()
                .accept(APPLICATION_JSON)
                .post(Entity.form(form));
    }

    /**
     * (5.1) Validate Id Token's claims and verify ID Token's signature.
     *
     * @param idToken
     * @param httpContext
     * @return JWT Claims
     */
    public JWTClaimsSet validateIdToken(IdentityTokenImpl idToken, HttpMessageContext httpContext) {
        JWTClaimsSet claimsSet;
        HttpServletRequest request = httpContext.getRequest();
        HttpServletResponse response = httpContext.getResponse();

        /*
         * The nonce in the returned ID Token is compared to the hash of the
         * session cookie to detect ID Token replay by third parties.
         */
        String expectedNonceHash = null;
        if (configuration.isUseNonce()) {
            OpenIdNonce expectedNonce = nonceController.get(configuration, request, response);
            expectedNonceHash = nonceController.getNonceHash(expectedNonce);
        }

        try {
            claimsSet = validator.validateBearerToken(
                            idToken.getTokenJWT(),
                            new IdTokenClaimsSetVerifier(expectedNonceHash, configuration));
        } finally {
            nonceController.remove(configuration, request, response);
        }

        return claimsSet;
    }

    /**
     * Validate Id Token received from Successful Refresh Response.
     *
     * @param previousIdToken
     * @param newIdToken
     * @return JWT Claims
     */
    public JWTClaimsSet validateRefreshedIdToken(IdentityToken previousIdToken, IdentityTokenImpl newIdToken) {
        return validator.validateBearerToken(
                newIdToken.getTokenJWT(),
                new RefreshedIdTokenClaimsSetVerifier(previousIdToken, configuration));
    }

    /**
     * (5.2) Validate the Access Token and its claims and verify the signature.
     *
     * @param accessToken
     * @param idTokenAlgorithm
     * @param idTokenClaims
     * @return JWT Claims
     */
    public Map<String, Object> validateAccessToken(AccessTokenImpl accessToken, Algorithm idTokenAlgorithm, Map<String, Object> idTokenClaims) {
        Map<String, Object> claims = emptyMap();

        AccessTokenClaimsSetVerifier jwtVerifier = new AccessTokenClaimsSetVerifier(
                accessToken,
                idTokenAlgorithm,
                idTokenClaims,
                configuration
        );

        jwtVerifier.validateAccessToken();

        return claims;
    }

    /**
     * Makes a refresh request to the token endpoint and the OpenId Provider
     * responds with a new (updated) Access Token and Refreshs Token.
     *
     * @param refreshToken Refresh Token received from previous token request.
     * @return a JSON object representation of OpenID Connect token response
     * from the Token endpoint.
     */
    public Response refreshTokens(RefreshToken refreshToken) {
        Form form = new Form()
                .param(OpenIdConstant.CLIENT_ID, configuration.getClientId())
                .param(OpenIdConstant.CLIENT_SECRET, new String(configuration.getClientSecret()))
                .param(OpenIdConstant.GRANT_TYPE, OpenIdConstant.REFRESH_TOKEN)
                .param(OpenIdConstant.REFRESH_TOKEN, refreshToken.getToken());

        // Access Token and RefreshToken Request
        Client client = ClientBuilder.newClient();
        WebTarget target = client.target(configuration.getProviderMetadata().getTokenEndpoint());
        return target.request()
                .accept(APPLICATION_JSON)
                .post(Entity.form(form));
    }

}
