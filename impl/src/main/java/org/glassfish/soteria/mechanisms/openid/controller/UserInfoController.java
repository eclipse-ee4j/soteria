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


import static jakarta.security.enterprise.identitystore.openid.OpenIdConstant.ERROR_DESCRIPTION_PARAM;
import static jakarta.security.enterprise.identitystore.openid.OpenIdConstant.SUBJECT_IDENTIFIER;
import static jakarta.ws.rs.core.HttpHeaders.CONTENT_TYPE;
import static jakarta.ws.rs.core.MediaType.APPLICATION_JSON;
import static java.util.Objects.nonNull;
import static java.util.logging.Level.WARNING;

import java.io.StringReader;
import java.util.logging.Logger;

import org.glassfish.soteria.mechanisms.openid.domain.OpenIdConfiguration;

import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.security.enterprise.identitystore.openid.AccessToken;
import jakarta.security.enterprise.identitystore.openid.OpenIdConstant;
import jakarta.security.enterprise.identitystore.openid.OpenIdContext;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;

/**
 * Controller for Token endpoint
 *
 * @author Gaurav Gupta
 * @author Rudy De Busscher
 */
@RequestScoped
public class UserInfoController {

    @Inject
    private OpenIdContext context;

    private static final String APPLICATION_JWT = "application/jwt";
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_TYPE = "Bearer ";

    private static final Logger LOGGER = Logger.getLogger(UserInfoController.class.getName());

    /**
     * (6) The RP send a request with the Access Token to the UserInfo Endpoint
     * and requests the claims about the End-User.
     *
     * @param configuration the OpenId Connect client configuration configuration
     * @param accessToken
     * @return the claims json object
     */
    public JsonObject getUserInfo(OpenIdConfiguration configuration, AccessToken accessToken) {
        LOGGER.finest("Sending the request to the userinfo endpoint");
        JsonObject userInfo;

        Client client = ClientBuilder.newClient();
        WebTarget target = client.target(configuration.getProviderMetadata().getUserinfoEndpoint());
        Response response = target.request()
                .accept(APPLICATION_JSON)
                .header(AUTHORIZATION_HEADER, BEARER_TYPE + accessToken)
                // 5.5.  Requesting Claims using the "claims" Request Parameter ??
                .get();

        String responseBody = response.readEntity(String.class);

        String contentType = response.getHeaderString(CONTENT_TYPE);
        if (response.getStatus() == Status.OK.getStatusCode()) {
            if (nonNull(contentType) && contentType.contains(APPLICATION_JSON)) {
                // Successful UserInfo Response
                try (JsonReader reader = Json.createReader(new StringReader(responseBody))) {
                    userInfo = reader.readObject();
                }
            } else if (nonNull(contentType) && contentType.contains(APPLICATION_JWT)) {
                throw new UnsupportedOperationException("application/jwt content-type not supported for userinfo endpoint");
                //If the UserInfo Response is signed and/or encrypted, then the Claims are returned in a JWT and the content-type MUST be application/jwt. The response MAY be encrypted without also being signed. If both signing and encryption are requested, the response MUST be signed then encrypted, with the result being a Nested JWT, ??
                //If signed, the UserInfo Response SHOULD contain the Claims iss (issuer) and aud (audience) as members. The iss value SHOULD be the OP's Issuer Identifier URL. The aud value SHOULD be or include the RP's Client ID value.
            } else {
                throw new IllegalStateException("Invalid response received from userinfo endpoint with content-type : " + contentType);
            }
        } else {
            // UserInfo Error Response
            JsonObject responseObject = Json.createReader(new StringReader(responseBody)).readObject();
            String error = responseObject.getString(OpenIdConstant.ERROR_PARAM, "Unknown Error");
            String errorDescription = responseObject.getString(ERROR_DESCRIPTION_PARAM, "Unknown");
            LOGGER.log(WARNING, "Error occurred in fetching user info: {0} caused by {1}", new Object[]{error, errorDescription});
            throw new IllegalStateException("Error occurred in fetching user info");
        }

        validateUserInfoClaims(userInfo);
        return userInfo;
    }

    private void validateUserInfoClaims(JsonObject userInfo) {
        /*
         * Check the token substitution attacks : The sub Claim in the UserInfo
         * Response must be verified to exactly match the sub claim in the ID
         * Token.
         */
        if (!context.getSubject().equals(userInfo.getString(SUBJECT_IDENTIFIER))) {
            throw new IllegalStateException("UserInfo Response is invalid as sub claim must match with the sub Claim in the ID Token");
        }
    }

}
