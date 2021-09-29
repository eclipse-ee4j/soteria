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


import jakarta.json.JsonObject;
import jakarta.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import jakarta.security.enterprise.credential.Credential;
import jakarta.security.enterprise.identitystore.openid.AccessToken;
import org.glassfish.soteria.openid.domain.AccessTokenImpl;
import org.glassfish.soteria.openid.domain.IdentityTokenImpl;

import static jakarta.security.enterprise.identitystore.openid.OpenIdConstant.*;
import static java.util.Objects.nonNull;

/**
 * @author Gaurav Gupta
 * @author Rudy De Busscher
 */
public class OpenIdCredential implements Credential {

    private final HttpMessageContext httpContext;

    private final IdentityTokenImpl identityToken;

    private final AccessToken accessToken;

    public OpenIdCredential(JsonObject tokensObject, HttpMessageContext httpContext, long tokenMinValidity) {
        this.httpContext = httpContext;

        this.identityToken = new IdentityTokenImpl(tokensObject.getString(IDENTITY_TOKEN), tokenMinValidity);
        String accessTokenString = tokensObject.getString(ACCESS_TOKEN, null);
        Long expiresIn = null;
        if (nonNull(tokensObject.getJsonNumber(EXPIRES_IN))) {
            expiresIn = tokensObject.getJsonNumber(EXPIRES_IN).longValue();
        }
        String tokenType = tokensObject.getString(TOKEN_TYPE, null);
        String scopeString = tokensObject.getString(SCOPE, null);
        if (nonNull(accessTokenString)) {
            accessToken = new AccessTokenImpl(tokenType, accessTokenString, expiresIn, scopeString, tokenMinValidity);
        } else {
            accessToken = null;
        }
    }

    /**
     * Only for internal use within Soteria to be able to validate the token.
     *
     * @return Identity Token Implementation
     */
    IdentityTokenImpl getIdentityTokenImpl() {
        return identityToken;
    }

    public AccessToken getAccessToken() {
        return accessToken;
    }

    public HttpMessageContext getHttpContext() {
        return httpContext;
    }

}
