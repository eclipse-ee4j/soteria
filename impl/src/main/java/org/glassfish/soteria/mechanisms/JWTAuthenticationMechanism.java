/*
 * Copyright (c) 2026 Contributors to the Eclipse Foundation.
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
 * SPDX-License-Identifier: EPL-2.0 OR GPL-2.0 WITH Classpath-exception-2.0
 */
package org.glassfish.soteria.mechanisms;

import jakarta.enterprise.inject.spi.CDI;
import jakarta.security.enterprise.AuthenticationException;
import jakarta.security.enterprise.AuthenticationStatus;
import jakarta.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism;
import jakarta.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import jakarta.security.enterprise.identitystore.CredentialValidationResult;
import jakarta.security.enterprise.identitystore.IdentityStore;
import jakarta.security.enterprise.identitystore.IdentityStoreHandler;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.Optional;

import org.glassfish.soteria.TokenCredential;
import org.glassfish.soteria.identitystores.jwt.JWTConfiguration;

import static jakarta.security.enterprise.identitystore.CredentialValidationResult.Status.VALID;
import static org.glassfish.soteria.identitystores.jwt.JWTConfiguration.CONFIG_TOKEN_HEADER_AUTHORIZATION;

/**
 * This authentication mechanism reads a JWT token from an HTTP header and passes it
 * to an {@link IdentityStore} for validation.
 *
 * @author Arjan Tijms
 */
public class JWTAuthenticationMechanism implements HttpAuthenticationMechanism {

    private final boolean useHeader;
    private final String configJwtTokenCookie;

    public JWTAuthenticationMechanism(JWTConfiguration jwtConfiguration) {
        this.useHeader = CONFIG_TOKEN_HEADER_AUTHORIZATION.equals(jwtConfiguration.configJwtTokenHeader());
        this.configJwtTokenCookie = jwtConfiguration.configJwtTokenCookie();
    }

    @Override
    public AuthenticationStatus validateRequest(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMessageContext) throws AuthenticationException {
        TokenCredential credential = getCredential(request);
        if (credential == null) {
            return httpMessageContext.doNothing();
        }

        CredentialValidationResult result =
            CDI.current()
               .select(IdentityStoreHandler.class)
               .get()
               .validate(credential);

        if (result.getStatus() != VALID) {
            return httpMessageContext.responseUnauthorized();
        }

        httpMessageContext.getClientSubject()
                .getPrincipals()
                .add(result.getCallerPrincipal());

        return httpMessageContext.notifyContainerAboutLogin(result);
    }

    private TokenCredential getCredential(HttpServletRequest request) {
        Optional<String> token = Optional.empty();
        if (useHeader) {
            String authorizationHeader = request.getHeader("Authorization");
            if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
                token = Optional.of(authorizationHeader.substring("Bearer ".length()));
            }
        } else {
            // use Cookie header
            String bearerMark = ";" + configJwtTokenCookie + "=";
            String cookieHeader = request.getHeader("Cookie");
            if (cookieHeader != null && cookieHeader.startsWith("$Version=") && cookieHeader.contains(bearerMark)) {
                token = Optional.of(cookieHeader.substring(cookieHeader.indexOf(bearerMark) + bearerMark.length()));
            }
        }

        return token.map(t -> createSignedJWTCredential(t))
                    .orElse(null);
    }

    private TokenCredential createSignedJWTCredential(String token) {
        if (token != null && !token.isEmpty()) {
            return new TokenCredential(token);
        }

        return null;
    }
}
