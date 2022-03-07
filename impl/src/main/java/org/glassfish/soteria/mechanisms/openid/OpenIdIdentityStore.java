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
package org.glassfish.soteria.mechanisms.openid;

import static java.util.Collections.emptySet;
import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;
import static java.util.logging.Level.FINE;
import static java.util.logging.Level.FINER;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

import org.glassfish.soteria.mechanisms.openid.controller.TokenController;
import org.glassfish.soteria.mechanisms.openid.domain.AccessTokenImpl;
import org.glassfish.soteria.mechanisms.openid.domain.IdentityTokenImpl;
import org.glassfish.soteria.mechanisms.openid.domain.OpenIdConfiguration;
import org.glassfish.soteria.mechanisms.openid.domain.OpenIdContextImpl;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jwt.JWTClaimsSet;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import jakarta.security.enterprise.credential.Credential;
import jakarta.security.enterprise.identitystore.CredentialValidationResult;
import jakarta.security.enterprise.identitystore.IdentityStore;

/**
 * Identity store validates the identity token and access token and returns the
 * validation result with the caller name and groups.
 *
 * @author Gaurav Gupta
 * @author Rudy De Busscher
 */
@ApplicationScoped
public class OpenIdIdentityStore implements IdentityStore {

    private static final Logger LOGGER = Logger.getLogger(OpenIdIdentityStore.class.getName());

    @Inject
    private OpenIdContextImpl context;

    @Inject
    private TokenController tokenController;

    @Inject
    private OpenIdConfiguration configuration;

    @SuppressWarnings("unused") // IdentityStore calls overloads
    public CredentialValidationResult validate(OpenIdCredential credential) {
        HttpMessageContext httpContext = credential.getHttpContext();
        IdentityTokenImpl idToken = credential.getIdentityTokenImpl();

        Algorithm idTokenAlgorithm = idToken.getTokenJWT().getHeader().getAlgorithm();

        JWTClaimsSet idTokenClaims;
        if (isNull(context.getIdentityToken())) {
            idTokenClaims = tokenController.validateIdToken(idToken, httpContext);
        } else {
            // If an ID Token is returned as a result of a token refresh request
            idTokenClaims = tokenController.validateRefreshedIdToken(context.getIdentityToken(), idToken);
        }
        context.setIdentityToken(idToken.withClaims(idTokenClaims));

        AccessTokenImpl accessToken = (AccessTokenImpl) credential.getAccessToken();
        if (nonNull(accessToken)) {
            tokenController.validateAccessToken(
                    accessToken, idTokenAlgorithm, context.getIdentityToken().getClaims()
            );
            context.setAccessToken(accessToken);
        }

        String callerName = getCallerName();
        context.setCallerName(callerName);
        Set<String> callerGroups = getCallerGroups();
        context.setCallerGroups(callerGroups);

        if (LOGGER.isLoggable(FINE)) {
            LOGGER.log(FINE, "Setting caller groups into the OpenID context: " + callerGroups);
            if (LOGGER.isLoggable(FINER)) {
                LOGGER.log(FINER, "Setting caller name into the OpenID context: " + callerName);
            }
        }

        return new CredentialValidationResult(
                context.getCallerName(),
                context.getCallerGroups()
        );
    }

    @Override
    public CredentialValidationResult validate(Credential credential) {
        if (credential instanceof OpenIdCredential) {
            return validate((OpenIdCredential) credential);
        }

        return CredentialValidationResult.NOT_VALIDATED_RESULT;
    }

    private String getCallerName() {
        String callerNameClaim = configuration.getClaimsConfiguration().getCallerNameClaim();

        String callerName =  context.getIdentityToken().getJwtClaims().getStringClaim(callerNameClaim).orElse(null);
        if (callerName == null) {
            callerName = context.getAccessToken().getJwtClaims().getStringClaim(callerNameClaim).orElse(null);
        }
        if (callerName == null) {
            callerName = context.getClaims().getStringClaim(callerNameClaim).orElse(null);
        }
        if (callerName == null) {
            callerName = context.getSubject();
        }

        return callerName;
    }

    private Set<String> getCallerGroups() {
        String callerGroupsClaim = configuration.getClaimsConfiguration().getCallerGroupsClaim();

        // Try CallerGroups from AccessToken
        List<String> groupsAccessClaim = context.getAccessToken().getJwtClaims().getArrayStringClaim(callerGroupsClaim);
        if (!groupsAccessClaim.isEmpty()) {
            return new HashSet<>(groupsAccessClaim);
        }

        // Try CallerGroups from IdentityToken
        List<String> groupsIdentityClaim = context.getIdentityToken().getJwtClaims().getArrayStringClaim(callerGroupsClaim);
        if (!groupsIdentityClaim.isEmpty()) {
            return new HashSet<>(groupsIdentityClaim);
        }

        // Try CallerGroups from info returned by /userinfo endpoint.
        List<String> groupsUserinfoClaim = context.getClaims().getArrayStringClaim(callerGroupsClaim);
        if (!groupsUserinfoClaim.isEmpty()) {
            return new HashSet<>(groupsUserinfoClaim);
        }

        // No luck, just empty set.
        return emptySet();
    }

}
