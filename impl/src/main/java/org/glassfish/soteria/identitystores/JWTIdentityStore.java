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
package org.glassfish.soteria.identitystores;

import jakarta.security.enterprise.identitystore.CredentialValidationResult;
import jakarta.security.enterprise.identitystore.IdentityStore;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

import org.glassfish.soteria.TokenCredential;
import org.glassfish.soteria.identitystores.jwt.JWTConfiguration;
import org.glassfish.soteria.identitystores.jwt.JsonWebTokenImpl;
import org.glassfish.soteria.identitystores.jwt.keystore.PrivateKeyStore;
import org.glassfish.soteria.identitystores.jwt.keystore.PublicKeyStore;
import org.glassfish.soteria.identitystores.jwt.token.JwtTokenParser;

import static jakarta.security.enterprise.identitystore.CredentialValidationResult.INVALID_RESULT;
import static java.util.logging.Level.INFO;

/**
 * @author Arjan Tijms
 */
public class JWTIdentityStore implements IdentityStore {

    private static final Logger LOGGER = Logger.getLogger(JWTIdentityStore.class.getName());

    private final JWTConfiguration jwtConfiguration;

    private final PublicKeyStore publicKeyStore;
    private final PrivateKeyStore privateKeyStore;

    public JWTIdentityStore(JWTConfiguration jwtConfiguration) {
        this.jwtConfiguration = jwtConfiguration;

        publicKeyStore = new PublicKeyStore(jwtConfiguration.keyCacheTTL(), jwtConfiguration.publicKey(), jwtConfiguration.publicKeyLocation());
        privateKeyStore = new PrivateKeyStore(jwtConfiguration.keyCacheTTL(), jwtConfiguration.decryptKeyLocation());
    }

    public CredentialValidationResult validate(TokenCredential signedJWTCredential) {
        JwtTokenParser jwtTokenParser =
                new JwtTokenParser(
                    jwtConfiguration.enabledNamespace(),
                    jwtConfiguration.customNamespace(),
                    jwtConfiguration.disableTypeVerification());

        try {
            JsonWebTokenImpl jsonWebToken =
                jwtTokenParser.parse(
                    signedJWTCredential.getSignedJWT(),
                    jwtConfiguration.isEncryptionRequired(),
                    publicKeyStore,
                    jwtConfiguration.acceptedIssuer(),
                    privateKeyStore,
                    jwtConfiguration.tokenAge(),
                    jwtConfiguration.clockSkew(),
                    jwtConfiguration.keyAlgorithm());

            Set<String> recipientsOfThisJWT = jsonWebToken.claimSet("aud");

            Boolean recipientInAudience =
                jwtConfiguration.allowedAudience().isEmpty() ||
                jwtConfiguration.allowedAudience()
                                .stream()
                                .anyMatch(a -> recipientsOfThisJWT != null && recipientsOfThisJWT.contains(a));

            if (!recipientInAudience) {
                throw new Exception("The supplied audience " + recipientsOfThisJWT + " is not a part of target audience.");
            }

            Set<String> groups = new HashSet<>();
            Collection<String> groupClaims = jsonWebToken.claimSet("groups");
            if (groupClaims != null) {
                groups.addAll(groupClaims);
            }

            return new CredentialValidationResult(jsonWebToken, groups);

        } catch (Exception e) {
            LOGGER.log(INFO, "Exception parsing JWT token.", e);
        }

        return INVALID_RESULT;
    }



}