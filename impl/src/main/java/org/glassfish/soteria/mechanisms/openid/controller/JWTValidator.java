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

import static com.nimbusds.jose.jwk.source.RemoteJWKSet.DEFAULT_HTTP_SIZE_LIMIT;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.isNull;

import java.text.ParseException;
import java.util.concurrent.ConcurrentHashMap;

import org.glassfish.soteria.mechanisms.openid.domain.OpenIdConfiguration;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWEKeySelector;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.security.enterprise.identitystore.openid.OpenIdConstant;

@ApplicationScoped
public class JWTValidator {
    @Inject
    private OpenIdConfiguration configuration;

    private ConcurrentHashMap<CacheKey, JWSKeySelector> jwsCache = new ConcurrentHashMap<>();
    private ConcurrentHashMap<CacheKey, JWEKeySelector> jweCache = new ConcurrentHashMap<>();


    public JWTClaimsSet validateBearerToken(JWT token, JWTClaimsSetVerifier jwtVerifier) {
        JWTClaimsSet claimsSet;
        try {
            if (token instanceof PlainJWT) {
                PlainJWT plainToken = (PlainJWT) token;
                claimsSet = plainToken.getJWTClaimsSet();
                jwtVerifier.verify(claimsSet, null);
            } else if (token instanceof SignedJWT) {
                SignedJWT signedToken = (SignedJWT) token;
                JWSHeader header = signedToken.getHeader();
                String alg = header.getAlgorithm().getName();
                if (isNull(alg)) {
                    // set the default value
                    alg = OpenIdConstant.DEFAULT_JWT_SIGNED_ALGORITHM;
                }

                ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
                jwtProcessor.setJWSKeySelector(getJWSKeySelector(alg));
                jwtProcessor.setJWTClaimsSetVerifier(jwtVerifier);
                claimsSet = jwtProcessor.process(signedToken, null);
            } else if (token instanceof EncryptedJWT) {
                /*
                 * If ID Token is encrypted, decrypt it using the keys and
                 * algorithms
                 */
                EncryptedJWT encryptedToken = (EncryptedJWT) token;
                JWEHeader header = encryptedToken.getHeader();
                String alg = header.getAlgorithm().getName();

                ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
                jwtProcessor.setJWSKeySelector(getJWSKeySelector(alg));
                // Only JWS supported, not JWE
                jwtProcessor.setJWTClaimsSetVerifier(jwtVerifier);
                claimsSet = jwtProcessor.process(encryptedToken, null);
            } else {
                throw new IllegalStateException("Unexpected JWT type : " + token.getClass());
            }
        } catch (ParseException | BadJOSEException | JOSEException ex) {
            throw new IllegalStateException(ex);
        }

        return claimsSet;
    }

    /**
     * JWSKeySelector finds the JSON Web Key Set (JWKS) from jwks_uri endpoint
     * and filter for potential signing keys in the JWKS with a matching kid
     * property.
     *
     * @param alg the algorithm for the key
     * @return the JSON Web Signing (JWS) key selector
     */
    private JWSKeySelector<?> getJWSKeySelector(String alg) {
        return jwsCache.computeIfAbsent(createCacheKey(alg), k -> createJWSKeySelector(alg));
    }

    private CacheKey createCacheKey(String alg) {
        return new CacheKey(alg,
                configuration.getJwksConnectTimeout(),
                configuration.getJwksReadTimeout(),
                configuration.getProviderMetadata().getJwksURL(),
                configuration.getClientSecret());
    }

    private JWSKeySelector<?> createJWSKeySelector(String alg) {
        JWKSource<?> jwkSource;
        JWSAlgorithm jWSAlgorithm = new JWSAlgorithm(alg);
        if (Algorithm.NONE.equals(jWSAlgorithm)) {
            throw new IllegalStateException("Unsupported JWS algorithm : " + jWSAlgorithm);
        }

        if (JWSAlgorithm.Family.RSA.contains(jWSAlgorithm)
                || JWSAlgorithm.Family.EC.contains(jWSAlgorithm)) {
            ResourceRetriever jwkSetRetriever = new DefaultResourceRetriever(
                    configuration.getJwksConnectTimeout(),
                    configuration.getJwksReadTimeout(),
                    DEFAULT_HTTP_SIZE_LIMIT
            );
            jwkSource = new RemoteJWKSet<>(configuration.getProviderMetadata().getJwksURL(), jwkSetRetriever);
        } else if (JWSAlgorithm.Family.HMAC_SHA.contains(jWSAlgorithm)) {
            byte[] clientSecret = new String(configuration.getClientSecret()).getBytes(UTF_8);
            if (isNull(clientSecret)) {  // FIXME
                throw new IllegalStateException("Missing client secret");
            }
            jwkSource = new ImmutableSecret<>(clientSecret);
        } else {
            throw new IllegalStateException("Unsupported JWS algorithm : " + jWSAlgorithm);
        }

        return new JWSVerificationKeySelector<>(jWSAlgorithm, jwkSource);
    }

}
