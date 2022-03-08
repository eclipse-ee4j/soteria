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

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.util.Objects.requireNonNull;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.glassfish.soteria.Utils;
import org.glassfish.soteria.mechanisms.openid.domain.OpenIdConfiguration;
import org.glassfish.soteria.mechanisms.openid.domain.OpenIdNonce;
import org.glassfish.soteria.mechanisms.openid.http.HttpStorageController;

import com.nimbusds.jose.util.Base64URL;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.security.enterprise.authentication.mechanism.http.openid.OpenIdConstant;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Controller to manage nonce state and create the nonce hash.
 *
 * @author Gaurav Gupta
 * @author Rudy De Busscher
 */
@ApplicationScoped
public class NonceController {

    private static final String NONCE_KEY = "oidc.nonce";

    public void store(
            OpenIdNonce nonce,
            OpenIdConfiguration configuration,
            HttpServletRequest request,
            HttpServletResponse response) {

        HttpStorageController.getInstance(configuration, request, response)
                .store(NONCE_KEY, nonce.getValue(), null);

    }

    public OpenIdNonce get(
            OpenIdConfiguration configuration,
            HttpServletRequest request,
            HttpServletResponse response) {

        return HttpStorageController.getInstance(configuration, request, response)
                .getAsString(NONCE_KEY)
                .filter(k -> !Utils.isEmpty(k))
                .map(OpenIdNonce::new)
                .orElse(null);
    }

    public void remove(
            OpenIdConfiguration configuration,
            HttpServletRequest request,
            HttpServletResponse response) {

        HttpStorageController.getInstance(configuration, request, response)
                .remove(NONCE_KEY);
    }

    public String getNonceHash(OpenIdNonce nonce) {
        requireNonNull(nonce, "OpenId nonce value must not be null");

        String nonceHash;
        try {
            MessageDigest md = MessageDigest.getInstance(OpenIdConstant.DEFAULT_HASH_ALGORITHM);
            md.update(nonce.getValue().getBytes(US_ASCII));
            byte[] hash = md.digest();
            nonceHash = Base64URL.encode(hash).toString();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("No MessageDigest instance found with the specified algorithm for nonce hash", ex);
        }

        return nonceHash;
    }
}
