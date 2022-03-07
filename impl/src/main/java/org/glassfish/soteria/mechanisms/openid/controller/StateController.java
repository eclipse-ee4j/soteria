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


import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.glassfish.soteria.Utils;
import org.glassfish.soteria.mechanisms.openid.OpenIdState;
import org.glassfish.soteria.mechanisms.openid.domain.OpenIdConfiguration;
import org.glassfish.soteria.mechanisms.openid.http.HttpStorageController;

import java.util.Optional;

/**
 * Controller to manage OpenId state parameter value and request being validated
 *
 * @author Gaurav Gupta
 * @author Rudy De Busscher
 */
@ApplicationScoped
public class StateController {

    private static final String STATE_KEY = "oidc.state";

    @Inject
    private OpenIdConfiguration configuration;

    public void store(
            OpenIdState state,
            OpenIdConfiguration configuration,
            HttpServletRequest request,
            HttpServletResponse response) {

        HttpStorageController storage = HttpStorageController.getInstance(configuration, request, response);

        storage.store(STATE_KEY, state.getValue(), null);
    }

    public Optional<OpenIdState> get(
            HttpServletRequest request,
            HttpServletResponse response) {

        return HttpStorageController.getInstance(configuration, request, response)
                .getAsString(STATE_KEY)
                .filter(k -> !Utils.isEmpty(k))
                .map(OpenIdState::new);
    }

    public void remove(
            HttpServletRequest request,
            HttpServletResponse response) {

        HttpStorageController.getInstance(configuration, request, response)
                .remove(STATE_KEY);
    }
}
