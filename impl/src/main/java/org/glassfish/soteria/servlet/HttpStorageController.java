/*
 * Copyright (c) 2021, 2022 Contributors to the Eclipse Foundation
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
package org.glassfish.soteria.servlet;

import java.util.Optional;

import org.glassfish.soteria.mechanisms.openid.domain.OpenIdConfiguration;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 *
 * @author Gaurav Gupta
 * @author Rudy De Busscher
 * @author Arjan Tijms
 */
public interface HttpStorageController {

    /**
     * Factory method to retrieve the configured {@link HttpStorageController}.
     * @param configuration
     * @param request
     * @param response
     * @return
     */
    static HttpStorageController getInstance(OpenIdConfiguration configuration, HttpServletRequest request, HttpServletResponse response) {
        HttpStorageController controller;

        if (configuration.isUseSession()) {
            controller = new SessionController(request);
        } else {
            controller = new CookieController(request, response);
        }

        return controller;
    }

    default HttpStorageController store(String name, String value) {
        return store(name, value, null);
    }

    HttpStorageController store(String name, String value, Integer maxAge);

    <T> Optional<T> get(String name);

    Optional<String> getAsString(String name);

    void remove(String name);

}
