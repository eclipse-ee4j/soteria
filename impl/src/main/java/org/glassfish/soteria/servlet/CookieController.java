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

import static java.util.Objects.nonNull;

import java.util.Optional;

import org.glassfish.soteria.Utils;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 *
 * @author Gaurav Gupta
 * @author Rudy De Busscher
 * @author Arjan Tijms
 */
public class CookieController implements HttpStorageController {

    private final HttpServletRequest request;
    private final HttpServletResponse response;

    public CookieController(HttpServletRequest request, HttpServletResponse response) {
        this.request = request;
        this.response = response;
    }

    @Override
    public HttpStorageController store(String name, String value, Integer maxAge) {
        Cookie cookie = new Cookie(name, value);
        if (maxAge != null) {
            cookie.setMaxAge(maxAge);
        }
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        String contextPath = request.getContextPath();
        cookie.setPath(Utils.isEmpty(contextPath) ? "/" : contextPath);

        response.addCookie(cookie);

        return this;
    }

    @Override
    public Optional<Cookie> get(String name) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (name.equals(cookie.getName())
                        && nonNull(cookie.getValue())
                        && !cookie.getValue().trim().isEmpty()) {
                    return Optional.of(cookie);
                }
            }
        }
        return Optional.empty();
    }

    @Override
    public Optional<String> getAsString(String name) {
        return get(name).map(Cookie::getValue);
    }

    @Override
    public void remove(String name) {
        store(name, null, 0);
    }

}
