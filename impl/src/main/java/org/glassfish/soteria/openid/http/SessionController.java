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
package org.glassfish.soteria.openid.http;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import java.util.Optional;

/**
 * @author Gaurav Gupta
 * @author Rudy De Busscher
 */
public class SessionController implements HttpStorageController {

    private final HttpServletRequest request;

    public SessionController(HttpServletRequest request) {
        this.request = request;
    }

    @Override
    public void store(String name, String value, Integer maxAge) {
        HttpSession session = request.getSession();
        session.setAttribute(name, value);
    }

    @Override
    public Optional<Object> get(String name) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            return Optional.ofNullable(session.getAttribute(name));
        } else {
            return Optional.empty();
        }
    }

    @Override
    public Optional<String> getAsString(String name) {
        return get(name).map(Object::toString);
    }

    @Override
    public void remove(String name) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.removeAttribute(name);
        }
    }

}
