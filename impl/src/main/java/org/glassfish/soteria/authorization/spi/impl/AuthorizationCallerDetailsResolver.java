/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
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
package org.glassfish.soteria.authorization.spi.impl;

import java.security.Principal;
import java.util.Set;

import javax.security.auth.Subject;

import org.glassfish.soteria.DefaultService;
import org.glassfish.soteria.authorization.spi.CallerDetailsResolver;

public class AuthorizationCallerDetailsResolver implements CallerDetailsResolver, DefaultService {

    @Override
    public Principal getCallerPrincipal() {
        return Authorization.getCallerPrincipal();
    }

    @Override
    public <T extends Principal> Set<T> getPrincipalsByType(Class<T> pType) {
        Subject subject = Authorization.getSubject();

        if (subject == null) {
            // Ensure behavior exactly matches that of Subject
            // when returning an empty Set, and when pType == null.
            subject = new Subject();
        }
        return subject.getPrincipals(pType);
    }

    @Override
    public boolean isCallerInRole(String role) {
        return Authorization.isCallerInRole(role);
    }

    @Override
    public Set<String> getAllDeclaredCallerRoles() {
        return Authorization.getAllDeclaredCallerRoles();
    }

}
