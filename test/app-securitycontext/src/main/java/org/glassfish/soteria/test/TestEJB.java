/*
 * Copyright (c) 2015, 2020 Oracle and/or its affiliates. All rights reserved.
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

package org.glassfish.soteria.test;

import static java.util.Collections.singleton;
import static org.glassfish.soteria.test.Utils.getELProcessor;

import java.security.Principal;
import java.util.Set;

import jakarta.annotation.Resource;
import jakarta.annotation.security.DeclareRoles;
import jakarta.annotation.security.PermitAll;
import jakarta.ejb.EJBContext;
import jakarta.ejb.Stateless;
import jakarta.inject.Inject;
import jakarta.security.enterprise.SecurityContext;


@Stateless
// Required by GlassFish and Payara
@DeclareRoles({ "foo", "bar", "kaz" })
// JBoss EAP 6.1+ (WildFly 7+) defaults unchecked methods to DenyAll
@PermitAll
public class TestEJB {

    @Inject
    private SecurityContext securityContext;

    @Resource
    private EJBContext ejbContext;

    public Principal getUserPrincipalFromEJBContext() {
        try {
            return ejbContext.getCallerPrincipal();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public boolean isCallerInRoleFromEJBContext(String role) {
        try {
            return ejbContext.isCallerInRole(role);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public Principal getUserPrincipalFromSecContext() {
        return securityContext.getCallerPrincipal();
    }

    public boolean isCallerInRoleFromSecContext(String role) {
        return securityContext.isCallerInRole(role);
    }

    @SuppressWarnings("unchecked")
    public Set<String> getAllDeclaredCallerRoles() {
        // Note: uses reflection to avoid adding server specific classes
        if (securityContext.getClass().getName().equals("org.glassfish.soteria.SecurityContextImpl")) {
            return (Set<String>) getELProcessor("securityContext", securityContext).eval("securityContext.allDeclaredCallerRoles");
        }
        
        return singleton("* getAllDeclaredCallerRoles only supported on RI *");
    }

}
