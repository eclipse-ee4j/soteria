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

package org.glassfish.soteria.authorization.spi.impl;

import jakarta.ejb.EJBContext;
import jakarta.security.jacc.EJBRoleRefPermission;
import jakarta.security.jacc.Policy;
import jakarta.security.jacc.PolicyContext;
import jakarta.security.jacc.PolicyFactory;
import jakarta.security.jacc.PrincipalMapper;
import jakarta.security.jacc.WebResourcePermission;
import jakarta.security.jacc.WebRoleRefPermission;

import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

import javax.security.auth.Subject;

import static jakarta.security.jacc.PolicyContext.PRINCIPAL_MAPPER;
import static jakarta.security.jacc.PolicyContext.SUBJECT;
import static java.util.Collections.list;
import static org.glassfish.soteria.authorization.EJB.getCurrentEJBName;
import static org.glassfish.soteria.authorization.EJB.getEJBContext;

class Authorization {

    public static Subject getSubject() {
        return getFromContext(SUBJECT);
    }

    public static Principal getCallerPrincipal() {
        Subject subject = getSubject();
        if (subject == null) {
            return null;
        }

        PrincipalMapper mapper = getFromContext(PRINCIPAL_MAPPER);

        return mapper.getCallerPrincipal(subject);
    }

    public static boolean isCallerInRole(String role) {
        Subject subject = getSubject();

        if (hasPermission(subject, new WebRoleRefPermission("", role))) {
            return true;
        }

        EJBContext ejbContext = getEJBContext();
        if (ejbContext == null) {
            return false;
        }

        // We're called from an EJB

        // To ask for the permission, get the EJB name first.
        // Unlike the Servlet container there's no automatic mapping
        // to a global ("") name.
        String ejbName = getCurrentEJBName(ejbContext);
        if (ejbName != null) {
            return hasPermission(subject, new EJBRoleRefPermission(ejbName, role));
        }

        // EJB name not supported for current container, fallback to going fully through
        // ejbContext.
        //
        // Note; When backed by Jakarta Authorization this should result result into
        //       a check for EJBRoleRefPermission(beanName, role) as well, with
        //       mostly the difference with the code above being that the bean name is stored
        //       in the EJB context internally.
        return ejbContext.isCallerInRole(role);
    }

    public static boolean hasAccessToWebResource(String resource, String... methods) {
        return hasPermission(getSubject(), new WebResourcePermission(resource, methods));
    }

    public static Set<String> getAllDeclaredCallerRoles() {
        // Get the permissions associated with the Subject we obtained
        PermissionCollection permissionCollection = getPermissionCollection(getSubject());

        // Resolve any potentially unresolved role permissions
        permissionCollection.implies(new WebRoleRefPermission("", "nothing"));
        permissionCollection.implies(new EJBRoleRefPermission("", "nothing"));

        // Filter just the roles from all the permissions, and obtain the actual role names.
        return filterRoles(permissionCollection);

    }

    public static boolean hasPermission(Subject subject, Permission permission) {
        return getPolicy().implies(permission, subject);
    }

    public static PermissionCollection getPermissionCollection(Subject subject) {
        // This may not be portable. According to the javadoc, "Applications are discouraged from
        // calling this method since this operation may not be supported by all policy implementations.
        // Applications should rely on the implies method to perform policy checks."
        return getPolicy().getPermissionCollection(subject);
    }

    private static Policy getPolicy() {
        return PolicyFactory.getPolicyFactory().getPolicy();
    }

    public static Set<String> filterRoles(PermissionCollection permissionCollection) {
        Set<String> roles = new HashSet<>();
        for (Permission permission : list(permissionCollection.elements())) {
            if (isRolePermission(permission)) {
                String role = permission.getActions();

                // Note that the WebRoleRefPermission is given for every Servlet in the application, even when
                // no role refs are used anywhere. This will also include Servlets like the default servlet and the
                // implicit JSP servlet. So if there are 2 application roles, and 3 application servlets, then
                // at least 6 WebRoleRefPermission elements will be present in the collection.
                if (!roles.contains(role) && isCallerInRole(role)) {
                    roles.add(role);
                }
            }
        }

        return roles;
    }

    public static <T> T getFromContext(String contextName) {
        return PolicyContext.get(contextName);
    }

    public static boolean isRolePermission(Permission permission) {
        return permission instanceof WebRoleRefPermission || permission instanceof EJBRoleRefPermission;
    }

}
