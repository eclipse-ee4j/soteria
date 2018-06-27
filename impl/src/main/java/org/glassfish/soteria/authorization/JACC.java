/*
 * Copyright (c) 2015, 2018 Oracle and/or its affiliates. All rights reserved.
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

package org.glassfish.soteria.authorization;

import static java.security.Policy.getPolicy;
import static java.util.Collections.list;
import static org.glassfish.soteria.authorization.EJB.getCurrentEJBName;
import static org.glassfish.soteria.authorization.EJB.getEJBContext;

import java.security.AccessController;
import java.security.CodeSource;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Policy;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;
import java.util.HashSet;
import java.util.Set;

import javax.ejb.EJBContext;
import javax.security.auth.Subject;
import javax.security.jacc.EJBRoleRefPermission;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.security.jacc.WebResourcePermission;
import javax.security.jacc.WebRoleRefPermission;

public class JACC {

    public static Subject getSubject() {
        return getFromContext("javax.security.auth.Subject.container");
    }

    public static boolean isCallerInRole(String role) {
        
        Subject subject = getSubject();
        
        if (hasPermission(subject, new WebRoleRefPermission("", role))) {
            return true;
        }
        
        EJBContext ejbContext = getEJBContext();
        
        if (ejbContext != null) {
            
            // We're called from an EJB
            
            // To ask for the permission, get the EJB name first.
            // Unlike the Servlet container there's no automatic mapping
            // to a global ("") name.
            String ejbName = getCurrentEJBName(ejbContext);
            if (ejbName != null) {
                return hasPermission(subject, new EJBRoleRefPermission(ejbName, role));
            }
            
            // EJB name not supported for current container, fallback to going fully through
            // ejbContext
            return ejbContext.isCallerInRole(role);
        }
        
        return false;
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
        
        // Filter just the roles from all the permissions, which may include things like 
        // java.net.SocketPermission, java.io.FilePermission, and obtain the actual role names.
        return filterRoles(permissionCollection);

    }

    public static boolean hasPermission(Subject subject, Permission permission) {
        return getPolicyPrivileged().implies(fromSubject(subject), permission);
    }

    public static PermissionCollection getPermissionCollection(Subject subject) {
        // This may not be portable. According to the javadoc, "Applications are discouraged from
        // calling this method since this operation may not be supported by all policy implementations.
        // Applications should rely on the implies method to perform policy checks."
        return getPolicyPrivileged().getPermissions(fromSubject(subject));
    }

    private static Policy getPolicyPrivileged() {
        return (Policy) AccessController.doPrivileged(new PrivilegedAction<Policy>() {
            public Policy run() {
                return getPolicy();
            }
        });
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

    public static ProtectionDomain fromSubject(Subject subject) {
        Principal[] principals = subject != null ?  subject.getPrincipals().toArray(new Principal[subject.getPrincipals().size()]) : new Principal[] {};
        
        return new ProtectionDomain(
                new CodeSource(null, (Certificate[]) null),
                null, null,
                principals
        );
    }

    @SuppressWarnings("unchecked")
    public static <T> T getFromContext(String contextName) {
        try {
            T ctx = AccessController.doPrivileged(new PrivilegedExceptionAction<T>() {
                public T run() throws PolicyContextException {
                    return (T) PolicyContext.getContext(contextName);
                }
            });
            return ctx;
        } catch (PrivilegedActionException e) {
            throw new IllegalStateException(e.getCause());
        }
    }
    
    public static boolean isRolePermission(Permission permission) {
        return permission instanceof WebRoleRefPermission || permission instanceof EJBRoleRefPermission;
    }
    
  

}
