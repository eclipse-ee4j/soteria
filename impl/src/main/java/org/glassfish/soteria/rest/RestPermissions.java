/*
 * Copyright (c) 2026 Contributors to the Eclipse Foundation.
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
package org.glassfish.soteria.rest;

import jakarta.servlet.ServletContext;

import java.security.Permission;
import java.security.Permissions;
import java.util.HashMap;
import java.util.Map;

import static org.glassfish.soteria.Utils.isEmpty;

public final class RestPermissions {

    public static final String EXCLUDED_PERMISSIONS = "org.glassfish.soteria.rest.authorization.excludedPermissions";
    public static final String UNCHECKED_PERMISSIONS = "org.glassfish.soteria.rest.authorization.uncheckedPermissions";
    public static final String ROLE_PERMISSIONS = "org.glassfish.soteria.rest.authorization.rolePermissions";

    private RestPermissions() {
    }

    public static void addExcluded(ServletContext servletContext, Permission permission) {
        getOrCreatePermissions(servletContext, EXCLUDED_PERMISSIONS).add(permission);
    }

    public static void addUnchecked(ServletContext servletContext, Permission permission) {
        getOrCreatePermissions(servletContext, UNCHECKED_PERMISSIONS).add(permission);
    }

    public static void addToRole(ServletContext servletContext, String role, Permission permission) {
        getOrCreateRolePermissions(servletContext).computeIfAbsent(role, ignored -> new Permissions()).add(permission);
    }

    public static boolean hasPermissions(ServletContext servletContext) {
        if (servletContext == null) {
            return false;
        }

        return
            !isEmpty(getPermissions(servletContext, EXCLUDED_PERMISSIONS)) ||
            !isEmpty(getPermissions(servletContext, UNCHECKED_PERMISSIONS)) ||
            hasRolePermissions(getRolePermissions(servletContext));
    }

    public static void clear(ServletContext servletContext) {
        if (servletContext == null) {
            return;
        }

        servletContext.removeAttribute(EXCLUDED_PERMISSIONS);
        servletContext.removeAttribute(UNCHECKED_PERMISSIONS);
        servletContext.removeAttribute(ROLE_PERMISSIONS);
    }

    public static Permissions getExcluded(ServletContext servletContext) {
        return getPermissions(servletContext, EXCLUDED_PERMISSIONS);
    }

    public static Permissions getUnchecked(ServletContext servletContext) {
        return getPermissions(servletContext, UNCHECKED_PERMISSIONS);
    }

    public static Map<String, Permissions> getPerRole(ServletContext servletContext) {
        return getRolePermissions(servletContext);
    }

    private static Permissions getOrCreatePermissions(ServletContext servletContext, String name) {
        Object existing = servletContext.getAttribute(name);
        if (existing instanceof Permissions permissions) {
            return permissions;
        }

        Permissions permissions = new Permissions();
        servletContext.setAttribute(name, permissions);

        return permissions;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Permissions> getOrCreateRolePermissions(ServletContext servletContext) {
        Object existing = servletContext.getAttribute(ROLE_PERMISSIONS);
        if (existing instanceof Map<?, ?> map) {
            return (Map<String, Permissions>) map;
        }

        Map<String, Permissions> rolePermissions = new HashMap<>();
        servletContext.setAttribute(ROLE_PERMISSIONS, rolePermissions);

        return rolePermissions;
    }

    private static Permissions getPermissions(ServletContext servletContext, String name) {
        Object existing = servletContext.getAttribute(name);

        return existing instanceof Permissions permissions ? permissions : null;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Permissions> getRolePermissions(ServletContext servletContext) {
        Object existing = servletContext.getAttribute(ROLE_PERMISSIONS);

        return existing instanceof Map<?, ?> map ? (Map<String, Permissions>) map : null;
    }

    private static boolean hasRolePermissions(Map<String, Permissions> rolePermissions) {
        if (isEmpty(rolePermissions)) {
            return false;
        }

        for (Permissions permissions : rolePermissions.values()) {
            if (!isEmpty(permissions)) {
                return true;
            }
        }

        return false;
    }
}