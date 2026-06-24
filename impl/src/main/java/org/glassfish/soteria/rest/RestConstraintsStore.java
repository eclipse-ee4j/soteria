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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.glassfish.soteria.rest.introspection.ResourceSecurityConstraintResolver.SecurityConstraint;

import static org.glassfish.soteria.utils.Utils.EMPTY_STRING;
import static org.glassfish.soteria.utils.Utils.isAnyNull;
import static org.glassfish.soteria.utils.Utils.isBlank;
import static org.glassfish.soteria.utils.Utils.isEmpty;

/**
 * This class stores authorization constraints discovered from REST resources.
 */
public final class RestConstraintsStore {

    public static final String REST_CONSTRAINTS = "org.glassfish.soteria.rest.authorization.restConstraints";

    public static record RestConstraint(
        String fullTemplatePath,
        String httpMethod,
        SecurityConstraint securityConstraint) {
    }

    private RestConstraintsStore() {
    }

    public static void addConstraint(ServletContext servletContext, String applicationBasePath, RestConstraint restConstraint) {
        if (isAnyNull(servletContext, restConstraint)) {
            return;
        }

        getOrCreateConstraints(servletContext)
                .computeIfAbsent(
                    normalizeApplicationBasePath(applicationBasePath),
                    ignored -> new ArrayList<>())
                .add(restConstraint);
    }

    public static boolean hasConstraints(ServletContext servletContext) {
        if (servletContext == null) {
            return false;
        }

        Map<String, List<RestConstraint>> constraints = getConstraints(servletContext);
        if (isEmpty(constraints)) {
            return false;
        }

        for (List<RestConstraint> applicationConstraints : constraints.values()) {
            if (!isEmpty(applicationConstraints)) {
                return true;
            }
        }

        return false;
    }

    public static Map<String, List<RestConstraint>> getConstraints(ServletContext servletContext) {
        if (servletContext == null) {
            return null;
        }

        return getConstraintsFromContext(servletContext);
    }

    public static List<RestConstraint> getConstraints(ServletContext servletContext, String applicationBasePath) {
        Map<String, List<RestConstraint>> constraints = getConstraints(servletContext);
        if (constraints == null) {
            return List.of();
        }

        List<RestConstraint> applicationConstraints = constraints.get(normalizeApplicationBasePath(applicationBasePath));

        return applicationConstraints == null ? List.of() : applicationConstraints;
    }

    public static void clear(ServletContext servletContext) {
        if (servletContext == null) {
            return;
        }

        servletContext.removeAttribute(REST_CONSTRAINTS);
    }


    // ### Private methods


    private static Map<String, List<RestConstraint>> getOrCreateConstraints(ServletContext servletContext) {
        Map<String, List<RestConstraint>> existing = getConstraintsFromContext(servletContext);
        if (existing != null) {
            return existing;
        }

        Map<String, List<RestConstraint>> constraints = new LinkedHashMap<>();
        servletContext.setAttribute(REST_CONSTRAINTS, constraints);

        return constraints;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, List<RestConstraint>> getConstraintsFromContext(ServletContext servletContext) {
        Object existing = servletContext.getAttribute(REST_CONSTRAINTS);

        return existing instanceof Map<?, ?> map ? (Map<String, List<RestConstraint>>) map : null;
    }

    private static String normalizeApplicationBasePath(String applicationBasePath) {
        return isBlank(applicationBasePath) || applicationBasePath.equals("/") ? EMPTY_STRING : applicationBasePath;
    }

}