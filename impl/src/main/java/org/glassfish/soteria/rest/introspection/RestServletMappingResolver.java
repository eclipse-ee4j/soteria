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
package org.glassfish.soteria.rest.introspection;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletRegistration;
import jakarta.ws.rs.core.Application;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import static org.glassfish.soteria.utils.Utils.isBlank;

public final class RestServletMappingResolver {

    private static final String JAKARTA_REST_APPLICATION_PARAM = "jakarta.ws.rs.Application";

    private RestServletMappingResolver() {
    }

    /**
     * Discover which mappings (if any) have been defined for the REST Servlet (if any).
     *
     * <p>
     * Due to Jakarta REST's long history, we have various options here that were used throughout the
     * years and are still valid.
     *
     * <p>
     * Additionally note that the specification does not strictly require Jakarta REST to be implemented via
     * a servlet at all.
     *
     * @param application
     * @param servletConfig
     * @param servletContext
     * @return
     */
    public static List<String> resolveServletMappingsForREST(Application application, ServletConfig servletConfig, ServletContext servletContext) {
        Set<String> mappings = new LinkedHashSet<>();

        // Best source: the actual servlet currently hosting this Jakarta REST runtime.
        addMappingsFromServletConfig(mappings, servletConfig);

        if (!mappings.isEmpty()) {
            return List.copyOf(mappings);
        }

        // Fallback: Servlet 3 pluggability conventions from Jakarta REST.
        addMappingsByApplication(application, servletContext, mappings);

        return List.copyOf(mappings);
    }

    private static void addMappingsFromServletConfig(Set<String> mappings, ServletConfig servletConfig) {
        if (servletConfig == null) {
            return;
        }

        ServletContext servletContext = servletConfig.getServletContext();
        if (servletContext == null) {
            return;
        }

        String servletName = servletConfig.getServletName();
        if (isBlank(servletName)) {
            return;
        }

        ServletRegistration registration = servletContext.getServletRegistration(servletName);
        if (registration != null) {
            addSupportedMappings(mappings, registration.getMappings());
        }
    }

    private static void addMappingsByApplication(Application application, ServletContext servletContext, Set<String> mappings) {
        if (servletContext == null) {
            return;
        }

        Set<String> applicationClassNames = applicationClassNameCandidates(application);

        // Case 1: servlet name equals Application subclass FQCN.
        for (String applicationClassName : applicationClassNames) {
            ServletRegistration registration =
                servletContext.getServletRegistration(applicationClassName);

            if (registration != null) {
                addSupportedMappings(mappings, registration.getMappings());
            }
        }

        // Case 2: servlet init-param jakarta.ws.rs.Application names Application subclass.
        for (ServletRegistration registration : servletContext.getServletRegistrations().values()) {

            String configuredApplicationClassName =
                registration.getInitParameter(JAKARTA_REST_APPLICATION_PARAM);

            if (configuredApplicationClassName != null && applicationClassNames.contains(configuredApplicationClassName)) {
                addSupportedMappings(mappings, registration.getMappings());
            }
        }

        // Case 3: no Application subclass present; servlet name is jakarta.ws.rs.core.Application.
        ServletRegistration defaultApplicationRegistration =
            servletContext.getServletRegistration(Application.class.getName());

        if (defaultApplicationRegistration != null) {
            addSupportedMappings(mappings, defaultApplicationRegistration.getMappings());
        }
    }

    private static Set<String> applicationClassNameCandidates(Application application) {
        if (application == null) {
            return Set.of(Application.class.getName());
        }

        Set<String> candidates = new LinkedHashSet<>();

        Class<?> type = application.getClass();

        while (type != null
                && type != Object.class
                && Application.class.isAssignableFrom(type)) {

            candidates.add(type.getName());
            type = type.getSuperclass();
        }

        candidates.add(Application.class.getName());

        return candidates;
    }

    private static void addSupportedMappings(Set<String> target, Collection<String> mappings) {
        if (mappings == null) {
            return;
        }

        for (String mapping : mappings) {
            if (isBlank(mapping)) {
                continue;
            }

            if (!isSupportedServletMapping(mapping)) {
                throw new IllegalArgumentException(
                    "Unsupported REST servlet mapping for Jakarta Authorization staging: " + mapping);
            }

            target.add(mapping.trim());
        }
    }

    private static boolean isSupportedServletMapping(String mapping) {
        if (mapping == null) {
            return false;
        }

        String trimmed = mapping.trim();

        return
            trimmed.equals("/") ||
            trimmed.equals("/*")||
            (trimmed.endsWith("/*") && trimmed.length() > 2);
    }
}