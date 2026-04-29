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

import jakarta.annotation.security.DenyAll;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import jakarta.security.jacc.WebResourcePermission;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.container.DynamicFeature;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.Application;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.FeatureContext;
import jakarta.ws.rs.ext.Provider;

import java.lang.reflect.Method;
import java.util.List;

import static org.glassfish.soteria.rest.ResourceInfoUrlPatternHelper.findMethodAnnotation;
import static org.glassfish.soteria.rest.ResourceInfoUrlPatternHelper.httpMethod;
import static org.glassfish.soteria.rest.ResourceInfoUrlPatternHelper.toStagedUrlPatternName;
import static org.glassfish.soteria.rest.RestPermissions.addExcluded;
import static org.glassfish.soteria.rest.RestPermissions.addToRole;
import static org.glassfish.soteria.rest.RestPermissions.addUnchecked;
import static org.glassfish.soteria.rest.RestServletMappingResolver.resolveServletMappings;

@Provider
public class RestAccessControlFeature implements DynamicFeature {

    @Context
    private HttpServletRequest httpRequest;

    @Context
    private HttpServletResponse httpResponse;

    @Context
    private Application application;

    @Context
    private ServletConfig servletConfig;

    @Context
    private ServletContext servletContext;

    @Override
    public void configure(ResourceInfo info, FeatureContext context) {
        Method method = info.getResourceMethod();
        if (method == null) {
            return;
        }

        AccessRule accessRule = resolveAccessRule(info, method);
        if (accessRule == null) {
            return;
        }

        registerFilter(context, accessRule);

        String httpMethod = httpMethod(info);
        if (httpMethod == null) {
            // Sub-resource locator or otherwise no HTTP method designator.
            return;
        }

        stagePermissions(info, httpMethod, accessRule);
    }

    private AccessRule resolveAccessRule(ResourceInfo info, Method method) {
        Class<?> resourceClass = info.getResourceClass();

        // ### Check Method-level first

        if (findMethodAnnotation(method, resourceClass, DenyAll.class).isPresent()) {
            return AccessRule.denyAll();
        }

        if (findMethodAnnotation(method, resourceClass, PermitAll.class).isPresent()) {
            return AccessRule.permitAll();
        }

        RolesAllowed methodRoles =
            findMethodAnnotation(method, resourceClass, RolesAllowed.class).orElse(null);

        if (methodRoles != null) {
            return AccessRule.rolesAllowed(methodRoles.value());
        }


        // ### Check Class-level second. Deliberately direct only.

        if (resourceClass.getDeclaredAnnotation(DenyAll.class) != null) {
            return AccessRule.denyAll();
        }

        if (resourceClass.getDeclaredAnnotation(PermitAll.class) != null) {
            return AccessRule.permitAll();
        }

        RolesAllowed classRoles = resourceClass.getDeclaredAnnotation(RolesAllowed.class);
        if (classRoles != null) {
            return AccessRule.rolesAllowed(classRoles.value());
        }

        return null;
    }

    private void registerFilter(FeatureContext context, AccessRule accessRule) {
        switch (accessRule.type()) {
            case DENY_ALL:
                context.register(new DenyAllFilter());
                break;

            case PERMIT_ALL:
                context.register(new PermitAllFilter(
                    httpRequest));
                break;

            case ROLES_ALLOWED:
                context.register(new RolesAllowedFilter(
                    httpRequest,
                    httpResponse,
                    accessRule.roles()));
                break;

            default:
                throw new IllegalStateException("Unknown access rule type: " + accessRule.type());
        }
    }

    private void stagePermissions(ResourceInfo info, String httpMethod, AccessRule accessRule) {
        List<String> servletMappings = resolveServletMappings(application, servletConfig, servletContext);

        if (servletMappings.isEmpty()) {
            stagePermissionForMapping(
                info,
                null,
                httpMethod,
                accessRule);
        } else {
            for (String servletMapping : servletMappings) {
                stagePermissionForMapping(
                    info,
                    servletMapping,
                    httpMethod,
                    accessRule);
            }
        }
    }

    private void stagePermissionForMapping(ResourceInfo info, String servletMapping, String httpMethod, AccessRule accessRule) {
        String stagedUrlPatternName = toStagedUrlPatternName(
            application,
            servletMapping,
            info);

        for (String stagedHttpMethod : httpMethodsForStaging(httpMethod)) {
            WebResourcePermission permission = new WebResourcePermission(stagedUrlPatternName, stagedHttpMethod);

            switch (accessRule.type()) {
                case DENY_ALL:
                    addExcluded(servletContext, permission);
                    break;

                case PERMIT_ALL:
                    addUnchecked(servletContext, permission);
                    break;

                case ROLES_ALLOWED:
                    for (String role : accessRule.roles()) {
                        addToRole(servletContext, role, permission);
                    }
                    break;

                default:
                    throw new IllegalStateException("Unknown access rule type: " + accessRule.type());
                }
        }
    }

    /**
     * Phase-1 policy: stage exactly the HTTP method reported by Jakarta REST.
     *
     * If you later decide to model implicit HEAD for GET at the JACC pre-dispatch
     * layer, this is the place to expand GET to GET + HEAD, ideally with awareness
     * of whether an explicit @HEAD method exists for the same path.
     */
    private static List<String> httpMethodsForStaging(String httpMethod) {
        return List.of(httpMethod);
    }

    private enum AccessRuleType {
        DENY_ALL,
        PERMIT_ALL,
        ROLES_ALLOWED
    }

    private record AccessRule(
            AccessRuleType type,
            String[] roles) {

        static AccessRule denyAll() {
            return new AccessRule(AccessRuleType.DENY_ALL, new String[0]);
        }

        static AccessRule permitAll() {
            return new AccessRule(AccessRuleType.PERMIT_ALL, new String[0]);
        }

        static AccessRule rolesAllowed(String[] roles) {
            return new AccessRule(AccessRuleType.ROLES_ALLOWED, roles.clone());
        }
    }
}