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
package org.glassfish.soteria.rest;

import jakarta.annotation.security.DenyAll;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.container.DynamicFeature;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.FeatureContext;
import jakarta.ws.rs.ext.Provider;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;

/**
 * Registers request filters for Jakarta REST based on common annotation security annotations.
 */
@Provider
public class RestAccessControlFeature implements DynamicFeature {

    @Context
    private HttpServletRequest httpRequest;

    @Context
    private HttpServletResponse httpResponse;

    @Override
    public void configure(ResourceInfo info, FeatureContext ctx) {
        final Method method = info.getResourceMethod();

        // ---- Method-level rules take precedence


        if (isAnnotatedWith(method, DenyAll.class)) {
            ctx.register(new DenyAllFilter());
            return;
        }

        if (isAnnotatedWith(method, PermitAll.class)) {
            ctx.register(new PermitAllFilter(httpRequest, httpResponse));
            return;
        }

        RolesAllowed methodRoles = method.getAnnotation(RolesAllowed.class);
        if (methodRoles != null) {
            ctx.register(new RolesAllowedFilter(httpRequest, httpResponse, methodRoles.value()));
            return;
        }


        // ---- Fallback to class-level @RolesAllowed

        RolesAllowed classRoles = info.getResourceClass().getAnnotation(RolesAllowed.class);
        if (classRoles != null) {
            ctx.register(new RolesAllowedFilter(httpRequest, httpResponse, classRoles.value()));
        }
    }

    private static boolean isAnnotatedWith(Method method, Class<?> annotationType) {
        return method.isAnnotationPresent(annotationType.asSubclass(Annotation.class));
    }
}