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

import org.glassfish.soteria.rest.filters.DenyAllFilter;
import org.glassfish.soteria.rest.filters.PermitAllFilter;
import org.glassfish.soteria.rest.filters.RolesAllowedFilter;
import org.glassfish.soteria.rest.introspection.ResourceSecurityConstraintResolver.SecurityConstraint;

import static org.glassfish.soteria.rest.introspection.ResourceSecurityConstraintResolver.resolveSecurityConstraintForResource;

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
    public void configure(ResourceInfo resourceInfo, FeatureContext context) {
        // Check whether the REST resource is protected by a
        // DENY, PERMIT or ROLES security constraint
        SecurityConstraint securityConstraint = resolveSecurityConstraintForResource(resourceInfo.getResourceClass(), resourceInfo.getResourceMethod());
        if (securityConstraint == null) {
            return;
        }

        // Register the filters that protect our REST resources
        // according to the DENY, PERMIT and ROLES security constraints.
        switch (securityConstraint.type()) {
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
                    securityConstraint.roles()));
                break;

            default:
                throw new IllegalStateException("Unknown access rule type: " + securityConstraint.type());
        }
    }

}