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

import jakarta.annotation.Priority;
import jakarta.enterprise.inject.spi.CDI;
import jakarta.security.enterprise.AuthenticationStatus;
import jakarta.security.enterprise.SecurityContext;
import jakarta.security.enterprise.authentication.mechanism.http.AuthenticationParameters;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.Response;

import java.io.IOException;
import java.util.Arrays;

import static jakarta.security.enterprise.AuthenticationStatus.NOT_DONE;
import static jakarta.security.enterprise.AuthenticationStatus.SEND_FAILURE;
import static jakarta.security.enterprise.AuthenticationStatus.SUCCESS;
import static org.glassfish.soteria.Utils.isOneOf;

/**
 * Enforces access to Jakarta REST resources based on allowed roles (or permits all).
 */
@Priority(Priorities.AUTHORIZATION)
public class RolesAllowedFilter implements ContainerRequestFilter {

    private final SecurityContext security;
    private final String[] allowed;

    private final HttpServletRequest httpRequest;
    private final HttpServletResponse httpResponse;

    public RolesAllowedFilter(HttpServletRequest req, HttpServletResponse resp, String[] allowed) {
        this.httpRequest = req;
        this.httpResponse = resp;
        this.allowed = allowed;
        this.security = CDI.current().select(SecurityContext.class).get();
    }

    @Override
    public void filter(ContainerRequestContext ctx) throws IOException {
        // If there are roles configured and the caller isn't yet authenticated, try to authenticate
        if (allowed.length > 0 && !isAuthenticated()) {
            AuthenticationStatus status =
                    security.authenticate(httpRequest, httpResponse, AuthenticationParameters.withParams());

            // No credentials or failed authentication
            if (isOneOf(NOT_DONE, SEND_FAILURE)) {
                throw unauthorized("Authentication resulted in " + status);
            }

            // Auth reported success but caller principal is missing (compat safeguard)
            if (status == SUCCESS && !isAuthenticated()) {
                throw unauthorized("Authentication not done");
            }
        }

        Arrays.stream(allowed)
              .filter(role -> ctx.getSecurityContext().isUserInRole(role))
              .findAny()
              .orElseThrow(() -> new ForbiddenException("Caller not in requested role"));
    }

    private boolean isAuthenticated() {
        return security.getCallerPrincipal() != null;
    }

    private static NotAuthorizedException unauthorized(String message) {
        return new NotAuthorizedException(
                message, Response.status(Response.Status.UNAUTHORIZED).build());
    }
}