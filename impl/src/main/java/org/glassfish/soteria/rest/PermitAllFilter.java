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
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Permits all roles to access resource
 */
@Priority(Priorities.AUTHORIZATION)
public class PermitAllFilter implements ContainerRequestFilter {

    private static Logger LOGGER = Logger.getLogger(PermitAllFilter.class.getName());

    private final HttpServletRequest httpRequest;

    public PermitAllFilter(HttpServletRequest httpRequest) {
        this.httpRequest = httpRequest;
    }

    @Override
    public void filter(ContainerRequestContext ctx) throws IOException {
        LOGGER.log(Level.FINER, () -> "Granting access because permit all to " + httpRequest.getRequestURI());
    }

}