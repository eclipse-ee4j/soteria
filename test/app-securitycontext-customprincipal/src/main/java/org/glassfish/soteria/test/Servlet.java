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

package org.glassfish.soteria.test;

import static jakarta.security.enterprise.authentication.mechanism.http.AuthenticationParameters.withParams;

import java.io.IOException;

import jakarta.annotation.security.DeclareRoles;
import jakarta.inject.Inject;
import jakarta.security.enterprise.SecurityContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.security.Principal;

/**
 * Test Servlet that authenticates that authenticates the request and returns
 * the class name of the caller principal
 */
@DeclareRoles("admin")
@WebServlet("/servlet")
public class Servlet extends HttpServlet {
    
    private static final long serialVersionUID = 1L;

    @Inject
    private SecurityContext securityContext;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        securityContext.authenticate(request, response, withParams());

        response.getWriter().write(securityContext.getCallerPrincipal().getClass().getName()+",");
        Principal applicationPrincipal;
        if (request.getParameter("useCallerPrincipal") != null) {
            applicationPrincipal=securityContext.getPrincipalsByType(CustomCallerPrincipal.class).toArray(new CustomCallerPrincipal[0])[0];
        } else {
            applicationPrincipal=securityContext.getPrincipalsByType(CustomPrincipal.class).toArray(new CustomPrincipal[0])[0];
        }
        response.getWriter().write(applicationPrincipal.getClass().getName());
    }

}
