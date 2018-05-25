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

package org.glassfish.soteria.test;

import static javax.security.enterprise.authentication.mechanism.http.AuthenticationParameters.withParams;

import java.io.IOException;

import javax.annotation.security.DeclareRoles;
import javax.inject.Inject;
import javax.security.enterprise.SecurityContext;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;

/**
 * Test Servlet that authenticates that authenticates the request and returns
 * the class name of the caller principal from an EJB
 *
 */
@DeclareRoles("admin")
@WebServlet("/ejb-servlet")
public class EjbServlet extends HttpServlet {

    @Inject
    private SecurityContext securityContext;

    @Inject
    private Ejb ejb;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        securityContext.authenticate(request, response, withParams());

        response.getWriter().write(ejb.getPrincipal().getClass().getName()+",");

        Principal applicationPrincipal;
        if (request.getParameter("useCallerPrincipal") != null) {
            applicationPrincipal=ejb.getPrincipalsByType(CustomCallerPrincipal.class).toArray(new CustomCallerPrincipal[0])[0];
        } else {
            applicationPrincipal=ejb.getPrincipalsByType(CustomPrincipal.class).toArray(new CustomPrincipal[0])[0];
        }
        response.getWriter().write(applicationPrincipal.getClass().getName());
    }

}
