/*
 * Copyright (c) 2021, 2022 Contributors to the Eclipse Foundation
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
 */
package org.glassfish.soteria.test.client;

import java.io.IOException;

import jakarta.annotation.security.DeclareRoles;
import jakarta.security.enterprise.authentication.mechanism.http.OpenIdAuthenticationMechanismDefinition;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.HttpConstraint;
import jakarta.servlet.annotation.ServletSecurity;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * This servlet is protected by the "foo" role.
 *
 * <p>
 * Requesting this servlet when not authenticated will results in the authentication mechanism
 * redirecting us to the configured OpenID Provider.
 *
 * @author Arjan Tijms
 */
@OpenIdAuthenticationMechanismDefinition(

    // The Mitre "openid-connect-server-webapp" provider that we deploy via pom.xml
    // The OpenId authentication mechanism directs us to here when logging in.
    providerURI =  "http://localhost:8081/openid-connect-server-webapp",

    // The ID of default client provided by Mitre.
    // See openid-connect-server-webapp/WEB-INF/classes/db/hsql/clients.sql:
    //
    // INSERT INTO client_details_TEMP (client_id, client_secret, client_name, ...) VALUES
    //        ('client', 'secret', 'Test Client', ...);
    clientId =     "client",

    // The secret associated with the client ID "client"
    // See openid-connect-server-webapp/WEB-INF/classes/db/hsql/clients.sql
    clientSecret = "secret",

    // The URI that the Mitre "openid-connect-server-webapp" uses to redirect us back to after authentication.
    // Note that URI must be known to Mitre.
    // See pom.xml and openid-connect-server-webapp/WEB-INF/classes/db/hsql/clients.sql:
    //
    // INSERT INTO client_redirect_uri_TEMP (owner_id, redirect_uri) VALUES
    //        ('client', 'http://localhost:8080/openid-client/Callback'),
    //        ('client', 'http://localhost:8080/');
    redirectURI =  "${baseURL}/Callback",

    redirectToOriginalResource = true
)
@WebServlet("/protectedServlet")
@DeclareRoles({ "foo", "bar", "kaz" })
@ServletSecurity(@HttpConstraint(rolesAllowed = "foo"))
public class ProtectedServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        response.getWriter().write("This is a protected servlet \n");

        String webName = null;
        if (request.getUserPrincipal() != null) {
            webName = request.getUserPrincipal().getName();
        }

        response.getWriter().write("web username: " + webName + "\n");

        response.getWriter().write("web user has role \"foo\": " + request.isUserInRole("foo") + "\n");
        response.getWriter().write("web user has role \"bar\": " + request.isUserInRole("bar") + "\n");
        response.getWriter().write("web user has role \"kaz\": " + request.isUserInRole("kaz") + "\n");
    }

}
