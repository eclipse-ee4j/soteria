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
 *
 * Contributors:
 *   2021 : Payara Foundation and/or its affiliates
 */
package org.glassfish.soteria.test;

import static jakarta.ws.rs.core.Response.Status.OK;
import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.net.URL;

import org.glassfish.soteria.test.client.CallbackServlet;
import org.glassfish.soteria.test.client.UnsecuredServlet;
import org.glassfish.soteria.test.client.UserNameServlet;
import org.glassfish.soteria.test.server.ApplicationConfig;
import org.glassfish.soteria.test.server.OidcProvider;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;

import com.gargoylesoftware.htmlunit.TextPage;
import com.gargoylesoftware.htmlunit.WebClient;

/**
 * @author Gaurav Gupta
 * @author Jonathan
 * @author Rudy De Busscher
 */
public class OpenIdTestUtil {

    public static WebArchive createServerDeployment() {
        WebArchive war = ShrinkWrap
                .create(WebArchive.class, "openid-server.war")
                .addClass(OidcProvider.class)
                .addClass(ApplicationConfig.class)
                .addAsResource("openid-configuration.json")
                .addAsWebInfResource("beans.xml");

        return war;
    }

    public static WebArchive createClientDeployment(Class<?>... additionalClasses) {
        WebArchive war = ShrinkWrap
                .create(WebArchive.class, "openid-client.war")
                .addClass(CallbackServlet.class)
                .addClass(UnsecuredServlet.class)
                .addClass(UserNameServlet.class)
                .addClasses(additionalClasses)
                .addAsWebInfResource("beans.xml");

        return war;
    }

    public static void testOpenIdConnect(WebClient webClient, URL base) throws IOException {
        // Unsecure page should be accessible for an unauthenticated user
        TextPage unsecuredPage = webClient.getPage(base + "Unsecured");
        assertEquals(OK.getStatusCode(), unsecuredPage.getWebResponse().getStatusCode());
        assertEquals("This is an unsecured web page", unsecuredPage.getContent().trim());

        // Access to secured web page authenticates the user and instructs to redirect to the callback URL
        TextPage securedPage = webClient.getPage(base + "Secured");
        assertEquals(OK.getStatusCode(), securedPage.getWebResponse().getStatusCode());
        assertEquals(String.format("%sCallback", base.getPath()), securedPage.getUrl().getPath());

        // Access secured web page as an authenticated user
        securedPage = webClient.getPage(base + "Secured");
        assertEquals(OK.getStatusCode(), securedPage.getWebResponse().getStatusCode());
        assertEquals("This is a secured web page", securedPage.getContent().trim());

        //Finally, access should still be allowed to an unsecured web page when already logged in
        unsecuredPage = webClient.getPage(base + "Unsecured");
        assertEquals(OK.getStatusCode(), unsecuredPage.getWebResponse().getStatusCode());
        assertEquals("This is an unsecured web page", unsecuredPage.getContent().trim());
    }

}
