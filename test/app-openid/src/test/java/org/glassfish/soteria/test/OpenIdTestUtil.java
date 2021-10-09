/*
 * Copyright (c) 2021 Contributors to the Eclipse Foundation
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

import com.gargoylesoftware.htmlunit.TextPage;
import com.gargoylesoftware.htmlunit.WebClient;
import org.glassfish.soteria.test.client.Callback;
import org.glassfish.soteria.test.client.GetUserName;
import org.glassfish.soteria.test.client.UnsecuredPage;
import org.glassfish.soteria.test.client.defaulttests.SecuredPage;
import org.glassfish.soteria.test.server.ApplicationConfig;
import org.glassfish.soteria.test.server.OidcProvider;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.EmptyAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.jboss.shrinkwrap.resolver.api.maven.Maven;

import javax.ws.rs.core.Response;
import java.io.IOException;
import java.net.URL;

import static org.junit.Assert.assertEquals;

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
                .addAsWebInfResource("payara-web.xml")
                .addAsWebInfResource(EmptyAsset.INSTANCE, "beans.xml");
        return war;
    }

    public static WebArchive createClientDeployment() {

        WebArchive war = ShrinkWrap
                .create(WebArchive.class, "openid-client.war")
                .addClass(Callback.class)
                .addClass(UnsecuredPage.class)
                .addClass(GetUserName.class)
                .addAsWebInfResource("payara-web.xml")
                // Always as bundled since it is a newer version!
                .addAsLibraries(Maven.resolver()
                        .loadPomFromFile("pom.xml")
                        .resolve("org.glassfish.soteria:jakarta.security.enterprise:3.0.0-SNAPSHOT")
                        .withTransitivity().asFile())
                .addAsWebInfResource(EmptyAsset.INSTANCE, "beans.xml");

        return war;
    }

    public static WebArchive createClientDefaultDeployment() {
        return createClientDeployment().addClass(SecuredPage.class);

    }

    public static void testOpenIdConnect(WebClient webClient, URL base) throws IOException {
        // unsecure page should be accessible for an unauthenticated user
        TextPage unsecuredPage = webClient.getPage(base + "Unsecured");
        assertEquals(Response.Status.OK.getStatusCode(), unsecuredPage.getWebResponse().getStatusCode());
        assertEquals("This is an unsecured web page", unsecuredPage.getContent().trim());

        // access to secured web page authenticates the user and instructs to redirect to the callback URL
        TextPage securedPage = webClient.getPage(base + "Secured");
        assertEquals(Response.Status.OK.getStatusCode(), securedPage.getWebResponse().getStatusCode());
        assertEquals(String.format("%sCallback", base.getPath()), securedPage.getUrl().getPath());

        // access secured web page as an authenticated user
        securedPage = webClient.getPage(base + "Secured");
        assertEquals(Response.Status.OK.getStatusCode(), securedPage.getWebResponse().getStatusCode());
        assertEquals("This is a secured web page", securedPage.getContent().trim());

        // finally, access should still be allowed to an unsecured web page when already logged in
        unsecuredPage = webClient.getPage(base + "Unsecured");
        assertEquals(Response.Status.OK.getStatusCode(), unsecuredPage.getWebResponse().getStatusCode());
        assertEquals("This is an unsecured web page", unsecuredPage.getContent().trim());
    }

}
