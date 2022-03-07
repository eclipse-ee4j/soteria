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

import static jakarta.ws.rs.core.Response.Status.NOT_FOUND;
import static org.glassfish.soteria.test.client.defaulttests.OpenIdConfig.OPEN_ID_CONFIG_PROPERTIES;
import static org.glassfish.soteria.test.client.defaulttests.OpenIdConfig.REDIRECT_URI;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.URL;

import org.glassfish.soteria.test.client.defaulttests.OpenIdConfig;
import org.glassfish.soteria.test.client.defaulttests.SecuredServletWithEL;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.OperateOnDeployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.WebClient;

/**
 * @author Gaurav Gupta
 * @author Rudy De Busscher
 */

@RunWith(Arquillian.class)
public class InvalidRedirectURIIT {

    private WebClient webClient;

    @OperateOnDeployment("openid-client")
    @ArquillianResource
    private URL base;

    @Before
    public void init() {
        webClient = new WebClient();
    }

    @Deployment(name = "openid-server", testable = false)
    public static Archive<?> createServerDeployment() {
        return OpenIdTestUtil.createServerDeployment();
    }

    @Deployment(name = "openid-client", testable = false)
    public static Archive<?> createClientDeployment() {
        StringAsset config = new StringAsset(REDIRECT_URI + "=invalid_callback");
        WebArchive war = OpenIdTestUtil.createClientDeployment(SecuredServletWithEL.class, OpenIdConfig.class)
                .addAsWebInfResource(config, "classes" + OPEN_ID_CONFIG_PROPERTIES);
        System.out.println(war.toString(true));
        return war;
    }

    @Test
    @RunAsClient
    public void testOpenIdConnect() throws IOException {
        try {
            webClient.getPage(base + "Secured");
            fail("redirect uri is valid");
        } catch (FailingHttpStatusCodeException ex) {
            assertEquals(NOT_FOUND.getStatusCode(), ex.getStatusCode());
        }
    }

}
