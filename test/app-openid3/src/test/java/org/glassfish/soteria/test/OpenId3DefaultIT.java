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

import static org.glassfish.soteria.test.Assert.assertAuthenticated;
import static org.glassfish.soteria.test.Assert.assertDefaultNotAuthenticated;
import static org.glassfish.soteria.test.ShrinkWrap.mavenWar;

import java.io.IOException;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.shrinkwrap.api.Archive;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.gargoylesoftware.htmlunit.TextPage;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlRadioButtonInput;

/**
 *
 * @author Gaurav Gupta
 * @author Rudy De Busscher
 * @author Arjan Tijms
 */
@RunWith(Arquillian.class)
public class OpenId3DefaultIT extends ArquillianBase {

    @Deployment(testable = false)
    public static Archive<?> createClientDeployment() {
        return mavenWar();
    }

    @Test
    @RunAsClient
    public void testOpenIdConnect() throws IOException {

        // 1. Public servlet should be accessible for an unauthenticated user
        assertDefaultNotAuthenticated(
                readFromServer("/publicServlet"));

        // 2. Access to secured web page redirects us to OpenID Connect Provider's login page
        HtmlPage providerLoginPage = pageFromServer("/protectedServlet");

        printPage(providerLoginPage);

        // Authenticate with the OpenId Provider using the username and password for a default user
        providerLoginPage.getElementById("j_username")
                         .setAttribute("value", "user");

        providerLoginPage.getElementById("j_password")
                         .setAttribute("value", "password");


        // 3. We should now get a confirmation page, which we acknowledge.
        HtmlPage confirmationPage = providerLoginPage.getElementByName("submit")
                                                     .click();

        printPage(confirmationPage);

        // Set to "remember-not" to make tests easily repeatable. If we don't set this without restarting the OpenID Provider
        // we would not get the confirmation page next time.
        HtmlRadioButtonInput radioButton = (HtmlRadioButtonInput) confirmationPage.getElementById("remember-not");
        radioButton.setChecked(true);


        // 4. After authenticating and confirmation, we are now redirected back to our original resource
        TextPage originalPage = confirmationPage.getElementByName("authorize")
                                                .click();
        assertAuthenticated("web", "user",
                originalPage.getContent(), "foo", "bar");

        // 5. Finally, access should still be allowed to a public web page when already logged in
        assertAuthenticated("web", "user",
                readFromServer("/publicServlet"), "foo", "bar");
    }

}
