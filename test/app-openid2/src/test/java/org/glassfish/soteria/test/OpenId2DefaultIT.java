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
import static org.junit.Assert.assertTrue;

import java.io.IOException;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.shrinkwrap.api.Archive;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.gargoylesoftware.htmlunit.TextPage;
import com.gargoylesoftware.htmlunit.WebResponse;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlRadioButtonInput;
import com.gargoylesoftware.htmlunit.util.NameValuePair;

/**
 *
 * @author Gaurav Gupta
 * @author Rudy De Busscher
 * @author Arjan Tijms
 */
@RunWith(Arquillian.class)
public class OpenId2DefaultIT extends ArquillianBase {

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

        // Look at redirect:
        getWebClient().getOptions().setRedirectEnabled(false);

        WebResponse response = responseFromServer("/protectedServlet");

        for (NameValuePair header : response.getResponseHeaders()) {
            System.out.println("name: " + header.getName() + " : " + header.getValue());
        }

        // Automatically follow redirects and request secured page again
        getWebClient().getOptions().setRedirectEnabled(true);


        // 3. We should now see the login page from the OpenId Provider
        HtmlPage providerLoginPage = pageFromServer("/protectedServlet");

        printPage(providerLoginPage);

        // Authenticate with the OpenId Provider using the username and password for a default user
        providerLoginPage.getElementById("j_username")
                         .setAttribute("value", "user");

        providerLoginPage.getElementById("j_password")
                         .setAttribute("value", "password");


        // 4. We should now get a confirmation page, which we acknowledge.
        HtmlPage confirmationPage = providerLoginPage.getElementByName("submit")
                                                     .click();

        printPage(confirmationPage);

        // Set to "remember-not" to make tests easily repeatable. If we don't set this without restarting the OpenID Provider
        // we would not get the confirmation page next time.
        HtmlRadioButtonInput radioButton = (HtmlRadioButtonInput) confirmationPage.getElementById("remember-not");
        radioButton.setChecked(true);


        // 5. After authenticating and confirmation, we are now redirected back to our application.
        // A servlet on the /callBack URI is called.
        TextPage callbackPage = confirmationPage.getElementByName("authorize")
                                                .click();
        printPage(callbackPage);

        assertTrue(callbackPage.getContent().contains("This is the callback servlet"));


        // 6. Access protected servlet as an authenticated user
        assertAuthenticated("web", "user",
            readFromServer("/protectedServlet"), "foo", "bar");


        // 7. Finally, access should still be allowed to a public web page when already logged in
        assertAuthenticated("web", "user",
                readFromServer("/publicServlet"), "foo", "bar");
    }

}
