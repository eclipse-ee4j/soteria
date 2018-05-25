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

import static java.lang.System.getProperty;
import static org.glassfish.soteria.test.Assert.assertDefaultAuthenticated;
import static org.glassfish.soteria.test.Assert.assertDefaultNotAuthenticated;
import static org.glassfish.soteria.test.ShrinkWrap.mavenWar;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeFalse;

import java.io.IOException;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.EmptyAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.gargoylesoftware.htmlunit.Page;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;


@RunWith(Arquillian.class)
public class AppMemCustomFormIT extends ArquillianBase {
    
    // Disabled for Liberty since as of version 16.0.0.3 / 2016.9 it doesn't
    // support request.authenticate(), which is essential for the custom form
    @Deployment(testable = false)
    public static Archive<?> createDeployment() {
        if ("liberty".equals(getProperty("arquillian.server"))) {
            return ShrinkWrap.create(WebArchive.class, "test.war")
                             .addAsWebInfResource(EmptyAsset.INSTANCE, "beans.xml");
        }
        return mavenWar();
    }

    @Before
    public void checkEnabled() {
        assumeFalse("liberty".equals(getProperty("arquillian.server")));
    }

    @Test
    public void testAuthenticated() throws IOException {
        
        
        // 1. Initially request protected page when we're not authenticated
        
        Page loginPage = pageFromServer("/servlet");
        
        
        // 2. Server should forward to login page
        
        assertTrue(
            "The login page should have been displayed, but was not",
            loginPage.getWebResponse().getContentAsString().contains("Login to continue")
        );
        
        
        // 3. Submit the form on the login page with the correct credentials
        
        HtmlForm form = ((HtmlPage) loginPage).getForms().get(0);
        
        form.getInputByName("form:username")
            .setValueAttribute("reza");
        
        form.getInputByName("form:password")
            .setValueAttribute("secret1");
        
        HtmlPage page = form.getInputByValue("Login")
                            .click();
        
        // Has to be authenticted now
        assertDefaultAuthenticated(
            page.getWebResponse()
                .getContentAsString());
        
        
        // 4. Request page again. FORM is stateful (http session bound) so
        // still has to be authenticated.
        
        page = pageFromServer("/servlet");
        
        assertDefaultAuthenticated(
            page.getWebResponse()
                .getContentAsString());
        
        
        // 5. Logout
        
        page = page.getForms()
                   .get(0)
                   .getInputByValue("Logout")
                   .click();
        
        // Has to be logged out now (page will still be rendered, but with 
        // web username null and no roles.
        
        assertDefaultNotAuthenticated(
            page.getWebResponse()
                .getContentAsString());
        
        
        
        // 6. Request page again. Should still be logged out
        // (and will display login to continue again now)
        
        assertDefaultNotAuthenticated(
            readFromServer("/servlet"));
        
    }
    
    @Test
    public void testNotAuthenticatedWrongName() throws IOException {
        
        // 1. Initially request protected page when we're not authenticated
        
        HtmlPage loginPage = pageFromServer("/servlet");
        
        
        // 2. Server should forward to login page
        
        assertTrue(
            "The login page should have been displayed, but was not",
            loginPage.getWebResponse().getContentAsString().contains("Login to continue")
        );
        
        
        // 3. Submit the form on the login page with the wrong credentials
        
        HtmlForm form = loginPage.getForms().get(0);
        
        form.getInputByName("form:username")
            .setValueAttribute("romo");
        
        form.getInputByName("form:password")
            .setValueAttribute("secret1");
        
        HtmlPage page = form.getInputByValue("Login")
                            .click();
        
        assertTrue(
            "An error message should be displayed, but was not",
            page.getWebResponse().getContentAsString().contains("Authentication failed")
        );
        
        // Should not be authenticted now
        assertDefaultNotAuthenticated(
            page.getWebResponse()
                .getContentAsString());
        
    }
    
    @Test
    public void testNotAuthenticatedWrongPassword() throws IOException {
        
        // 1. Initially request protected page when we're not authenticated
        
        HtmlPage loginPage = pageFromServer("/servlet");
        
        
        // 2. Server should forward to login page
        
        assertTrue(
            "The login page should have been displayed, but was not",
            loginPage.getWebResponse().getContentAsString().contains("Login to continue")
        );
        
        
        // 3. Submit the form on the login page with the wrong credentials
        
        HtmlForm form = loginPage.getForms().get(0);
        
        form.getInputByName("form:username")
            .setValueAttribute("reza");
        
        form.getInputByName("form:password")
            .setValueAttribute("wrongpassword");
        
        HtmlPage page = form.getInputByValue("Login")
                            .click();
        
        assertTrue(
            "An error message should be displayed, but was not",
            page.getWebResponse().getContentAsString().contains("Authentication failed")
        );
        
        // Should not be authenticted now
        assertDefaultNotAuthenticated(
            page.getWebResponse()
                .getContentAsString());
       
    }
    
    @Test
    public void testNotAuthenticatedInitiallyWrongNameThenCorrect() throws IOException {
        
        // 1. Initially request protected page when we're not authenticated
        
        HtmlPage loginPage = pageFromServer("/servlet");
        
        
        // 2. Server should forward to login page
        
        assertTrue(
            "The login page should have been displayed, but was not",
            loginPage.getWebResponse().getContentAsString().contains("Login to continue")
        );
        
        
        // 3. Submit the form on the login page with the wrong credentials
        
        HtmlForm form = loginPage.getForms().get(0);
        
        form.getInputByName("form:username")
            .setValueAttribute("reza");
        
        form.getInputByName("form:password")
            .setValueAttribute("wrongpassword");
        
        HtmlPage page = form.getInputByValue("Login")
                            .click();
        
        assertTrue(
            "An error message should be displayed, but was not",
            page.getWebResponse().getContentAsString().contains("Authentication failed")
        );
        
        // Should not be authenticted now
        assertDefaultNotAuthenticated(
            page.getWebResponse()
                .getContentAsString());
        
        
        // 4. Fill out form on page again (note that contrary to app mem form, this sample
        //    app causes an error message to be displayed on the form instead of showing
        //    an error page.
        
        
        form = page.getForms().get(0);
        
        form.getInputByName("form:username")
            .setValueAttribute("reza");
        
        form.getInputByName("form:password")
            .setValueAttribute("secret1");
        
        page = form.getInputByValue("Login")
                            .click();
        
        // Has to be authenticted now
        assertDefaultAuthenticated(
            page.getWebResponse()
                .getContentAsString());
    }

}
