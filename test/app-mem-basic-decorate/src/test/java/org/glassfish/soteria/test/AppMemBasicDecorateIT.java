/*
 * Copyright (c) 2015, 2018 Oracle and/or its affiliates and others.
 * All rights reserved.
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

import static org.glassfish.soteria.test.Assert.assertDefaultAuthenticated;
import static org.glassfish.soteria.test.Assert.assertDefaultNotAuthenticated;
import static org.glassfish.soteria.test.ShrinkWrap.mavenWar;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.shrinkwrap.api.Archive;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.gargoylesoftware.htmlunit.DefaultCredentialsProvider;
import com.gargoylesoftware.htmlunit.WebResponse;

import test.AuthenticationMechanismDecorator;


@RunWith(Arquillian.class)
public class AppMemBasicDecorateIT extends ArquillianBase {

    @Deployment(testable = false)
    public static Archive<?> createDeployment() {
        return mavenWar();
    }

    /**
     * Test that authentication via BASIC works normally
     */
    @Test
    public void testAuthenticated() {

    	DefaultCredentialsProvider credentialsProvider = new DefaultCredentialsProvider();
    	credentialsProvider.addCredentials("reza", "secret1");

    	getWebClient().setCredentialsProvider(credentialsProvider);

        assertDefaultAuthenticated(
            readFromServer("/servlet"));
    }

    /**
     * Test that in case of not-authenticated, we received a custom
     * header that has been set by the decorator {@link AuthenticationMechanismDecorator}
     */
    @Test
    public void testNotAuthenticatedAndDecorated() {

        // Request a constrained (protected) resources without providing authentication
        WebResponse response = responseFromServer("/servlet");

        // Should get a 401, since we're not authenticated
        assertEquals(401, response.getStatusCode());

        // Should also get a custom header, which a decorator sets
        assertEquals("bar", response.getResponseHeaderValue("foo"));

        assertTrue(
            "Response did not contain the \"WWW-Authenticate\" header, but should have",
            response.getResponseHeaderValue("WWW-Authenticate") != null);

        assertDefaultNotAuthenticated(
            response.getContentAsString());
    }


}
