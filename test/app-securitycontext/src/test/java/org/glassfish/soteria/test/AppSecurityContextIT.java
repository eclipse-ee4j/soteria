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

import static org.glassfish.soteria.test.Assert.assertDefaultAuthenticated;
import static org.glassfish.soteria.test.Assert.assertDefaultNotAuthenticated;
import static org.glassfish.soteria.test.ShrinkWrap.mavenWar;
import static org.junit.Assert.assertTrue;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.shrinkwrap.api.Archive;
import org.junit.Test;
import org.junit.runner.RunWith;


@RunWith(Arquillian.class)
public class AppSecurityContextIT extends ArquillianBase {

	@Deployment(testable = false)
    public static Archive<?> createDeployment() {
        return mavenWar();
    }

    @Test
    public void testWebAuthenticated() {
        assertDefaultAuthenticated(
            readFromServer("/servlet?name=reza&password=secret1"));
    }
    
    @Test
    public void testEJBContextAuthenticated() {
        Assert.assertAuthenticated(
            "ejb",
            "reza",
            readFromServer("/servlet?name=reza&password=secret1"));
    }
    
    @Test
    public void testContextAuthenticated() {
        Assert.assertAuthenticated(
            "context",
            "reza",
            readFromServer("/servlet?name=reza&password=secret1"));
    }
    
    @Test
    public void testNotAuthenticated() {
        assertDefaultNotAuthenticated(
            readFromServer("/servlet"));
    }
    
    @Test
    public void testContextNotAuthenticated() {
        assertDefaultNotAuthenticated(
            readFromServer("/servlet"));
    }
    
    @Test
    public void testHasAccessToOtherURLAuthenticated() {
        String response = readFromServer("/servlet?name=reza&password=secret1");
        
        assertTrue(
            "SecurityContext should say authenticated caller has access to /protectedServlet, but says has not.",
            response.contains("has access to /protectedServlet: true")
        );
    }
    
    @Test
    public void testHasNoAccessToOtherURLNotAuthenticated() {
        String response = readFromServer("/servlet");
        
        assertTrue(
            "SecurityContext should say authenticated caller has access to /protectedServlet, but says has not.",
            response.contains("has access to /protectedServlet: false")
        );
    }
    
   //has access to /protectedServlet: true

}
