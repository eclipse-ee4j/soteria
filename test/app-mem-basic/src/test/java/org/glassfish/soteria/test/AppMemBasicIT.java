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


@RunWith(Arquillian.class)
public class AppMemBasicIT extends ArquillianBase {
    
    @Deployment(testable = false)
    public static Archive<?> createDeployment() {
        return mavenWar();
    }

    @Test
    public void testAuthenticated() {
    	
    	DefaultCredentialsProvider credentialsProvider = new DefaultCredentialsProvider();
    	credentialsProvider.addCredentials("reza", "secret:1");
    	
    	getWebClient().setCredentialsProvider(credentialsProvider);
    	
        assertDefaultAuthenticated(
            readFromServer("/servlet"));
    }
    
    @Test
    public void testNotAuthenticated() {
        
        WebResponse response = responseFromServer("/servlet");
        
        assertEquals(401, response.getStatusCode());
        
        assertTrue(
            "Response did not contain the \"WWW-Authenticate\" header, but should have", 
            response.getResponseHeaderValue("WWW-Authenticate") != null);
        
        assertDefaultNotAuthenticated(
            response.getContentAsString());
    }
    
    @Test
    public void testNotAuthenticatedWrongName() {
    	
    	DefaultCredentialsProvider credentialsProvider = new DefaultCredentialsProvider();
    	credentialsProvider.addCredentials("romo", "secret:1");
    	
    	getWebClient().setCredentialsProvider(credentialsProvider);
    	
    	WebResponse response = responseFromServer("/servlet");
          
    	assertEquals(401, response.getStatusCode());
          
    	assertTrue(
	        "Response did not contain the \"WWW-Authenticate\" header, but should have", 
	        response.getResponseHeaderValue("WWW-Authenticate") != null);
          
    	assertDefaultNotAuthenticated(
	        response.getContentAsString());
    }
    
    @Test
    public void testNotAuthenticatedWrongPassword() {
    	
      	DefaultCredentialsProvider credentialsProvider = new DefaultCredentialsProvider();
    	credentialsProvider.addCredentials("reza", "wrongpassword");
    	
    	getWebClient().setCredentialsProvider(credentialsProvider);
    	
        WebResponse response = responseFromServer("/servlet");
        
        assertEquals(401, response.getStatusCode());
          
        assertTrue(
            "Response did not contain the \"WWW-Authenticate\" header, but should have", 
            response.getResponseHeaderValue("WWW-Authenticate") != null);
          
        assertDefaultNotAuthenticated(
            response.getContentAsString());
    }

}
