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

import static org.glassfish.soteria.test.ShrinkWrap.mavenWar;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.shrinkwrap.api.Archive;
import org.junit.Test;
import org.junit.runner.RunWith;


@RunWith(Arquillian.class)
public class AppJaxRsIT extends ArquillianBase {
    
    @Deployment(testable = false)
    public static Archive<?> createDeployment() {
        return mavenWar();
    }

    @Test
    public void testAuthenticated() {
        String response = readFromServer("/rest/resource/callerName?name=reza&password=secret1");
        
        assertTrue(
            "Should be authenticated as user reza but was not",
            response.contains("reza"));
    }
    
    @Test
    public void testNotAuthenticated() {
        String response = readFromServer("/rest/resource/callerName");
        
        assertFalse(
            "Should not be authenticated as user reza but was",
            response.contains("reza"));
    }
    
    @Test
    public void testHasRoleFoo() {
        String response = readFromServer("/rest/resource/hasRoleFoo?name=reza&password=secret1");
        
        assertTrue(
            "Should be in role foo, but was not",
            response.contains("true"));
    }
    
    @Test
    public void testNotHasRoleFoo() {
        String response = readFromServer("/rest/resource/hasRoleFoo");
        
        assertTrue(
            "Should not be in role foo, but was",
            response.contains("false"));
    }
    
    @Test
    public void testNotHasRoleKaz1() {
        String response = readFromServer("/rest/resource/hasRoleKaz?name=reza&password=secret1");
        
        assertFalse(
            "Should not be in role kaz, but was",
            response.contains("true"));
    }
    
    @Test
    public void testNotHasRoleKaz2() {
        String response = readFromServer("/rest/resource/hasRoleKaz");
        
        assertFalse(
            "Should not be in role kaz, but was",
            response.contains("true"));
    }
    
    @Test
    public void testSayHi() {
        String response = readFromServer("/rest/protectedResource/sayHi?name=reza&password=secret1");
        
        assertTrue(
            "Endpoint should have been called, but was not",
            response.contains("saying hi!"));
    }
    
    @Test
    public void testNotSayHi() {
        String response = readFromServer("/rest/protectedResource/sayHi");
        
        assertFalse(
            "Endpoint should not have been called, but was",
            response.contains("saying hi!"));
    }

}
