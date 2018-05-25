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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public final class Assert {
    
    public static void assertDefaultAuthenticated(String response) {
        assertAuthenticated("web", "reza", response, "foo", "bar");
    }
    
    public static void assertDefaultNotAuthenticated(String response) {
        assertNotAuthenticated("web", "reza", response, "foo", "bar");
    }
    
    public static void assertAuthenticated(String userType, String name, String response, String... roles) {
        assertTrue(
            "Should be authenticated as user " + name + " but was not \n Response: \n" + 
            response + "\n search: " + userType + " username: " + name,
            response.contains(userType + " username: " + name));
        
        for (String role : roles) {
            assertTrue(
                "Authenticated user should have role \"" + role + "\", but did not \n Response: \n" + 
                response,
                response.contains(userType + " user has role \"" + role + "\": true"));
        }
    }
    
    public static void assertNotAuthenticated(String userType, String name, String response, String... roles) {
        assertFalse(
            "Should not be authenticated as user " + name + " but was \n Response: \n" + 
            response + "\n search: " + userType + " username: " + name,
            response.contains(userType + " username: " + name));
        
        for (String role : roles) {
            assertFalse(
                "Authenticated user should not have role \"" + role + "\", but did \n Response: \n" + 
                response,
                response.contains(userType + " user has role \"" + role + "\": true"));
        }
     }

}
