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

import static javax.ws.rs.core.MediaType.TEXT_PLAIN;

import jakarta.inject.Inject;
import jakarta.security.enterprise.SecurityContext;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;

@Path("/protectedResource")
@Produces(TEXT_PLAIN)
public class ProtectedResource {
    
    @Inject
    private SecurityContext securityContext;
    
    @GET
    @Path("sayHi")
    public String sayHi() {
       return "saying hi!";
    }

    @GET
    @Path("callerName")
    public String getCallerName() {
        if (securityContext.getCallerPrincipal() != null) {
            return securityContext.getCallerPrincipal().getName();
        }
        
        return null;
    }
    
    @GET
    @Path("hasRoleFoo")
    public boolean hasRoleFoo() {
        return securityContext.isCallerInRole("foo");
    }
    
    @GET
    @Path("hasRoleKaz")
    public boolean hasRoleKaz() {
        return securityContext.isCallerInRole("kaz");
    }
    
}
