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

package org.glassfish.soteria;

import static javax.security.enterprise.AuthenticationStatus.SEND_FAILURE;
import static javax.security.enterprise.AuthenticationStatus.SUCCESS;
import static org.glassfish.soteria.mechanisms.jaspic.Jaspic.getLastAuthenticationStatus;

import java.io.Serializable;
import java.security.Principal;
import java.util.Set;

import javax.annotation.PostConstruct;
import javax.security.enterprise.AuthenticationStatus;
import javax.security.enterprise.SecurityContext;
import javax.security.enterprise.authentication.mechanism.http.AuthenticationParameters;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.glassfish.soteria.authorization.spi.CallerDetailsResolver;
import org.glassfish.soteria.authorization.spi.ResourceAccessResolver;
import org.glassfish.soteria.authorization.spi.impl.JaccResourceAccessResolver;
import org.glassfish.soteria.authorization.spi.impl.ReflectionAndJaccCallerDetailsResolver;
import org.glassfish.soteria.mechanisms.jaspic.Jaspic;

public class SecurityContextImpl implements SecurityContext, Serializable {
    
    private static final long serialVersionUID = 1L;
    
    private CallerDetailsResolver callerDetailsResolver;
    private ResourceAccessResolver resourceAccessResolver;

    @PostConstruct
    public void init() {
       callerDetailsResolver = new ReflectionAndJaccCallerDetailsResolver();
       resourceAccessResolver = new JaccResourceAccessResolver();
    }

    @Override
    public Principal getCallerPrincipal() {
        return callerDetailsResolver.getCallerPrincipal();
    }

    @Override
    public <T extends Principal> Set<T> getPrincipalsByType(Class<T> pType) {
        return callerDetailsResolver.getPrincipalsByType(pType);
    }

    @Override
    public boolean isCallerInRole(String role) {
        return callerDetailsResolver.isCallerInRole(role);
    }

    // Implementation specific method, not present in API.
    public Set<String> getAllDeclaredCallerRoles() {
        return callerDetailsResolver.getAllDeclaredCallerRoles();
    }

    @Override
    public boolean hasAccessToWebResource(String resource, String... methods) {
        return resourceAccessResolver.hasAccessToWebResource(resource, methods);
    }

    @Override
    public AuthenticationStatus authenticate(HttpServletRequest request, HttpServletResponse response, AuthenticationParameters parameters) {
        
        try {
            if (Jaspic.authenticate(request, response, parameters)) {
                // All servers return true when authentication actually took place 
                return SUCCESS;
            }
            
            // GlassFish returns false when either authentication is in progress or authentication
            // failed (or was not done at all). 
            // Therefore we need to rely on the status we saved as a request attribute
            return getLastAuthenticationStatus(request);
        } catch (IllegalArgumentException e) { // TODO: exception type not ideal
            // JBoss returns false when authentication is in progress, but throws exception when
            // authentication fails (or was not done at all).
            return SEND_FAILURE;
        }
    }

}
