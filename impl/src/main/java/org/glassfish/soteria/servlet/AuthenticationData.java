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

package org.glassfish.soteria.servlet;

import static java.util.Collections.unmodifiableSet;

import java.io.Serializable;
import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

/**
 * This class holds stores "authentication data" (principal and groups).
 * 
 * <p>
 * This is intended as a temporary storage in the HTTP session for this data specifically 
 * during an HTTP redirect, which is why this class is in the servlet package.
 * 
 * @author Arjan Tijms
 */
public class AuthenticationData implements Serializable {

    private static final long serialVersionUID = 1L;
    
    private final Principal principal;
    private final Set<String> groups;
    
    public AuthenticationData(Principal principal, Set<String> groups) {
        this.principal = principal;
        this.groups = new HashSet<>(unmodifiableSet(groups));
    }
    
    public Principal getPrincipal() {
        return principal;
    }

    public Set<String> getGroups() {
        return groups;
    }
    
}
