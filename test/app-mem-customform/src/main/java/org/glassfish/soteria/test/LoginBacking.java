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

import static javax.faces.application.FacesMessage.SEVERITY_ERROR;
import static jakarta.security.enterprise.AuthenticationStatus.SEND_CONTINUE;
import static jakarta.security.enterprise.AuthenticationStatus.SEND_FAILURE;
import static jakarta.security.enterprise.authentication.mechanism.http.AuthenticationParameters.withParams;

import jakarta.enterprise.context.RequestScoped;
import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import jakarta.inject.Inject;
import jakarta.inject.Named;
import jakarta.security.enterprise.AuthenticationStatus;
import jakarta.security.enterprise.SecurityContext;
import jakarta.security.enterprise.credential.Credential;
import jakarta.security.enterprise.credential.Password;
import jakarta.security.enterprise.credential.UsernamePasswordCredential;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

@Named
@RequestScoped
public class LoginBacking {
    
    @Inject
    private SecurityContext securityContext;

    @NotNull
    @Size(min = 3, max = 15, message="Username must be between 3 and 15 characters")
    private String username;
    
    @NotNull
    @Size(min = 5, max = 50, message="Password must be between 5 and 50 characters")
    private String password;
    
    public void login() {
        
        FacesContext context = FacesContext.getCurrentInstance();
        Credential credential = new UsernamePasswordCredential(username, new Password(password));
        
        AuthenticationStatus status = securityContext.authenticate(
            getRequest(context),
            getResponse(context), 
            withParams()
                .credential(credential));
        
        if (status.equals(SEND_CONTINUE)) {
            // Authentication mechanism has send a redirect, should not
            // send anything to response from JSF now.
            context.responseComplete();
        } else if (status.equals(SEND_FAILURE)) {
            addError(context, "Authentication failed");
        }
        
    }
    
    private static HttpServletResponse getResponse(FacesContext context) {
        return (HttpServletResponse) context
            .getExternalContext()
            .getResponse();
    }
    
    private static HttpServletRequest getRequest(FacesContext context) {
        return (HttpServletRequest) context
            .getExternalContext()
            .getRequest();
    }
    
    private static void addError(FacesContext context, String message) {
        context
            .addMessage(
                null, 
                new FacesMessage(SEVERITY_ERROR, message, null));
    }

    
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

}
