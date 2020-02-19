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

package org.glassfish.soteria.mechanisms;

import jakarta.enterprise.inject.Typed;
import jakarta.security.enterprise.AuthenticationException;
import jakarta.security.enterprise.AuthenticationStatus;
import jakarta.security.enterprise.authentication.mechanism.http.AutoApplySession;
import jakarta.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism;
import jakarta.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import jakarta.security.enterprise.authentication.mechanism.http.LoginToContinue;
import jakarta.security.enterprise.identitystore.IdentityStoreHandler;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.glassfish.soteria.cdi.CdiUtils;

/**
 * Authentication mechanism that authenticates according to the Servlet spec defined FORM
 * authentication mechanism. See Servlet spec for further details.
 * 
 * @author Arjan Tijms
 *
 */
@AutoApplySession // For "is user already logged-in"
@LoginToContinue  // Redirects to form page if protected resource and not-logged in
@Typed(CustomFormAuthenticationMechanism.class) // Omit HttpAuthenticationMechanism type so it won't qualify directly as mechanism
public class CustomFormAuthenticationMechanism implements HttpAuthenticationMechanism, LoginToContinueHolder {
	
    private LoginToContinue loginToContinue;
    
	@Override
	public AuthenticationStatus validateRequest(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMessageContext) throws AuthenticationException {
        
        if (hasCredential(httpMessageContext)) {

            IdentityStoreHandler identityStoreHandler = CdiUtils.getBeanReference(IdentityStoreHandler.class);
            
            return httpMessageContext.notifyContainerAboutLogin(
                    identityStoreHandler.validate(
                    httpMessageContext.getAuthParameters()
                                      .getCredential()));
        }
		
		return httpMessageContext.doNothing();
	}
	
	private static boolean hasCredential(HttpMessageContext httpMessageContext) {
	    return 
            httpMessageContext.getAuthParameters().getCredential() != null;
	}
	
    @Override
    public LoginToContinue getLoginToContinue() {
        return loginToContinue;
    }

    public void setLoginToContinue(LoginToContinue loginToContinue) {
        this.loginToContinue = loginToContinue;
    }

}
