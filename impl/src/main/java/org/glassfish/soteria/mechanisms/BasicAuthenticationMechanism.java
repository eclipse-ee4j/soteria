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

package org.glassfish.soteria.mechanisms;

import static java.lang.String.format;
import static javax.security.enterprise.identitystore.CredentialValidationResult.Status.VALID;
import static javax.xml.bind.DatatypeConverter.parseBase64Binary;
import static org.glassfish.soteria.Utils.isEmpty;

import javax.enterprise.inject.spi.CDI;
import javax.security.enterprise.AuthenticationException;
import javax.security.enterprise.AuthenticationStatus;
import javax.security.enterprise.authentication.mechanism.http.BasicAuthenticationMechanismDefinition;
import javax.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism;
import javax.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import javax.security.enterprise.credential.Password;
import javax.security.enterprise.credential.UsernamePasswordCredential;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.IdentityStoreHandler;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Authentication mechanism that authenticates using basic authentication
 *
 * @author Arjan Tijms
 *
 */
public class BasicAuthenticationMechanism implements HttpAuthenticationMechanism {
    
    private final BasicAuthenticationMechanismDefinition basicAuthenticationMechanismDefinition;

    // CDI requires a no-arg constructor to be portable
    // It's only used to create the proxy
    protected BasicAuthenticationMechanism() {
        basicAuthenticationMechanismDefinition = null;
    }
    
    public BasicAuthenticationMechanism(BasicAuthenticationMechanismDefinition basicAuthenticationMechanismDefinition) {
        this.basicAuthenticationMechanismDefinition = basicAuthenticationMechanismDefinition;
    }

	@Override
	public AuthenticationStatus validateRequest(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMsgContext) throws AuthenticationException {

		String[] credentials = getCredentials(request);
		if (!isEmpty(credentials)) {

            IdentityStoreHandler identityStoreHandler = CDI.current().select(IdentityStoreHandler.class).get();

            CredentialValidationResult result = identityStoreHandler.validate(
                    new UsernamePasswordCredential(credentials[0], new Password(credentials[1])));

            if (result.getStatus() == VALID) {
                return httpMsgContext.notifyContainerAboutLogin(
                    result.getCallerPrincipal(), result.getCallerGroups());
			}
		}

		if (httpMsgContext.isProtected()) {
			response.setHeader("WWW-Authenticate", format("Basic realm=\"%s\"", basicAuthenticationMechanismDefinition.realmName()));
			return httpMsgContext.responseUnauthorized();
		}

		return httpMsgContext.doNothing();
	}

	private String[] getCredentials(HttpServletRequest request) {

		String authorizationHeader = request.getHeader("Authorization");
		if (!isEmpty(authorizationHeader) && authorizationHeader.startsWith("Basic ") ) {
			return new String(parseBase64Binary(authorizationHeader.substring(6))).split(":");
		}

		return null;
	}

}
