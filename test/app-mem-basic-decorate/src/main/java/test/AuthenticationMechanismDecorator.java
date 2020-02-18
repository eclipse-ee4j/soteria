/*
 * Copyright (c) 2018, 2020 Payara Foundation and/or its affiliates and others.
 * All rights reserved.
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
package test;

import java.io.IOException;

import jakarta.annotation.Priority;
import jakarta.decorator.Decorator;
import jakarta.decorator.Delegate;
import jakarta.inject.Inject;
import jakarta.security.enterprise.AuthenticationException;
import jakarta.security.enterprise.AuthenticationStatus;
import jakarta.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism;
import jakarta.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;

/**
 * This is a CDI decorator that decorates the authentication mechanism (in this test
 * the one that is installed via the annotation on the {@link Servlet} class.
 *
 * @author Arjan Tijms
 *
 */
@Decorator
@Priority(100)
public abstract class AuthenticationMechanismDecorator implements HttpAuthenticationMechanism {

    @Inject
    @Delegate
    private HttpAuthenticationMechanism delagate;

    @Override
    public AuthenticationStatus validateRequest(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMessageContext) throws AuthenticationException {

        // Wrap the response, so we can catch the error code being sent
        // (the error code causes the response to be committed)
        ResponseWrapper responseWrapper = new ResponseWrapper(response);
        httpMessageContext.getMessageInfo().setResponseMessage(responseWrapper);

        try {

            // Invoke the original authentication mechanism
            AuthenticationStatus status = delagate.validateRequest(request, responseWrapper, httpMessageContext);

            // If there was an error, add our custom header and pass on the error
            // to the original response
            if (responseWrapper.getError() != null) {
                response.addHeader("foo", "bar");
                response.sendError(responseWrapper.getError());
            }

            return status;

        } catch (IOException e) {
            throw new AuthenticationException(e);
        } finally {
            // Restore the original response
            httpMessageContext.getMessageInfo().setResponseMessage(response);
        }
    }

    private static class ResponseWrapper extends HttpServletResponseWrapper {

        private Integer error;

        public ResponseWrapper(HttpServletResponse response) {
            super(response);
        }

        @Override
        public void sendError(int sc) throws IOException {
            error = sc;
        }

        public Integer getError() {
            return error;
        }

    }

}
