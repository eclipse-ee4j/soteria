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

package org.glassfish.soteria.mechanisms.jaspic;

import static javax.security.enterprise.AuthenticationStatus.NOT_DONE;
import static javax.security.enterprise.AuthenticationStatus.SEND_FAILURE;
import static org.glassfish.soteria.mechanisms.jaspic.Jaspic.fromAuthenticationStatus;
import static org.glassfish.soteria.mechanisms.jaspic.Jaspic.setLastAuthenticationStatus;

import java.util.Map;

import javax.enterprise.inject.spi.CDI;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.config.ServerAuthContext;
import javax.security.auth.message.module.ServerAuthModule;
import javax.security.enterprise.AuthenticationException;
import javax.security.enterprise.AuthenticationStatus;
import javax.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism;
import javax.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.glassfish.soteria.cdi.spi.CDIPerRequestInitializer;
import org.glassfish.soteria.mechanisms.HttpMessageContextImpl;

/**
 *
 * @author Arjan Tijms
 *
 */
public class HttpBridgeServerAuthModule implements ServerAuthModule {

        private final CallbackHandler handler;
        private final Class<?>[] supportedMessageTypes = new Class[] { HttpServletRequest.class, HttpServletResponse.class };
        private final CDIPerRequestInitializer cdiPerRequestInitializer;
        
        public HttpBridgeServerAuthModule(CDIPerRequestInitializer cdiPerRequestInitializer, CallbackHandler handler) {
            this.cdiPerRequestInitializer = cdiPerRequestInitializer;
            this.handler = handler;
        }
        
        @Override
        public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy, CallbackHandler handler, @SuppressWarnings("rawtypes") Map options) throws AuthException {
            // options not supported.
        }

        /**
         * A Servlet Container Profile compliant implementation should return HttpServletRequest and HttpServletResponse, so
         * the delegation class {@link ServerAuthContext} can choose the right SAM to delegate to.
         */
        @Override
        public Class<?>[] getSupportedMessageTypes() {
            return supportedMessageTypes;
        }

        @Override
        public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws AuthException {
            
            HttpMessageContext msgContext = new HttpMessageContextImpl(handler, messageInfo, clientSubject);
            
            if (cdiPerRequestInitializer != null) {
                cdiPerRequestInitializer.init(msgContext.getRequest());
            }
            
            AuthenticationStatus status = NOT_DONE;
            setLastAuthenticationStatus(msgContext.getRequest(), status);
                
            try {
                status = CDI.current()
                            .select(HttpAuthenticationMechanism.class).get()
                            .validateRequest(
                                msgContext.getRequest(), 
                                msgContext.getResponse(), 
                                msgContext);
            } catch (AuthenticationException e) {
                // In case of an explicit AuthException, status will
                // be set to SEND_FAILURE, for any other (non checked) exception
                // the status will be the default NOT_DONE
                setLastAuthenticationStatus(msgContext.getRequest(), SEND_FAILURE);
                throw (AuthException) new AuthException("Authentication failure in HttpAuthenticationMechanism").initCause(e);
            }
            
            setLastAuthenticationStatus(msgContext.getRequest(), status);
            
            return fromAuthenticationStatus(status);
        }

        @Override
        public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject) throws AuthException {
            HttpMessageContext msgContext = new HttpMessageContextImpl(handler, messageInfo, null);

            try {
                AuthenticationStatus status = CDI.current()
                                                 .select(HttpAuthenticationMechanism.class).get()
                                                 .secureResponse(
                                                     msgContext.getRequest(), 
                                                     msgContext.getResponse(), 
                                                     msgContext);
                AuthStatus authStatus = fromAuthenticationStatus(status);
                if (authStatus == AuthStatus.SUCCESS) {
                    return AuthStatus.SEND_SUCCESS;
                }
                return authStatus;
            } catch (AuthenticationException e) {
                throw (AuthException) new AuthException("Secure response failure in HttpAuthenticationMechanism").initCause(e);
            } finally {
                if (cdiPerRequestInitializer != null) {
                    cdiPerRequestInitializer.destroy(msgContext.getRequest());
                }
            }

        }

        /**
         * Called in response to a {@link HttpServletRequest#logout()} call.
         *
         */
        @Override
        public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
            HttpMessageContext msgContext = new HttpMessageContextImpl(handler, messageInfo, subject);
            
            CDI.current()
               .select(HttpAuthenticationMechanism.class).get()
               .cleanSubject(msgContext.getRequest(), msgContext.getResponse(), msgContext);
        }

}
