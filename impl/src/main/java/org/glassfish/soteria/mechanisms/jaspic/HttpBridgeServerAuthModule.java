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

package org.glassfish.soteria.mechanisms.jaspic;

import static jakarta.security.enterprise.AuthenticationStatus.NOT_DONE;
import static jakarta.security.enterprise.AuthenticationStatus.SEND_FAILURE;
import static org.glassfish.soteria.mechanisms.jaspic.Jaspic.fromAuthenticationStatus;
import static org.glassfish.soteria.mechanisms.jaspic.Jaspic.setLastAuthenticationStatus;

import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import jakarta.security.auth.message.AuthException;
import jakarta.security.auth.message.AuthStatus;
import jakarta.security.auth.message.MessageInfo;
import jakarta.security.auth.message.MessagePolicy;
import jakarta.security.auth.message.config.ServerAuthContext;
import jakarta.security.auth.message.module.ServerAuthModule;
import jakarta.security.enterprise.AuthenticationException;
import jakarta.security.enterprise.AuthenticationStatus;
import jakarta.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism;
import jakarta.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.glassfish.soteria.cdi.CdiUtils;
import org.glassfish.soteria.cdi.spi.CDIPerRequestInitializer;
import org.glassfish.soteria.mechanisms.HttpMessageContextImpl;

/**
 *
 * @author Arjan Tijms
 *
 */
public class HttpBridgeServerAuthModule implements ServerAuthModule {

        private CallbackHandler handler;
        private final Class<?>[] supportedMessageTypes = new Class[] { HttpServletRequest.class, HttpServletResponse.class };
        private final CDIPerRequestInitializer cdiPerRequestInitializer;
        
        public HttpBridgeServerAuthModule(CDIPerRequestInitializer cdiPerRequestInitializer) {
            this.cdiPerRequestInitializer = cdiPerRequestInitializer;
        }
        
        @Override
        public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy, CallbackHandler handler, @SuppressWarnings("rawtypes") Map options) throws AuthException {
            this.handler = handler;
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
                status = CdiUtils.getBeanReference(HttpAuthenticationMechanism.class)
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
                AuthenticationStatus status = CdiUtils.getBeanReference(HttpAuthenticationMechanism.class)
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
            
            CdiUtils.getBeanReference(HttpAuthenticationMechanism.class)
               .cleanSubject(msgContext.getRequest(), msgContext.getResponse(), msgContext);
        }

}
