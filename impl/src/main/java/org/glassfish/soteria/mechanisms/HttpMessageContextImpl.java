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

import static jakarta.security.enterprise.AuthenticationStatus.NOT_DONE;
import static jakarta.security.enterprise.AuthenticationStatus.SEND_CONTINUE;
import static jakarta.security.enterprise.AuthenticationStatus.SEND_FAILURE;
import static jakarta.security.enterprise.AuthenticationStatus.SUCCESS;
import static jakarta.security.enterprise.identitystore.CredentialValidationResult.Status.VALID;
import static jakarta.servlet.http.HttpServletResponse.SC_NOT_FOUND;
import static jakarta.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;

import java.io.IOException;
import java.security.Principal;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;

import org.glassfish.soteria.Utils;
import org.glassfish.soteria.mechanisms.jaspic.Jaspic;

import jakarta.security.auth.message.MessageInfo;
import jakarta.security.enterprise.AuthenticationStatus;
import jakarta.security.enterprise.CallerPrincipal;
import jakarta.security.enterprise.authentication.mechanism.http.AuthenticationParameters;
import jakarta.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import jakarta.security.enterprise.identitystore.CredentialValidationResult;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * A convenience context that provides access to JASPIC Servlet Profile specific types
 * and functionality.
 *
 * @author Arjan Tijms
 */
public class HttpMessageContextImpl implements HttpMessageContext {

    private CallbackHandler handler;
    private MessageInfo messageInfo;
    private Subject clientSubject;
    private AuthenticationParameters authParameters;

    private Principal callerPrincipal;
    private Set<String> groups;

    public HttpMessageContextImpl(CallbackHandler handler, MessageInfo messageInfo, Subject clientSubject) {
        this.handler = handler;
        this.messageInfo = messageInfo;
        this.clientSubject = clientSubject;
        if (messageInfo != null) {
            this.authParameters = Jaspic.getAuthParameters(getRequest());
        }
    }

    @Override
    public boolean isProtected() {
        return Jaspic.isProtectedResource(messageInfo);
    }

    @Override
    public boolean isAuthenticationRequest() {
        return Jaspic.isAuthenticationRequest(getRequest());
    }

    @Override
    public boolean isRegisterSession() {
        return Jaspic.isRegisterSession(messageInfo);
    }

    @Override
    public void setRegisterSession(String username, Set<String> groups) {
        Jaspic.setRegisterSession(messageInfo, username, groups);
    }

    @Override
    public void cleanClientSubject() {
        Jaspic.cleanSubject(clientSubject);
    }

    @Override
    public AuthenticationParameters getAuthParameters() {
        return authParameters;
    }

    @Override
    public CallbackHandler getHandler() {
        return handler;
    }

    @Override
    public MessageInfo getMessageInfo() {
        return messageInfo;
    }

    @Override
    public Subject getClientSubject() {
        return clientSubject;
    }

    @Override
    public HttpServletRequest getRequest() {
        return (HttpServletRequest) messageInfo.getRequestMessage();
    }

    @Override
    public void setRequest(HttpServletRequest request) {
        messageInfo.setRequestMessage(request);
    }

    @Override
    public HttpMessageContext withRequest(HttpServletRequest request) {
        setRequest(request);
        return this;
    }

    @Override
    public HttpServletResponse getResponse() {
        return (HttpServletResponse) messageInfo.getResponseMessage();
    }

    @Override
    public void setResponse(HttpServletResponse response) {
        messageInfo.setResponseMessage(response);
    }

    @Override
    public AuthenticationStatus redirect(String location) {
        Utils.redirect(getResponse(), location);

        return SEND_CONTINUE;
    }

    @Override
    public AuthenticationStatus forward(String path) {
        try {
            getRequest().getRequestDispatcher(path)
                    .forward(getRequest(), getResponse());
        } catch (IOException | ServletException e) {
            throw new IllegalStateException(e);
        }

        // After forward MUST NOT invoke the resource, so CAN NOT return SUCCESS here.
        return SEND_CONTINUE;
    }

    @Override
    public AuthenticationStatus responseUnauthorized() {
        try {
            getResponse().sendError(SC_UNAUTHORIZED);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }

        return SEND_FAILURE;
    }

    @Override
    public AuthenticationStatus responseNotFound() {
        try {
            getResponse().sendError(SC_NOT_FOUND);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }

        return SEND_FAILURE;
    }

    @Override
    public AuthenticationStatus notifyContainerAboutLogin(String callerName, Set<String> groups) {
        NameHolderPrincipal nameHolder = null;
        if (callerName != null) {
            nameHolder = new NameHolderPrincipal(callerName);
        }

        return notifyContainerAboutLogin(nameHolder, groups);
    }

    @Override
    public AuthenticationStatus notifyContainerAboutLogin(CredentialValidationResult result) {
        if (result.getStatus() == VALID) {
            return notifyContainerAboutLogin(
                    result.getCallerPrincipal(),
                    result.getCallerGroups());

        }

        return SEND_FAILURE;
    }

    @Override
    public AuthenticationStatus notifyContainerAboutLogin(Principal callerPrincipal, Set<String> groups) {
        this.callerPrincipal = callerPrincipal;
        if (callerPrincipal != null) {
            this.groups = groups;
        } else {
            this.groups = null;
        }

        if (this.callerPrincipal instanceof NameHolderPrincipal) {
            Jaspic.notifyContainerAboutLogin(clientSubject, handler, this.callerPrincipal.getName(), this.groups);
        }
        else {
            Jaspic.notifyContainerAboutLogin(clientSubject, handler, this.callerPrincipal, this.groups);
        }

        // Explicitly set a flag that we did authentication, so code can check that this happened
        // TODO: or throw CDI event here?
        Jaspic.setDidAuthentication((HttpServletRequest) messageInfo.getRequestMessage());

        return SUCCESS;
    }

    @Override
    public AuthenticationStatus doNothing() {
        this.callerPrincipal = null;
        this.groups = null;

        Jaspic.notifyContainerAboutLogin(clientSubject, handler, (String) null, null);

        return NOT_DONE;
    }

    @Override
    public Principal getCallerPrincipal() {
        // This will be a NameHolderPrincipal if String callerName passed to notifyContainerAboutLogin().
        return callerPrincipal;
    }

    @Override
    public Set<String> getGroups() {
        return groups;
    }

    /**
     * Private Principal type used to hold a caller name in the case that
     * notifyContainerAboutLogin() is called with a string name, rather than
     * a Principal or a CredentialValidationResult. HttpMessageContext unfortunately
     * doesn't have a getCallerName() method, so if string is passed we need some
     * way to store and return the caller's name; this is it.
     */
    private static class NameHolderPrincipal extends CallerPrincipal {
        private static final long serialVersionUID = 1L;

        NameHolderPrincipal(String name) {
            super(name);
        }
    }

}
