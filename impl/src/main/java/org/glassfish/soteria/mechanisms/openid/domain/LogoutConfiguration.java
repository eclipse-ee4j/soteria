/*
 * Copyright (c) 2021 Contributors to the Eclipse Foundation
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
 * Contributors:
 *   2021 : Payara Foundation and/or its affiliates
 *      Initially authored in Security Connectors
 */
package org.glassfish.soteria.mechanisms.openid.domain;

import static org.glassfish.soteria.mechanisms.openid.domain.OpenIdConfiguration.BASE_URL_EXPRESSION;

import jakarta.servlet.http.HttpServletRequest;

/**
 *
 * @author Gaurav Gupta
 * @author Rudy De Busscher
 */
public class LogoutConfiguration {

    private boolean notifyProvider;

    private String redirectURI;

    private boolean accessTokenExpiry;

    private boolean identityTokenExpiry;

    public boolean isNotifyProvider() {
        return notifyProvider;
    }

    public LogoutConfiguration setNotifyProvider(boolean notifyProvider) {
        this.notifyProvider = notifyProvider;
        return this;
    }

    public String getRedirectURI() {
        return redirectURI;
    }

    public LogoutConfiguration setRedirectURI(String redirectURI) {
        this.redirectURI = redirectURI;
        return this;
    }

    public String buildRedirectURI(HttpServletRequest request) {
        if (redirectURI.contains(BASE_URL_EXPRESSION)) {
            String baseURL = request.getRequestURL().substring(0, request.getRequestURL().length() - request.getRequestURI().length())
                    + request.getContextPath();
            return redirectURI.replace(BASE_URL_EXPRESSION, baseURL);
        }
        return redirectURI;
    }

    public boolean isAccessTokenExpiry() {
        return accessTokenExpiry;
    }

    public LogoutConfiguration setAccessTokenExpiry(boolean accessTokenExpiry) {
        this.accessTokenExpiry = accessTokenExpiry;
        return this;
    }

    public boolean isIdentityTokenExpiry() {
        return identityTokenExpiry;
    }

    public LogoutConfiguration setIdentityTokenExpiry(boolean identityTokenExpiry) {
        this.identityTokenExpiry = identityTokenExpiry;
        return this;
    }

    @Override
    public String toString() {
        return "LogoutConfiguration{" + "notifyProvider=" + notifyProvider + ", redirectURI=" + redirectURI + ", accessTokenExpiry=" + accessTokenExpiry + ", identityTokenExpiry=" + identityTokenExpiry + '}';
    }

}
