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

import static org.glassfish.soteria.Utils.isEmpty;

import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

/**
 * This class stores the core data that makes up an {@link HttpServletRequest}.
 *
 * @author Arjan Tijms
 *
 */
public class RequestData {

    private Cookie[] cookies;
    private Map<String, List<String>> headers;
    private List<Locale> locales;
    private Map<String, String[]> parameters;

    private String method;
    private String requestURL;
    private String queryString;

    private boolean restoreRequest = true;

    public Cookie[] getCookies() {
        return cookies;
    }

    public void setCookies(Cookie[] cookies) {
        this.cookies = cookies;
    }

    public Map<String, List<String>> getHeaders() {
        return headers;
    }

    public void setHeaders(Map<String, List<String>> headers) {
        this.headers = headers;
    }

    public List<Locale> getLocales() {
        return locales;
    }

    public void setLocales(List<Locale> locales) {
        this.locales = locales;
    }

    public Map<String, String[]> getParameters() {
        return parameters;
    }

    public void setParameters(Map<String, String[]> parameters) {
        this.parameters = parameters;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getQueryString() {
        return queryString;
    }

    public void setQueryString(String queryString) {
        this.queryString = queryString;
    }

    public String getRequestURL() {
        return requestURL;
    }

    public void setRequestURL(String requestURL) {
        this.requestURL = requestURL;
    }

    public boolean isRestoreRequest() {
        return restoreRequest;
    }

    public void setRestoreRequest(boolean restoreRequest) {
        this.restoreRequest = restoreRequest;
    }

    public String getFullRequestURL() {
        return buildFullRequestURL(requestURL, queryString);
    }

    public boolean matchesRequest(HttpServletRequest request) {
        // (or use requestURI instead of requestURL?)
        return getFullRequestURL().equals(buildFullRequestURL(request.getRequestURL().toString(), request.getQueryString()));
    }

    @Override
    public String toString() {
        return String.format("%s %s", method, getFullRequestURL());
    }

    private String buildFullRequestURL(String requestURL, String queryString) {
        return requestURL + (isEmpty(queryString) ? "" : "?" + queryString);
    }

}
