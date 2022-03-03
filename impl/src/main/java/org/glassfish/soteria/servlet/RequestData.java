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

package org.glassfish.soteria.servlet;

import static java.util.Arrays.copyOf;
import static java.util.Collections.emptyMap;
import static java.util.Collections.list;
import static org.glassfish.soteria.Utils.isEmpty;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;


/**
 * This class stores the core data that makes up an {@link HttpServletRequest}.
 *
 * @author Arjan Tijms
 *
 */
public class RequestData implements Serializable {

    private static final long serialVersionUID = 1L;

    private Cookie[] cookies;
    private Map<String, List<String>> headers;
    private List<Locale> locales;
    private Map<String, String[]> parameters;

    private String method;
    private String requestURL;
    private String queryString;

    public static RequestData of(HttpServletRequest request) {

        RequestData requestData = new RequestData();

        requestData.cookies = copyCookies(request.getCookies());
        requestData.headers = copyHeaders(request);
        requestData.parameters = copyParameters(request.getParameterMap());
        requestData.locales = list(request.getLocales());

        requestData.method = request.getMethod();
        requestData.requestURL = request.getRequestURL().toString();
        requestData.queryString = request.getQueryString();

        return requestData;
    }


    private static Cookie[] copyCookies(Cookie[] cookies) {

        if (isEmpty(cookies)) {
            return cookies;
        }

        List<Cookie> copiedCookies = new ArrayList<>();
        for (Cookie cookie : cookies) {
            copiedCookies.add((Cookie)cookie.clone());
        }

        return copiedCookies.toArray(new Cookie[copiedCookies.size()]);
    }

    private static Map<String, List<String>> copyHeaders(HttpServletRequest request) {

        Map<String, List<String>> copiedHeaders = new HashMap<>();
        for (String headerName : list(request.getHeaderNames())) {
            copiedHeaders.put(headerName, list(request.getHeaders(headerName)));
        }

        return copiedHeaders;
    }

    private static Map<String, String[]> copyParameters(Map<String, String[]> parameters) {

        if (isEmptyMap(parameters)) {
            return emptyMap();
        }

        Map<String, String[]> copiedParameters = new HashMap<>();
        for (Map.Entry<String, String[]> parameter : parameters.entrySet()) {
            copiedParameters.put(parameter.getKey(), copyOf(parameter.getValue(), parameter.getValue().length));
        }

        return copiedParameters;
    }

    private static boolean isEmptyMap(Map<?, ?> map) {
        return map == null || map.isEmpty();
    }

    public Cookie[] getCookies() {
        return cookies;
    }

    public Map<String, List<String>> getHeaders() {
        return headers;
    }


    public List<Locale> getLocales() {
        return locales;
    }

    public Map<String, String[]> getParameters() {
        return parameters;
    }

    public String getMethod() {
        return method;
    }


    public String getQueryString() {
        return queryString;
    }


    public String getRequestURL() {
        return requestURL;
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
