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

import static java.util.Arrays.copyOf;
import static java.util.Collections.emptyMap;
import static java.util.Collections.list;
import static org.glassfish.soteria.Utils.isEmpty;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

/**
 * This class copies all "base data" from a given request. The goal is that this copied data can be used
 * later to restore a request, by wrapping a new request and delegating methods that fetch data
 * from that request to the copied data.
 * 
 * @author Arjan Tijms
 *
 */
public final class RequestCopier {
    
    private RequestCopier() {}

    public static RequestData copy(HttpServletRequest request) {
        
        RequestData requestData = new RequestData();
        
        requestData.setCookies(copyCookies(request.getCookies()));
        requestData.setHeaders(copyHeaders(request));
        requestData.setParameters(copyParameters(request.getParameterMap()));
        requestData.setLocales(list(request.getLocales()));
        
        requestData.setMethod(request.getMethod());
        requestData.setRequestURL(request.getRequestURL().toString());
        requestData.setQueryString(request.getQueryString());
    
        return requestData;
    }
    
    
    private static Cookie[] copyCookies(Cookie[] cookies) {
        
        if (isEmpty(cookies)) {
            return cookies;
        }
        
        ArrayList<Cookie> copiedCookies = new ArrayList<>();
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
    
}
