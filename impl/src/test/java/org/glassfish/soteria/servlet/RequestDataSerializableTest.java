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

import jakarta.security.enterprise.CallerPrincipal;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.junit.Test;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.Principal;
import java.util.*;

/**
 *
 * @author guillermo
 */
public class RequestDataSerializableTest {

    @Test
    public void testSerializable() throws IOException {
        Locale.setDefault(Locale.ENGLISH);
        RequestData requestCopy = RequestData.of(new HttpServletRequestTestImpl());

        try (ObjectOutputStream out = new ObjectOutputStream(new ByteArrayOutputStream())) {
            out.writeObject(requestCopy);
        }
    }

    static class HttpServletRequestTestImpl implements HttpServletRequest {

        private final Cookie[] cookies;
        private final Map<String, List<String>> headers;
        private final List<Locale> locales;
        private final Map<String, String[]> parameters;

        public HttpServletRequestTestImpl() {
            this.cookies = new Cookie[]{new Cookie("name", "value")};
            this.headers = new HashMap<>();
            headers.put("header1", Arrays.asList("value1", "value2"));
            this.locales = List.of(Locale.ENGLISH);
            this.parameters = new HashMap<>();
            parameters.put("param1", new String[]{"value1", "value2"});
        }

        @Override
        public String getAuthType() {
            return "form";
        }

        @Override
        public Cookie[] getCookies() {
            return cookies;
        }

        @Override
        public long getDateHeader(String name) {
            return -1;
        }

        @Override
        public String getHeader(String name) {
            return null;
        }

        @Override
        public Enumeration<String> getHeaders(String name) {
            return Collections.enumeration(headers.get(name));
        }

        @Override
        public Enumeration<String> getHeaderNames() {
            return Collections.enumeration(headers.keySet());
        }

        @Override
        public int getIntHeader(String name) {
            return -1;
        }

        @Override
        public String getMethod() {
            return "POST";
        }

        @Override
        public String getPathInfo() {
            return "/";
        }

        @Override
        public String getPathTranslated() {
            return "test";
        }

        @Override
        public String getContextPath() {
            return "test";
        }

        @Override
        public String getQueryString() {
            return "test";
        }

        @Override
        public String getRemoteUser() {
            return "test";
        }

        @Override
        public boolean isUserInRole(String role) {
            return false;
        }

        @Override
        public Principal getUserPrincipal() {
            return new CallerPrincipal("test");
        }

        @Override
        public String getRequestedSessionId() {
            return "test";
        }

        @Override
        public String getRequestURI() {
            return "test";
        }

        @Override
        public StringBuffer getRequestURL() {
            return new StringBuffer("test");
        }

        @Override
        public String getServletPath() {
            return "test";
        }

        @Override
        public HttpSession getSession(boolean create) {
            return null;
        }

        @Override
        public HttpSession getSession() {
            return null;
        }

        @Override
        public String changeSessionId() {
            return "test";
        }

        @Override
        public boolean isRequestedSessionIdValid() {
            return false;
        }

        @Override
        public boolean isRequestedSessionIdFromCookie() {
            return false;
        }

        @Override
        public boolean isRequestedSessionIdFromURL() {
            return false;
        }

        @Override
        public boolean isRequestedSessionIdFromUrl() {
            return false;
        }

        @Override
        public boolean authenticate(HttpServletResponse response) {
            return false;
        }

        @Override
        public void login(String username, String password) {

        }

        @Override
        public void logout() {

        }

        @Override
        public Collection<Part> getParts() {
            return Collections.emptyList();
        }

        @Override
        public Part getPart(String name) {
            return null;
        }

        @Override
        public <T extends HttpUpgradeHandler> T upgrade(Class<T> handlerClass) {
            return null;
        }

        @Override
        public Object getAttribute(String name) {
            return null;
        }

        @Override
        public Enumeration<String> getAttributeNames() {
            return Collections.emptyEnumeration();
        }

        @Override
        public String getCharacterEncoding() {
            return "UTF-8";
        }

        @Override
        public void setCharacterEncoding(String env) {

        }

        @Override
        public int getContentLength() {
            return -1;
        }

        @Override
        public long getContentLengthLong() {
            return -1;
        }

        @Override
        public String getContentType() {
            return "text/plain";
        }

        @Override
        public ServletInputStream getInputStream() {
            return null;
        }

        @Override
        public String getParameter(String name) {
            return "test";
        }

        @Override
        public Enumeration<String> getParameterNames() {
            return Collections.enumeration(parameters.keySet());
        }

        @Override
        public String[] getParameterValues(String name) {
            return parameters.get(name);
        }

        @Override
        public Map<String, String[]> getParameterMap() {
            return parameters;
        }

        @Override
        public String getProtocol() {
            return "http";
        }

        @Override
        public String getScheme() {
            return "https";
        }

        @Override
        public String getServerName() {
            return "localhost";
        }

        @Override
        public int getServerPort() {
            return 80;
        }

        @Override
        public BufferedReader getReader() {
            return null;
        }

        @Override
        public String getRemoteAddr() {
            return "localhost";
        }

        @Override
        public String getRemoteHost() {
            return "localhost";
        }

        @Override
        public void setAttribute(String name, Object o) {

        }

        @Override
        public void removeAttribute(String name) {

        }

        @Override
        public Locale getLocale() {
            return Locale.ENGLISH;
        }

        @Override
        public Enumeration<Locale> getLocales() {
            return Collections.enumeration(locales);
        }

        @Override
        public boolean isSecure() {
            return false;
        }

        @Override
        public RequestDispatcher getRequestDispatcher(String path) {
            return null;
        }

        @Override
        public String getRealPath(String path) {
            return "test";
        }

        @Override
        public int getRemotePort() {
            return 80;
        }

        @Override
        public String getLocalName() {
            return "localhost";
        }

        @Override
        public String getLocalAddr() {
            return "localhost";
        }

        @Override
        public int getLocalPort() {
            return 80;
        }

        @Override
        public ServletContext getServletContext() {
            return null;
        }

        @Override
        public AsyncContext startAsync() throws IllegalStateException {
            return null;
        }

        @Override
        public AsyncContext startAsync(ServletRequest servletRequest, ServletResponse servletResponse) throws IllegalStateException {
            return null;
        }

        @Override
        public boolean isAsyncStarted() {
            return false;
        }

        @Override
        public boolean isAsyncSupported() {
            return false;
        }

        @Override
        public AsyncContext getAsyncContext() {
            return null;
        }

        @Override
        public DispatcherType getDispatcherType() {
            return DispatcherType.REQUEST;
        }

    }
}
