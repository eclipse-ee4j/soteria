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
package org.glassfish.soteria.openid.domain;


import java.util.Arrays;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

/**
 * OpenId Connect client configuration.
 *
 * @author Gaurav Gupta
 * @author Rudy De Busscher
 */
public class OpenIdConfiguration {

    private String clientId;
    private char[] clientSecret;
    private String redirectURI;
    private String scopes;
    private String responseType;
    private String responseMode;
    private Map<String, String> extraParameters;
    private String prompt;
    private String display;
    private boolean useNonce;
    private boolean useSession;
    private int jwksConnectTimeout;
    private int jwksReadTimeout;
    private OpenIdProviderData providerMetadata;
    private ClaimsConfiguration claimsConfiguration;
    private LogoutConfiguration logoutConfiguration;
    private boolean tokenAutoRefresh;
    private int tokenMinValidity;

    static final String BASE_URL_EXPRESSION = "${baseURL}";

    public String getClientId() {
        return clientId;
    }

    public OpenIdConfiguration setClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public char[] getClientSecret() {
        return clientSecret;
    }

    public OpenIdConfiguration setClientSecret(char[] clientSecret) {
        this.clientSecret = clientSecret;
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

    public String getRedirectURI() {
        return redirectURI;
    }

    public OpenIdConfiguration setRedirectURI(String redirectURI) {
        this.redirectURI = redirectURI;
        return this;
    }

    public String getScopes() {
        return scopes;
    }

    public OpenIdConfiguration setScopes(String scopes) {
        this.scopes = scopes;
        return this;
    }

    public String getResponseType() {
        return responseType;
    }

    public OpenIdConfiguration setResponseType(String responseType) {
        this.responseType = responseType;
        return this;
    }

    public String getResponseMode() {
        return responseMode;
    }

    public OpenIdConfiguration setResponseMode(String responseMode) {
        this.responseMode = responseMode;
        return this;
    }

    public Map<String, String> getExtraParameters() {
        return extraParameters;
    }

    public OpenIdConfiguration setExtraParameters(Map<String, String> extraParameters) {
        this.extraParameters = extraParameters;
        return this;
    }

    public String getPrompt() {
        return prompt;
    }

    public OpenIdConfiguration setPrompt(String prompt) {
        this.prompt = prompt;
        return this;
    }

    public String getDisplay() {
        return display;
    }

    public OpenIdConfiguration setDisplay(String display) {
        this.display = display;
        return this;
    }

    public boolean isUseNonce() {
        return useNonce;
    }

    public OpenIdConfiguration setUseNonce(boolean useNonce) {
        this.useNonce = useNonce;
        return this;
    }

    public boolean isUseSession() {
        return useSession;
    }

    public int getJwksConnectTimeout() {
        return jwksConnectTimeout;
    }

    public OpenIdConfiguration setJwksConnectTimeout(int jwksConnectTimeout) {
        this.jwksConnectTimeout = jwksConnectTimeout;
        return this;
    }

    public int getJwksReadTimeout() {
        return jwksReadTimeout;
    }

    public OpenIdConfiguration setJwksReadTimeout(int jwksReadTimeout) {
        this.jwksReadTimeout = jwksReadTimeout;
        return this;
    }

    public OpenIdConfiguration setUseSession(boolean useSession) {
        this.useSession = useSession;
        return this;
    }

    public OpenIdProviderData getProviderMetadata() {
        return providerMetadata;
    }

    public OpenIdConfiguration setProviderMetadata(OpenIdProviderData providerMetadata) {
        this.providerMetadata = providerMetadata;
        return this;
    }

    public ClaimsConfiguration getClaimsConfiguration() {
        return claimsConfiguration;
    }

    public OpenIdConfiguration setClaimsConfiguration(ClaimsConfiguration claimsConfiguration) {
        this.claimsConfiguration = claimsConfiguration;
        return this;
    }

    public LogoutConfiguration getLogoutConfiguration() {
        return logoutConfiguration;
    }

    public OpenIdConfiguration setLogoutConfiguration(LogoutConfiguration logoutConfiguration) {
        this.logoutConfiguration = logoutConfiguration;
        return this;
    }

    public boolean isTokenAutoRefresh() {
        return tokenAutoRefresh;
    }

    public OpenIdConfiguration setTokenAutoRefresh(boolean tokenAutoRefresh) {
        this.tokenAutoRefresh = tokenAutoRefresh;
        return this;
    }

    public int getTokenMinValidity() {
        return tokenMinValidity;
    }

    public OpenIdConfiguration setTokenMinValidity(int tokenMinValidity) {
        this.tokenMinValidity = tokenMinValidity;
        return this;
    }

    @Override
    public String toString() {
        return OpenIdConfiguration.class.getSimpleName()
                + "{"
                + "clientID=" + clientId
                + ", clientSecret=" + Arrays.toString(clientSecret)
                + ", redirectURI=" + redirectURI
                + ", scopes=" + scopes
                + ", responseType=" + responseType
                + ", responseMode=" + responseMode
                + ", extraParameters=" + extraParameters
                + ", prompt=" + prompt
                + ", display=" + display
                + ", useNonce=" + useNonce
                + ", useSession=" + useSession
                + ", providerMetadata=" + providerMetadata
                + ", claimsConfiguration=" + claimsConfiguration
                + ", tokenAutoRefresh=" + tokenAutoRefresh
                + ", tokenMinValidity=" + tokenMinValidity
                + '}';
    }

}
