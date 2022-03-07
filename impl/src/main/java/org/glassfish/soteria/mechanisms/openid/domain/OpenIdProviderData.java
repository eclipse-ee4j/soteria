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

import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonString;
import java.net.URL;
import java.util.Set;

import static jakarta.security.enterprise.identitystore.openid.OpenIdConstant.*;
import static java.util.Collections.emptySet;
import static java.util.Objects.isNull;
import static java.util.stream.Collectors.toSet;
import static jakarta.json.JsonValue.ValueType.STRING;

/**
 * OpenId Connect Provider information.
 *
 * @author Gaurav Gupta
 * @author Rudy De Busscher
 */
public class OpenIdProviderData {

    private final JsonObject document;
    private String issuerURI;
    private String authorizationEndpoint;
    private String tokenEndpoint;
    private String userinfoEndpoint;
    private String endSessionEndpoint;
    private URL jwksURL;
    private final Set<String> scopesSupported;
    private  Set<String> responseTypeSupported;
    private  Set<String> idTokenSigningAlgorithmsSupported;
    private  Set<String> subjectTypesSupported;

    public OpenIdProviderData(JsonObject document) {
        this.document = document;
        this.scopesSupported = getValues(SCOPES_SUPPORTED);
    }

    public String getIssuerURI() {
        return issuerURI;
    }

    public OpenIdProviderData setIssuer(String issuerURI) {
        this.issuerURI = issuerURI;
        return this;
    }

    public String getAuthorizationEndpoint() {
        return authorizationEndpoint;
    }

    public OpenIdProviderData setAuthorizationEndpoint(String authorizationEndpoint) {
        this.authorizationEndpoint = authorizationEndpoint;
        return this;
    }

    public String getTokenEndpoint() {
        return tokenEndpoint;
    }

    public OpenIdProviderData setTokenEndpoint(String tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
        return this;
    }

    public String getUserinfoEndpoint() {
        return userinfoEndpoint;
    }

    public OpenIdProviderData setUserinfoEndpoint(String userinfoEndpoint) {
        this.userinfoEndpoint = userinfoEndpoint;
        return this;
    }

    public String getEndSessionEndpoint() {
        return endSessionEndpoint;
    }

    public OpenIdProviderData setEndSessionEndpoint(String endSessionEndpoint) {
        this.endSessionEndpoint = endSessionEndpoint;
        return this;
    }

    public URL getJwksURL() {
        return jwksURL;
    }

    public OpenIdProviderData setJwksURL(URL jwksURL) {
        this.jwksURL = jwksURL;
        return this;
    }

    public JsonObject getDocument() {
        return document;
    }

    public Set<String> getScopesSupported() {
        return scopesSupported;
    }

    public Set<String> getResponseTypeSupported() {
        return responseTypeSupported;
    }

    public OpenIdProviderData setResponseTypeSupported(Set<String> responseTypeSupported) {
        this.responseTypeSupported = responseTypeSupported;
        return this;
    }

    public Set<String> getSubjectTypesSupported() {
        return subjectTypesSupported;
    }

    public OpenIdProviderData setSubjectTypesSupported(Set<String> subjectTypesSupported) {
        this.subjectTypesSupported = subjectTypesSupported;
        return this;
    }

    public Set<String> getIdTokenSigningAlgorithmsSupported() {
        return idTokenSigningAlgorithmsSupported;
    }

    public OpenIdProviderData setIdTokenSigningAlgorithmsSupported(Set<String> idTokenSigningAlgorithmsSupported) {
        this.idTokenSigningAlgorithmsSupported = idTokenSigningAlgorithmsSupported;
        return this;
    }

    private Set<String> getValues(String key) {
        JsonArray jsonArray = document.getJsonArray(key);
        if (isNull(jsonArray)) {
            return emptySet();
        } else {
            return jsonArray
                    .stream()
                    .filter(element -> element.getValueType() == STRING)
                    .map(element -> (JsonString) element)
                    .map(JsonString::getString)
                    .collect(toSet());
        }
    }

    @Override
    public String toString() {
        return OpenIdProviderData.class.getSimpleName()
                + "{"
                + "issuerURI=" + issuerURI
                + ", authorizationEndpoint=" + authorizationEndpoint
                + ", tokenEndpoint=" + tokenEndpoint
                + ", userinfoEndpoint=" + userinfoEndpoint
                + ", jwksURI=" + jwksURL
                + '}';
    }

}
