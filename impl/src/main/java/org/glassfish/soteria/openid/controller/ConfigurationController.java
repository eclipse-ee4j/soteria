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
package org.glassfish.soteria.openid.controller;


import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.context.RequestScoped;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Inject;
import jakarta.json.JsonObject;
import jakarta.json.JsonString;
import jakarta.security.enterprise.identitystore.*;
import jakarta.security.enterprise.identitystore.openid.OpenIdConstant;
import org.glassfish.soteria.Utils;
import org.glassfish.soteria.openid.domain.ClaimsConfiguration;
import org.glassfish.soteria.openid.domain.LogoutConfiguration;
import org.glassfish.soteria.openid.domain.OpenIdConfiguration;
import org.glassfish.soteria.openid.domain.OpenIdProviderData;

import java.io.Serializable;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.stream.Collectors;

import static java.util.stream.Collectors.joining;
import static org.glassfish.soteria.cdi.AnnotationELPProcessor.evalImmediate;

/**
 * Build and validate the OpenId Connect client configuration.
 *
 * @author Gaurav Gupta
 * @author Rudy De Busscher
 */
@ApplicationScoped
public class ConfigurationController implements Serializable {

    @Inject
    private ProviderMetadataController providerMetadataController;

    private static final String SPACE_SEPARATOR = " ";

    private volatile transient LastBuiltConfig lastBuiltConfig;

    @Produces
    @RequestScoped
    public OpenIdConfiguration produceConfiguration(OpenIdAuthenticationDefinition definition) {
        if (lastBuiltConfig == null) {
            lastBuiltConfig = new LastBuiltConfig(null, null);
        }
        OpenIdConfiguration cached = lastBuiltConfig.cachedConfiguration(definition);
        if (cached != null) {
            return cached;
        }
        OpenIdConfiguration config = buildConfig(definition);
        lastBuiltConfig = new LastBuiltConfig(definition, config);
        return config;
    }

    /**
     * Creates the {@link OpenIdConfiguration} using the properties as defined
     * in an {@link OpenIdAuthenticationDefinition} annotation or using MP
     * Config source. MP Config source value take precedence over
     * {@link OpenIdAuthenticationDefinition} annotation value.
     *
     * @param definition
     * @return
     */
    public OpenIdConfiguration buildConfig(OpenIdAuthenticationDefinition definition) {

        String providerURI;
        JsonObject providerDocument;
        String authorizationEndpoint;
        String tokenEndpoint;
        String userinfoEndpoint;
        String endSessionEndpoint;
        String jwksURI;
        URL jwksURL;
        String issuer;

        providerURI = evalImmediate(definition.providerURI());
        OpenIdProviderMetadata providerMetadata = definition.providerMetadata();
        providerDocument = providerMetadataController.getDocument(providerURI);

        if (Utils.isEmpty(providerMetadata.authorizationEndpoint()) && providerDocument.containsKey(OpenIdConstant.AUTHORIZATION_ENDPOINT)) {
            authorizationEndpoint = evalImmediate(providerDocument.getString(OpenIdConstant.AUTHORIZATION_ENDPOINT));
        } else {
            authorizationEndpoint = evalImmediate(providerMetadata.authorizationEndpoint());
        }
        if (Utils.isEmpty(providerMetadata.tokenEndpoint()) && providerDocument.containsKey(OpenIdConstant.TOKEN_ENDPOINT)) {
            tokenEndpoint = evalImmediate(providerDocument.getString(OpenIdConstant.TOKEN_ENDPOINT));
        } else {
            tokenEndpoint = evalImmediate(providerMetadata.tokenEndpoint());
        }
        if (Utils.isEmpty(providerMetadata.userinfoEndpoint()) && providerDocument.containsKey(OpenIdConstant.USERINFO_ENDPOINT)) {
            userinfoEndpoint = evalImmediate(providerDocument.getString(OpenIdConstant.USERINFO_ENDPOINT));
        } else {
            userinfoEndpoint = evalImmediate(providerMetadata.userinfoEndpoint());
        }
        if (Utils.isEmpty(providerMetadata.endSessionEndpoint()) && providerDocument.containsKey(OpenIdConstant.END_SESSION_ENDPOINT)) {
            endSessionEndpoint = evalImmediate(providerDocument.getString(OpenIdConstant.END_SESSION_ENDPOINT));
        } else {
            endSessionEndpoint = evalImmediate(providerMetadata.endSessionEndpoint());
        }
        if (Utils.isEmpty(providerMetadata.jwksURI()) && providerDocument.containsKey(OpenIdConstant.JWKS_URI)) {
            jwksURI = evalImmediate(providerDocument.getString(OpenIdConstant.JWKS_URI));
        } else {
            jwksURI = evalImmediate(providerMetadata.jwksURI());
        }
        try {
            jwksURL = new URL(jwksURI);
        } catch (MalformedURLException ex) {
            throw new IllegalStateException("jwksURI is invalid", ex);
        }

        if (Utils.isEmpty(providerMetadata.issuer()) && providerDocument.containsKey(OpenIdConstant.ISSUER)) {
            issuer = evalImmediate(providerDocument.getString(OpenIdConstant.ISSUER));
        } else {
            issuer = evalImmediate(providerMetadata.issuer());
        }

        List<String> supportedResponseTypes = null;
        if (providerDocument.containsKey(OpenIdConstant.RESPONSE_TYPES_SUPPORTED)) {
            supportedResponseTypes = providerDocument.getJsonArray(OpenIdConstant.RESPONSE_TYPES_SUPPORTED).getValuesAs(JsonString::getString);
        }
        if (Utils.isEmpty(supportedResponseTypes)) {
            String value = evalImmediate(providerMetadata.responseTypeSupported());
            supportedResponseTypes = Arrays.stream(value.split(","))
                    .map(String::trim)
                    .collect(Collectors.toList());
        }

        List<String> supportedIdTokenSigningAlgorithms = null;
        if (providerDocument.containsKey(OpenIdConstant.ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED)) {
            supportedIdTokenSigningAlgorithms = providerDocument.getJsonArray(OpenIdConstant.ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED).getValuesAs(JsonString::getString);
        }
        if (Utils.isEmpty(supportedIdTokenSigningAlgorithms)) {
            String value = evalImmediate(providerMetadata.idTokenSigningAlgorithmsSupported());
            supportedIdTokenSigningAlgorithms = Arrays.stream(value.split(","))
                    .map(String::trim)
                    .collect(Collectors.toList());
        }

        List<String> supportedSubjectTypes = null;
        if (providerDocument.containsKey(OpenIdConstant.SUBJECT_TYPES_SUPPORTED)) {
            supportedSubjectTypes = providerDocument.getJsonArray(OpenIdConstant.SUBJECT_TYPES_SUPPORTED).getValuesAs(JsonString::getString);
        }
        if (Utils.isEmpty(supportedSubjectTypes)) {
            String value = evalImmediate(providerMetadata.subjectTypeSupported());
            supportedSubjectTypes = Arrays.stream(value.split(","))
                    .map(String::trim)
                    .collect(Collectors.toList());
        }


        String clientId = evalImmediate(definition.clientId());
        char[] clientSecret = evalImmediate(definition.clientSecret()).toCharArray();
        String redirectURI = evalImmediate(definition.redirectURI());

        String scopes = String.join(SPACE_SEPARATOR, definition.scope());
        scopes = evalImmediate(definition.scopeExpression(), scopes);
        if (Utils.isEmpty(scopes)) {
            scopes = OpenIdConstant.OPENID_SCOPE;
        } else if (!scopes.contains(OpenIdConstant.OPENID_SCOPE)) {
            scopes = OpenIdConstant.OPENID_SCOPE + SPACE_SEPARATOR + scopes;
        }

        String responseType = evalImmediate(definition.responseType());
        responseType
                = Arrays.stream(responseType.trim().split(SPACE_SEPARATOR))
                .map(String::toLowerCase)
                .sorted()
                .collect(joining(SPACE_SEPARATOR));

        String responseMode = evalImmediate(definition.responseMode());

        String display = definition.display().toString().toLowerCase();
        display = evalImmediate(display);

        String prompt = Arrays.stream(definition.prompt())
                .map(PromptType::toString)
                .map(String::toLowerCase)
                .collect(joining(SPACE_SEPARATOR));
        prompt = evalImmediate(definition.promptExpression(), prompt);

        Map<String, String> extraParameters = new HashMap<>();
        for (String extraParameter : definition.extraParameters()) {
            String[] parts = extraParameter.split("=");
            String key = parts[0];
            String value = parts[1];
            extraParameters.put(key, value);
        }

        boolean nonce = evalImmediate(definition.useNonceExpression(), definition.useNonce());
        boolean session = evalImmediate(definition.useSessionExpression(), definition.useSession());

        int jwksConnectTimeout = evalImmediate(definition.jwksConnectTimeoutExpression(), definition.jwksConnectTimeout());
        int jwksReadTimeout = evalImmediate(definition.jwksReadTimeoutExpression(), definition.jwksReadTimeout());

        String callerNameClaim = evalImmediate(definition.claimsDefinition().callerNameClaim());
        String callerGroupsClaim = evalImmediate(definition.claimsDefinition().callerGroupsClaim());

        boolean notifyProvider = evalImmediate(definition.logout().notifyProviderExpression(), definition.logout().notifyProvider());
        String logoutRedirectURI = evalImmediate(definition.logout().redirectURI());
        boolean accessTokenExpiry = evalImmediate(definition.logout().accessTokenExpiryExpression(), definition.logout().accessTokenExpiry());
        boolean identityTokenExpiry = evalImmediate(definition.logout().identityTokenExpiryExpression(), definition.logout().identityTokenExpiry());

        boolean tokenAutoRefresh = evalImmediate(definition.tokenAutoRefreshExpression(), definition.tokenAutoRefresh());
        int tokenMinValidity = evalImmediate(definition.tokenMinValidityExpression(), definition.tokenMinValidity());

        OpenIdConfiguration configuration = new OpenIdConfiguration()
                .setProviderMetadata(
                        new OpenIdProviderData(providerDocument)
                                .setAuthorizationEndpoint(authorizationEndpoint)
                                .setTokenEndpoint(tokenEndpoint)
                                .setUserinfoEndpoint(userinfoEndpoint)
                                .setEndSessionEndpoint(endSessionEndpoint)
                                .setJwksURL(jwksURL)
                                .setIssuer(issuer)
                                .setResponseTypeSupported(new HashSet<>(supportedResponseTypes))
                                .setIdTokenSigningAlgorithmsSupported(new HashSet<>(supportedIdTokenSigningAlgorithms))
                                .setSubjectTypesSupported(new HashSet<>(supportedSubjectTypes))
                )
                .setClaimsConfiguration(
                        new ClaimsConfiguration()
                                .setCallerNameClaim(callerNameClaim)
                                .setCallerGroupsClaim(callerGroupsClaim)
                ).setLogoutConfiguration(
                        new LogoutConfiguration()
                                .setNotifyProvider(notifyProvider)
                                .setRedirectURI(logoutRedirectURI)
                                .setAccessTokenExpiry(accessTokenExpiry)
                                .setIdentityTokenExpiry(identityTokenExpiry)
                )
                .setClientId(clientId)
                .setClientSecret(clientSecret)
                .setRedirectURI(redirectURI)
                .setScopes(scopes)
                .setResponseType(responseType)
                .setResponseMode(responseMode)
                .setExtraParameters(extraParameters)
                .setPrompt(prompt)
                .setDisplay(display)
                .setUseNonce(nonce)
                .setUseSession(session)
                .setJwksConnectTimeout(jwksConnectTimeout)
                .setJwksReadTimeout(jwksReadTimeout)
                .setTokenAutoRefresh(tokenAutoRefresh)
                .setTokenMinValidity(tokenMinValidity);

        validateConfiguration(configuration);

        return configuration;
    }

    /**
     * Validate the properties of the OpenId Connect Client and Provider
     * Metadata
     */
    private void validateConfiguration(OpenIdConfiguration configuration) {
        List<String> errorMessages = new ArrayList<>();
        errorMessages.addAll(validateProviderMetadata(configuration));
        errorMessages.addAll(validateClientConfiguration(configuration));

        if (!errorMessages.isEmpty()) {
            throw new IllegalStateException(errorMessages.toString());
        }
    }

    private List<String> validateProviderMetadata(OpenIdConfiguration configuration) {
        List<String> errorMessages = new ArrayList<>();

        if (Utils.isEmpty(configuration.getProviderMetadata().getIssuerURI())) {
            errorMessages.add("issuer metadata is mandatory");
        }
        if (Utils.isEmpty(configuration.getProviderMetadata().getAuthorizationEndpoint())) {
            errorMessages.add("authorization_endpoint metadata is mandatory");
        }
        if (Utils.isEmpty(configuration.getProviderMetadata().getTokenEndpoint())) {
            errorMessages.add("token_endpoint metadata is mandatory");
        }
        if (configuration.getProviderMetadata().getJwksURL() == null) {
            errorMessages.add("jwks_uri metadata is mandatory");
        }
        if (configuration.getProviderMetadata().getResponseTypeSupported().isEmpty()) {
            errorMessages.add("response_types_supported metadata is mandatory");
        }
        if (configuration.getProviderMetadata().getSubjectTypesSupported().isEmpty()) {
            errorMessages.add("subject_types_supported metadata is mandatory");
        }
        if (configuration.getProviderMetadata().getIdTokenSigningAlgorithmsSupported().isEmpty()) {
            errorMessages.add("id_token_signing_alg_values_supported metadata is mandatory");
        }
        return errorMessages;
    }

    private List<String> validateClientConfiguration(OpenIdConfiguration configuration) {
        List<String> errorMessages = new ArrayList<>();

        if (Utils.isEmpty(configuration.getClientId())) {
            errorMessages.add("client_id request parameter is mandatory");
        }
        if (Utils.isEmpty(configuration.getRedirectURI())) {
            errorMessages.add("redirect_uri request parameter is mandatory");
        }
        if (configuration.getJwksConnectTimeout() <= 0) {
            errorMessages.add("jwksConnectTimeout value is not valid");
        }
        if (configuration.getJwksReadTimeout() <= 0) {
            errorMessages.add("jwksReadTimeout value is not valid");
        }

        if (Utils.isEmpty(configuration.getResponseType())) {
            errorMessages.add("The response type must contain at least one value");
        } else if (!configuration.getProviderMetadata().getResponseTypeSupported().contains(configuration.getResponseType())
                && !OpenIdConstant.AUTHORIZATION_CODE_FLOW_TYPES.contains(configuration.getResponseType())
                && !OpenIdConstant.IMPLICIT_FLOW_TYPES.contains(configuration.getResponseType())
                && !OpenIdConstant.HYBRID_FLOW_TYPES.contains(configuration.getResponseType())) {
            errorMessages.add("Unsupported OpenID Connect response type value : " + configuration.getResponseType());
        }

        Set<String> supportedScopes = configuration.getProviderMetadata().getScopesSupported();
        if (!supportedScopes.isEmpty()) {
            for (String scope : configuration.getScopes().split(SPACE_SEPARATOR)) {
                if (!supportedScopes.contains(scope)) {
                    errorMessages.add(String.format(
                            "%s scope is not supported by %s OpenId Connect provider",
                            scope,
                            configuration.getProviderMetadata().getIssuerURI())
                    );
                }
            }
        }

        return errorMessages;
    }

    static class LastBuiltConfig {
        private final OpenIdAuthenticationDefinition definition;
        private final OpenIdConfiguration configuration;

        public LastBuiltConfig(OpenIdAuthenticationDefinition definition, OpenIdConfiguration configuration) {
            this.definition = definition;
            this.configuration = configuration;
        }

        OpenIdConfiguration cachedConfiguration(OpenIdAuthenticationDefinition definition) {
            if (this.definition != null && this.definition.equals(definition)) {
                return configuration;
            }
            return null;
        }
    }

}
