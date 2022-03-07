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

import static jakarta.ws.rs.core.MediaType.APPLICATION_JSON;
import static java.util.Objects.isNull;
import static org.glassfish.soteria.Utils.isEmpty;

import java.io.StringReader;
import java.util.HashMap;
import java.util.Map;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;

/**
 * Manages the OpenId Connect Provider metadata
 *
 * @author Gaurav Gupta
 * @author Rudy De Busscher
 */
@ApplicationScoped
public class ProviderMetadataController {

    private static final String WELL_KNOWN_PREFIX = "/.well-known/openid-configuration";

    private final Map<String, JsonObject> providerDocuments = new HashMap<>();

    /**
     * Request to the provider
     * https://example.com/.well-known/openid-configuration to obtain its
     * Configuration information / document which includes all necessary
     * endpoints (authorization_endpoint, token_endpoint, userinfo_endpoint,
     * revocation_endpoint etc), scopes, Claims, and public key location
     * information (jwks_uri)
     *
     * @param providerURI the OpenID Provider's uri
     * @return the OpenID Provider's configuration information / document
     *
     */
    public JsonObject getDocument(String providerURI) {
        if (isNull(providerDocuments.get(providerURI))) {
            if (isEmpty(providerURI)) {
                // Empty providerURI so all data needs to be defined within OpenIdProviderMetadata structure
                providerDocuments.put(providerURI, Json.createObjectBuilder().build());
            } else {
                if (providerURI.endsWith("/")) {
                    providerURI = providerURI.substring(0, providerURI.length() - 1);
                }

                // Append WELL_KNOWN_PREFIX to the URL
                if (!providerURI.endsWith(WELL_KNOWN_PREFIX)) {
                    providerURI = providerURI + WELL_KNOWN_PREFIX;
                }

                // Call
                Client client = ClientBuilder.newClient();
                WebTarget target = client.target(providerURI);
                Response response = target.request()
                        .accept(APPLICATION_JSON)
                        .get();

                if (response.getStatus() == Status.OK.getStatusCode()) {
                    // Get back the result of the REST request
                    String responseBody = response.readEntity(String.class);
                    try (JsonReader reader = Json.createReader(new StringReader(responseBody))) {
                        JsonObject responseObject = reader.readObject();
                        providerDocuments.put(providerURI, responseObject);
                    }
                } else {
                    throw new IllegalStateException(String.format(
                            "Unable to retrieve OpenID Provider's [%s] configuration document, HTTP respons code : [%s] ",
                            providerURI,
                            response.getStatus()
                    ));
                }
            }
        }

        return providerDocuments.get(providerURI);
    }

}
