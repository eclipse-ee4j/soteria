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
 */
package org.glassfish.soteria.test.client.defaulttests;

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.Dependent;
import jakarta.inject.Named;
import org.glassfish.soteria.test.server.OidcProvider;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

@Named
@Dependent
public class OpenIdConfig {

    public static final String OPEN_ID_CONFIG_PROPERTIES = "/openIdConfig.properties";
    public static final String REDIRECT_URI = "redirectURI";
    public static final String CLIENT_ID = "clientId";
    public static final String CLIENT_SECRET = "clientSecret";

    private Properties config;

    @PostConstruct
    public void init() {

        config = new Properties();

        InputStream configFile = OpenIdConfig.class.getResourceAsStream(OPEN_ID_CONFIG_PROPERTIES);
        if (configFile != null) {
            try {
                config.load(configFile);
            } catch (IOException e) {
                throw new IllegalStateException("Could not load OpenIdConfig");
            }
        }
    }

    public String getRedirectURI() {
        if (config.containsKey(REDIRECT_URI)) {
            return config.getProperty(REDIRECT_URI);
        }
        return "${baseURL}/Callback";
    }

    public String getClientId() {
        if (config.containsKey(CLIENT_ID)) {
            return config.getProperty(CLIENT_ID);
        }
        return OidcProvider.CLIENT_ID_VALUE;
    }

    public String getClientSecret() {
        if (config.containsKey(CLIENT_SECRET)) {
            return config.getProperty(CLIENT_SECRET);
        }
        return OidcProvider.CLIENT_SECRET_VALUE;
    }
}
