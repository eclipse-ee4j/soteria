/*
 * Copyright (c) 2019 Arjan Tijms and/or affiliates and others.
 * All rights reserved.
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
package org.glassfish.soteria.cdi.spi.impl;

import org.glassfish.soteria.DefaultService;
import org.glassfish.soteria.cdi.spi.WebXmlLoginConfig;

/**
 * Default implementation of WebXmlLoginConfig using simple attributes to 
 * set the 4 attributes from the login config element in web.xml.
 * 
 * @author Arjan Tijms
 *
 */
public class DefaultWebXmlLoginConfig implements WebXmlLoginConfig, DefaultService {
    
    /**
     * The list &lt;auth-methodgt; element inside
     * &lt;login-config&gt;
     * 
     */
    private String authMethod;

    /**
     * The list &lt;realm-name&gt; element inside
     * &lt;login-config&gt;
     * 
     */
    private String realmName;
        
    /**
     * The list &lt;form-login-page&gt; element inside
     * &lt;form-login-config&gt;
     * 
     */
    private String formLoginPage;
    
    /**
     * The list &lt;form-error-page&gt; element inside
     * &lt;form-login-config&gt;
     * 
     */
    private String formErrorPage;
    
    @Override
    public String getAuthMethod() {
        return authMethod;
    }

    @Override
    public void setAuthMethod(String authMethod) {
        this.authMethod = authMethod;
    }

    @Override
    public String getRealmName() {
        return realmName;
    }

    @Override
    public void setRealmName(String realmName) {
        this.realmName = realmName;
    }

    @Override
    public String getFormLoginPage() {
        return formLoginPage;
    }

    @Override
    public void setFormLoginPage(String formLoginPage) {
        this.formLoginPage = formLoginPage;
    }

    @Override
    public String getFormErrorPage() {
        return formErrorPage;
    }

    @Override
    public void setFormErrorPage(String formErrorPage) {
        this.formErrorPage = formErrorPage;
    }

}
