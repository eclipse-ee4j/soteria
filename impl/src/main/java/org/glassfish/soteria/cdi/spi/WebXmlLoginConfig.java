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
package org.glassfish.soteria.cdi.spi;

import org.glassfish.soteria.cdi.spi.impl.DefaultWebXmlLoginConfig;

/**
 * Implementations of this interface can be used by a servlet container to pass the login config
 * from web.xml to Soteria.
 * 
 * <p>
 * This SPI is needed since there is no portable way for CDI extensions to read web.xml. Soteria
 * would need this information when its CDI extension runs.
 * 
 * <p>
 * Soteria needs access to the login config from web.xml to satisfy the option allowed and detailed
 * by Jakarta Security to use the Jakarta EE BASIC and FORM authentication mechanisms to fullfill
 * the Servlet spec requirements for those mechanisms.
 * 
 * <p>
 * If the configuration is readily available before the CDI implementation is initialized, containers
 * can opt to use the default implementation {@link DefaultWebXmlLoginConfig}.
 * 
 * @author Arjan Tijms
 *
 */
public interface WebXmlLoginConfig {
    
    String getAuthMethod();

    void setAuthMethod(String authMethod);

    String getRealmName();

    void setRealmName(String realmName);

    String getFormLoginPage();

    void setFormLoginPage(String formLoginPage);

    String getFormErrorPage();

    void setFormErrorPage(String formErrorPage);

}
