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

package org.glassfish.soteria.test;

import static org.glassfish.soteria.test.ShrinkWrap.mavenWar;
import static org.junit.Assert.assertTrue;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.shrinkwrap.api.Archive;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(Arquillian.class)
public class AppSecurityContextCallerPrincipalIT extends ArquillianBase {

    @Deployment(testable = false)
    public static Archive<?> createDeployment() {
        return mavenWar();
    }

    @Test
    public void testServletCustomPrincipal() {
        String resp = readFromServer("/servlet");
        assertTrue(isContainerPrincipalTypeInResponse(resp,false));
    }

    @Test
    public void testServletCustomCallerPrincipal() {
        String resp = readFromServer("/servlet?useCallerPrincipal");
        assertTrue(isContainerPrincipalTypeInResponse(resp,true));
    }

    @Test
    public void testEjbCustomPrincipal() {
        String resp = readFromServer("/ejb-servlet");
        assertTrue(isContainerPrincipalTypeInResponse(resp,false));
    }

    @Test
    public void testEjbCustomCallerPrincipal() {
        String resp = readFromServer("/ejb-servlet?useCallerPrincipal");
        assertTrue(isContainerPrincipalTypeInResponse(resp,true));
    }

    public boolean isContainerPrincipalTypeInResponse(String response, boolean isCallerPrincipalUsed) {
        String[] principalArray = response.split(",");
        String containerPrincipal = principalArray[0];
        String applicationPrincipal = principalArray[1];
        String inputApplicationPrincipal = isCallerPrincipalUsed ? "org.glassfish.soteria.test.CustomCallerPrincipal" : "org.glassfish.soteria.test.CustomPrincipal";
        boolean isContainerPricipalCorrect = containerPrincipal.contains("com.sun.enterprise.security.web.integration.WebPrincipal") ||
                containerPrincipal.contains("weblogic.security.principal.WLSUserImpl") ||
                containerPrincipal.contains("com.ibm.ws.security.authentication.principals.WSPrincipal") ||
                containerPrincipal.contains("org.jboss.security.SimplePrincipal") ||
                containerPrincipal.contains("org.jboss.security.SimpleGroup") ||
                containerPrincipal.contains("org.apache.tomee.catalina.TomcatSecurityService$TomcatUser") ||
                containerPrincipal.contains("jakarta.security.enterprise.CallerPrincipal") ||
                containerPrincipal.contains(inputApplicationPrincipal);
        boolean isApplicationPrincipalCorrect = applicationPrincipal.contains(inputApplicationPrincipal);
        return isContainerPricipalCorrect && isApplicationPrincipalCorrect;
    }
}
