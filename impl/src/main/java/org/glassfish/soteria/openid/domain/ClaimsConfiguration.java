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

/**
 *
 * @author Gaurav Gupta
 * @author Rudy De Busscher
 */
public class ClaimsConfiguration {

    private String callerNameClaim;

    private String callerGroupsClaim;

    public String getCallerNameClaim() {
        return callerNameClaim;
    }

    public ClaimsConfiguration setCallerNameClaim(String callerNameClaim) {
        this.callerNameClaim = callerNameClaim;
        return this;
    }

    public String getCallerGroupsClaim() {
        return callerGroupsClaim;
    }

    public ClaimsConfiguration setCallerGroupsClaim(String callerGroupsClaim) {
        this.callerGroupsClaim = callerGroupsClaim;
        return this;
    }

    @Override
    public String toString() {
        return "ClaimsConfiguration{" + "callerNameClaim=" + callerNameClaim + ", callerGroupsClaim=" + callerGroupsClaim + '}';
    }

}
