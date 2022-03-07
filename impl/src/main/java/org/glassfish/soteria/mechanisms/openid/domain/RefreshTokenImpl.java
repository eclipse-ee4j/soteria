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


import jakarta.security.enterprise.identitystore.openid.RefreshToken;

/**
 *
 * @author Gaurav Gupta
 * @author Rudy De Busscher
 */
public class RefreshTokenImpl implements RefreshToken {

    private final String token;

    public RefreshTokenImpl(String token) {
        this.token = token;
    }

    @Override
    public String getToken() {
        return token;
    }

    @Override
    public String toString() {
        return token;
    }

}
