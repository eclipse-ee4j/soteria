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
package org.glassfish.soteria.openid;

import java.io.Serializable;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Class to hold state of OpenId
 * <p>
 * This is used in the authentication mechanism to both help prevent CSRF and to
 * pass data to the callback page.
 *
 * @author Gaurav Gupta
 * @author jonathan
 * @author Rudy De Busscher
 */
public class OpenIdState implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String state;

    /**
     * Creates a new instance with a random UUID as the state.
     */
    public OpenIdState() {
        state = UUID.randomUUID().toString();
    }

    /**
     * Creates a new instance set the state to what is in the constructor.
     * <p>
     * This can be used so that the callback page knows the originating page,
     * but is not used by the
     * {@link OpenIdAuthenticationMechanism} by default
     *
     * @param state the state to encapsulate
     */
    public OpenIdState(String state) {
        this.state = state;
    }

    /**
     * Factory method which creates an {@link OpenIdState} if the
     * state provided is not NULL or empty.
     * @param state the state to create an {@link OpenIdState} from
     * @return an {@link OpenIdState} if the state provided is not NULL or empty
     */
    public static Optional<OpenIdState> from(String state) {
        if (state == null || "".equals(state.trim())) {
            return Optional.empty();
        }
        return Optional.of(new OpenIdState(state.trim()));
    }

    /**
     * Gets the state
     *
     * @return the state
     */
    public String getValue() {
        return state;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof OpenIdState) {
            return Objects.equals(this.state, ((OpenIdState)obj).state);
        }
        return false;
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.state);
    }

    @Override
    public String toString() {
        return state;
    }

}
