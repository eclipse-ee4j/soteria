/*
 * Copyright (c) 2026 Contributors to the Eclipse Foundation.
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
package org.glassfish.soteria.identitystores.jwt;

import jakarta.json.JsonArray;
import jakarta.json.JsonString;
import jakarta.json.JsonValue;
import jakarta.security.enterprise.CallerPrincipal;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static java.util.stream.Collectors.toSet;

/**
 *
 * @author Arjan Tijms
 */
public class JsonWebTokenImpl extends CallerPrincipal {

    private static final long serialVersionUID = 1L;

    private final Map<String, JsonValue> claims;

    public JsonWebTokenImpl(String callerName, Map<String, JsonValue> claims) {
        super(callerName);
        this.claims = claims;
    }

    public Map<String, JsonValue> claims() {
        return claims;
    }

    public JsonValue claimValue(String claimName) {
        return claims.get(claimName);
    }

    public Set<String> claimSet(String claimName) {
        JsonValue claimValue =  claims.get(claimName);
        if (claimValue == null) {
            return null;
        }

        if (claimValue instanceof JsonString jsonString) {
            return Collections.singleton((jsonString.getString()));
        }

        if (claimValue instanceof JsonArray jsonArray) {
            return new HashSet<>(jsonArray.getValuesAs(JsonString.class))
                    .stream().map(t -> t.getString())
                    .collect(toSet());
        }

        throw new IllegalStateException("");

    }

    public Set<String> getClaimNames() {
        if (claims.isEmpty()) {
            return null;
        }

        return claims.keySet();
    }


}
