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

import com.nimbusds.jwt.JWTClaimsSet;
import jakarta.security.enterprise.identitystore.openid.Claims;
import jakarta.security.enterprise.identitystore.openid.JwtClaims;

import java.text.ParseException;
import java.time.Instant;
import java.util.*;

class NimbusJwtClaims implements JwtClaims {
    private final JWTClaimsSet claimsSet;

    NimbusJwtClaims(JWTClaimsSet claimsSet) {
        this.claimsSet = claimsSet;
    }

    @Override
    public Optional<String> getStringClaim(String name) {
        try {
            return Optional.ofNullable(claimsSet.getStringClaim(name));
        } catch (ParseException e) {
            throw new IllegalArgumentException("Cannot parse "+name+" as string", e);
        }
    }

    @Override
    public Optional<Instant> getNumericDateClaim(String name) {
        try {
            return Optional.ofNullable(claimsSet.getDateClaim(name)).map(Date::toInstant);
        } catch (ParseException e) {
            throw new IllegalArgumentException("Cannot parse "+name+" as numeric date", e);
        }
    }

    @Override
    public List<String> getArrayStringClaim(String name) {
        Object audValue = claimsSet.getClaim(name);
        if (audValue == null) {
            return Collections.emptyList();
        }
        if (audValue instanceof String) {
            return Collections.singletonList((String)audValue);
        }
        try {
            return claimsSet.getStringListClaim(name);
        } catch (ParseException e) {
            throw new IllegalArgumentException("Cannot parse "+name+" as a string array", e);
        }
    }

    @Override
    public OptionalInt getIntClaim(String name) {
        Integer value;
        try {
            value = claimsSet.getIntegerClaim(name);
        } catch (ParseException e) {
            throw new IllegalArgumentException("Cannot parse "+name+" as number");
        }
        return value == null ? OptionalInt.empty() : OptionalInt.of(value);
    }

    @Override
    public OptionalLong getLongClaim(String name) {
        Long value;
        try {
            value = claimsSet.getLongClaim(name);
        } catch (ParseException e) {
            throw new IllegalArgumentException("Cannot parse "+name+" as number");
        }
        return value == null ? OptionalLong.empty() : OptionalLong.of(value);
    }

    @Override
    public OptionalDouble getDoubleClaim(String name) {
        Double value;
        try {
            value = claimsSet.getDoubleClaim(name);
        } catch (ParseException e) {
            throw new IllegalArgumentException("Cannot parse "+name+" as number");
        }
        return value == null ? OptionalDouble.empty() : OptionalDouble.of(value);
    }

    @Override
    public Optional<Claims> getNested(String name) {
        return Optional.empty();
    }

    @Override
    public String toString() {
        return claimsSet.toString();
    }

    static JwtClaims ifPresent(JWTClaimsSet claimsSet) {
        return claimsSet == null ? JwtClaims.NONE : new NimbusJwtClaims(claimsSet);
    }
}
