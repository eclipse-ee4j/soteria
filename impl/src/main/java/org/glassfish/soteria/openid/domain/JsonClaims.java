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


import jakarta.json.JsonNumber;
import jakarta.json.JsonObject;
import jakarta.json.JsonString;
import jakarta.json.JsonValue;
import jakarta.security.enterprise.identitystore.openid.Claims;
import jakarta.security.enterprise.identitystore.openid.OpenIdClaims;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

class JsonClaims implements OpenIdClaims {
    private final JsonObject claims;

    JsonClaims(JsonObject claims) {
        this.claims = claims;
    }

    @Override
    public Optional<String> getStringClaim(String name) {
        return Optional.ofNullable(claims.getString(name, null));
    }

    @Override
    public Optional<Instant> getNumericDateClaim(String name) {
        return Optional.ofNullable(getNumber(name))
                .map(n -> Instant.ofEpochSecond(n.longValue()));
    }

    @Override
    public List<String> getArrayStringClaim(String name) {
        JsonValue value = claims.get(name);
        if (value == null) {
            return Collections.emptyList();
        }
        if (value.getValueType() == JsonValue.ValueType.ARRAY) {
            return value.asJsonArray().stream().map(this::getStringValue).collect(Collectors.toList());
        }
        return Collections.singletonList(getStringValue(value));
    }

    private String getStringValue(JsonValue value) {
        switch (value.getValueType()) {
            case STRING:
                return ((JsonString) value).getString();
            case TRUE:
                return "true";
            case FALSE:
                return "false";
            case NUMBER:
                return ((JsonNumber) value).numberValue().toString();
            default:
                throw new IllegalArgumentException("Cannot handle nested JSON value in a claim:" + value);
        }
    }

    private JsonNumber getNumber(String name) {
        try {
            return claims.getJsonNumber(name);
        } catch (ClassCastException cce) {
            throw new IllegalArgumentException("Cannot interpret " + name + " as number", cce);
        }
    }

    @Override
    public OptionalInt getIntClaim(String name) {
        JsonNumber value = getNumber(name);
        return value == null ? OptionalInt.empty() : OptionalInt.of(value.intValue());
    }

    @Override
    public OptionalLong getLongClaim(String name) {
        JsonNumber value = getNumber(name);
        return value == null ? OptionalLong.empty() : OptionalLong.of(value.longValue());
    }

    @Override
    public OptionalDouble getDoubleClaim(String name) {
        JsonNumber value = getNumber(name);
        return value == null ? OptionalDouble.empty() : OptionalDouble.of(value.doubleValue());
    }

    @Override
    public Optional<Claims> getNested(String claimName) {
        return Optional.ofNullable(claims.getJsonObject(claimName)).map(JsonClaims::new);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName()
                + "{"
                + "subject=" + getSubject()
                + ",name=" + getName()
                + ", familyName=" + getFamilyName()
                + ", givenName=" + getGivenName()
                + ", middleName=" + getMiddleName()
                + ", nickname=" + getNickname()
                + ", preferredUsername=" + getPreferredUsername()
                + ", profile=" + getProfile()
                + ", picture=" + getPicture()
                + ", website=" + getWebsite()
                + ", gender=" + getGender()
                + ", birthdate=" + getBirthdate()
                + ", zoneinfo=" + getZoneinfo()
                + ", locale=" + getLocale()
                + ", updatedAt=" + getUpdatedAt()
                + ", email=" + getEmail()
                + ", emailVerified=" + getEmailVerified()
                + ", address=" + getAddress()
                + ", phoneNumber=" + getPhoneNumber()
                + ", phoneNumberVerified=" + getPhoneNumberVerified()
                + '}';

    }
}
