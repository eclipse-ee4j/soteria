/*
 * Copyright (c) 2015, 2020 Oracle and/or its affiliates. All rights reserved.
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

package org.glassfish.soteria.identitystores;

import static jakarta.security.enterprise.identitystore.CredentialValidationResult.INVALID_RESULT;
import static jakarta.security.enterprise.identitystore.CredentialValidationResult.NOT_VALIDATED_RESULT;
import static java.util.Arrays.asList;
import static java.util.Arrays.stream;
import static java.util.Collections.emptySet;
import static java.util.Collections.unmodifiableSet;
import static java.util.stream.Collectors.toMap;

import jakarta.security.enterprise.CallerPrincipal;
import jakarta.security.enterprise.credential.Credential;
import jakarta.security.enterprise.credential.UsernamePasswordCredential;
import jakarta.security.enterprise.identitystore.CredentialValidationResult;
import jakarta.security.enterprise.identitystore.IdentityStore;
import jakarta.security.enterprise.identitystore.InMemoryIdentityStoreDefinition;
import jakarta.security.enterprise.identitystore.InMemoryIdentityStoreDefinition.Credentials;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class InMemoryIdentityStore implements IdentityStore {

    private final InMemoryIdentityStoreDefinition embeddedIdentityStoreDefinition;
    private final Map<String, InMemoryIdentityStoreDefinition.Credentials> callerToCredentials;
    private final Set<ValidationType> validationType;

    // CDI requires a no-arg constructor to be portable
    // It's only used to create the proxy
    protected InMemoryIdentityStore() {
        embeddedIdentityStoreDefinition = null;
        callerToCredentials = null;
        validationType = null;
    }

    public InMemoryIdentityStore(InMemoryIdentityStoreDefinition embeddedIdentityStoreDefinition) {

        this.embeddedIdentityStoreDefinition = embeddedIdentityStoreDefinition;
        callerToCredentials = stream(embeddedIdentityStoreDefinition.value()).collect(toMap(
                e -> e.callerName(),
                e -> e)
        );
        validationType = unmodifiableSet(new HashSet<>(asList(embeddedIdentityStoreDefinition.useFor())));
    }

    @Override
    public CredentialValidationResult validate(Credential credential) {
        if (credential instanceof UsernamePasswordCredential) {
            return validate((UsernamePasswordCredential) credential);
        }

        return NOT_VALIDATED_RESULT;
    }

    public CredentialValidationResult validate(UsernamePasswordCredential usernamePasswordCredential) {
        Credentials credentials = callerToCredentials.get(usernamePasswordCredential.getCaller());

        if (credentials != null && usernamePasswordCredential.getPassword().compareTo(credentials.password())) {
            return new CredentialValidationResult(
                new CallerPrincipal(credentials.callerName()),
                new HashSet<>(asList(credentials.groups()))
            );
        }

        return INVALID_RESULT;
    }

    @Override
    public Set<String> getCallerGroups(CredentialValidationResult validationResult) {
        Credentials credentials = callerToCredentials.get(validationResult.getCallerPrincipal().getName());

        return credentials != null ? new HashSet<>(asList(credentials.groups())) : emptySet();
    }

    public int priority() {
        return embeddedIdentityStoreDefinition.priority();
    }

    @Override
    public Set<ValidationType> validationTypes() {
        return validationType;
    }
}
