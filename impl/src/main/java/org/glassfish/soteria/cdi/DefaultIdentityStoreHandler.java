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

package org.glassfish.soteria.cdi;

import jakarta.security.enterprise.CallerPrincipal;
import jakarta.security.enterprise.credential.Credential;
import jakarta.security.enterprise.identitystore.CredentialValidationResult;
import jakarta.security.enterprise.identitystore.IdentityStore;
import jakarta.security.enterprise.identitystore.IdentityStoreHandler;

import static java.util.Comparator.comparing;
import static java.util.stream.Collectors.toList;
import static jakarta.security.enterprise.identitystore.CredentialValidationResult.INVALID_RESULT;
import static jakarta.security.enterprise.identitystore.CredentialValidationResult.NOT_VALIDATED_RESULT;
import static jakarta.security.enterprise.identitystore.CredentialValidationResult.Status.VALID;
import static jakarta.security.enterprise.identitystore.CredentialValidationResult.Status.INVALID;
import static jakarta.security.enterprise.identitystore.IdentityStore.ValidationType.PROVIDE_GROUPS;
import static jakarta.security.enterprise.identitystore.IdentityStore.ValidationType.VALIDATE;
import static org.glassfish.soteria.cdi.CdiUtils.getBeanReferencesByType;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.HashSet;
import java.util.List;
import java.util.Set;


/**
 *
 */
public class DefaultIdentityStoreHandler implements IdentityStoreHandler {

    private List<IdentityStore> authenticationIdentityStores;
    private List<IdentityStore> authorizationIdentityStores;

    public void init() {
    	List<IdentityStore> identityStores = getBeanReferencesByType(IdentityStore.class, false);

    	authenticationIdentityStores = identityStores.stream()
    												 .filter(i -> i.validationTypes().contains(VALIDATE))
    												 .sorted(comparing(IdentityStore::priority))
    												 .collect(toList());

    	authorizationIdentityStores = identityStores.stream()
				 									.filter(i -> i.validationTypes().contains(PROVIDE_GROUPS) && !i.validationTypes().contains(VALIDATE))
		 											.sorted(comparing(IdentityStore::priority))
	 												.collect(toList());
    }

    @Override
    public CredentialValidationResult validate(Credential credential) {

        CredentialValidationResult validationResult = null;
        IdentityStore identityStore = null;
        boolean isGotAnInvalidResult = false;

        // Check stores to authenticate until one succeeds.
        for (IdentityStore authenticationIdentityStore : authenticationIdentityStores) {
            validationResult = authenticationIdentityStore.validate(credential);
            if (validationResult.getStatus() == VALID) {
                identityStore = authenticationIdentityStore;
                break;
            }
            else if (validationResult.getStatus() == INVALID) {
                isGotAnInvalidResult = true;
            }
        }

        if (validationResult == null || validationResult.getStatus() != VALID) {
            // Didn't get a VALID result. If we got an INVALID result at any point,
            // return INVALID_RESULT. Otherwise, return NOT_VALIDATED_RESULT.
            if (isGotAnInvalidResult) {
                return INVALID_RESULT;
            }
            else {
                return NOT_VALIDATED_RESULT;
            }
        }

        Set<String> groups = new HashSet<>();

        // Take the groups from the identity store that validated the credentials only
        // if it has been set to provide groups.
        if (identityStore.validationTypes().contains(PROVIDE_GROUPS)) {
            groups.addAll(validationResult.getCallerGroups());
        }

        // Ask all stores that were configured for group providing only to get the groups for the
        // authenticated caller
        CredentialValidationResult finalResult = validationResult; // compiler didn't like validationResult in the enclosed scope
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            public Void run() {
                for (IdentityStore authorizationIdentityStore : authorizationIdentityStores) {
                    groups.addAll(authorizationIdentityStore.getCallerGroups(finalResult));
                }
                return null;
            }
        });

        return new CredentialValidationResult(
                validationResult.getIdentityStoreId(),
                validationResult.getCallerPrincipal(),
                validationResult.getCallerDn(),
                validationResult.getCallerUniqueId(),
                groups);
    }

}
