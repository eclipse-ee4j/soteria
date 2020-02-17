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

package org.glassfish.soteria.identitystores;

import static java.util.Arrays.asList;
import static java.util.Arrays.stream;
import static java.util.Collections.emptySet;
import static java.util.Collections.unmodifiableMap;
import static java.util.Collections.unmodifiableSet;
import static java.util.stream.Collectors.toMap;
import static jakarta.security.enterprise.identitystore.CredentialValidationResult.INVALID_RESULT;
import static jakarta.security.enterprise.identitystore.CredentialValidationResult.NOT_VALIDATED_RESULT;
import static org.glassfish.soteria.cdi.AnnotationELPProcessor.evalImmediate;
import static org.glassfish.soteria.cdi.CdiUtils.getBeanReference;
import static org.glassfish.soteria.cdi.CdiUtils.jndiLookup;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import jakarta.security.enterprise.CallerPrincipal;
import jakarta.security.enterprise.credential.Credential;
import jakarta.security.enterprise.credential.UsernamePasswordCredential;
import jakarta.security.enterprise.identitystore.CredentialValidationResult;
import jakarta.security.enterprise.identitystore.DatabaseIdentityStoreDefinition;
import jakarta.security.enterprise.identitystore.IdentityStore;
import jakarta.security.enterprise.identitystore.IdentityStorePermission;
import jakarta.security.enterprise.identitystore.PasswordHash;
import javax.sql.DataSource;

public class DatabaseIdentityStore implements IdentityStore {

    private final DatabaseIdentityStoreDefinition dataBaseIdentityStoreDefinition;

    private final Set<ValidationType> validationTypes;
    private final PasswordHash hashAlgorithm; // Note: effectively application scoped, no support for @PreDestroy now
    
    // CDI requires a no-arg constructor to be portable
    // It's only used to create the proxy
    protected DatabaseIdentityStore() {
        this.dataBaseIdentityStoreDefinition = null;
        this.validationTypes = null;
        this.hashAlgorithm = null;
    }
    
    public DatabaseIdentityStore(DatabaseIdentityStoreDefinition dataBaseIdentityStoreDefinition) {
        this.dataBaseIdentityStoreDefinition = dataBaseIdentityStoreDefinition;
        
        validationTypes = unmodifiableSet(new HashSet<>(asList(dataBaseIdentityStoreDefinition.useFor())));
        hashAlgorithm = getBeanReference(dataBaseIdentityStoreDefinition.hashAlgorithm());
        hashAlgorithm.initialize(
            unmodifiableMap(
                    stream(
                        dataBaseIdentityStoreDefinition.hashAlgorithmParameters())
                    .flatMap(s -> toStream(evalImmediate(s, (Object)s)))
                    .collect(toMap(
                        s -> s.substring(0, s.indexOf('=')) , 
                        s -> evalImmediate(s.substring(s.indexOf('=') + 1))
                    ))));
    }

    @Override
    public CredentialValidationResult validate(Credential credential) {
        if (credential instanceof UsernamePasswordCredential) {
            return validate((UsernamePasswordCredential) credential);
        }

        return NOT_VALIDATED_RESULT;
    }

    public CredentialValidationResult validate(UsernamePasswordCredential usernamePasswordCredential) {

        DataSource dataSource = getDataSource();

        List<String> passwords = executeQuery(
            dataSource, 
            dataBaseIdentityStoreDefinition.callerQuery(),
            usernamePasswordCredential.getCaller()
        );
        
        if (passwords.isEmpty()) {
            return INVALID_RESULT;
        }
        
        if (hashAlgorithm.verify(usernamePasswordCredential.getPassword().getValue(), passwords.get(0))) {
            Set<String> groups = emptySet();
            if (validationTypes.contains(ValidationType.PROVIDE_GROUPS)) {
                groups = new HashSet<>(executeQuery(dataSource, dataBaseIdentityStoreDefinition.groupsQuery(), usernamePasswordCredential.getCaller()));
            }

            return new CredentialValidationResult(new CallerPrincipal(usernamePasswordCredential.getCaller()), groups);
        }

        return INVALID_RESULT;
    }
    
    @Override
    public Set<String> getCallerGroups(CredentialValidationResult validationResult) {

        SecurityManager securityManager = System.getSecurityManager();
        if (securityManager != null) {
            securityManager.checkPermission(new IdentityStorePermission("getGroups"));
        }

        DataSource dataSource = getDataSource();

        return new HashSet<>(executeQuery(
            dataSource,
            dataBaseIdentityStoreDefinition.groupsQuery(),
            validationResult.getCallerPrincipal().getName())
        );
    }

    private List<String> executeQuery(DataSource dataSource, String query, String parameter) {
        List<String> result = new ArrayList<>();

        try (Connection connection = dataSource.getConnection()) {
            try (PreparedStatement statement = connection.prepareStatement(query)) {
                statement.setString(1, parameter);
                try (ResultSet resultSet = statement.executeQuery()) {
                    while (resultSet.next()) {
                        result.add(resultSet.getString(1));
                    }
                }
            }
        } catch (SQLException e) {
            throw new IdentityStoreConfigurationException(e.getMessage(), e);
        }

        return result;
    }

    @Override
    public int priority() {
        return dataBaseIdentityStoreDefinition.priority();
    }

    @Override
    public Set<ValidationType> validationTypes() {
        return validationTypes;
    }
    
    @SuppressWarnings("unchecked")
    private Stream<String> toStream(Object raw) {
        if (raw instanceof String[]) {
            return stream((String[])raw);
        }
        if (raw instanceof Stream<?>) {
            return ((Stream<String>) raw).map(s -> s.toString());
        }
        
        return asList(raw.toString()).stream();
    }

    private DataSource getDataSource() {
        DataSource dataSource = null;
        try {
            dataSource = jndiLookup(dataBaseIdentityStoreDefinition.dataSourceLookup());
            if (dataSource == null) {
                throw new IdentityStoreConfigurationException("Jndi lookup failed for DataSource " + dataBaseIdentityStoreDefinition.dataSourceLookup());
            }
        } catch (IdentityStoreConfigurationException e) {
            throw e;
        } catch (Exception e) {
            throw new IdentityStoreRuntimeException(e);
        }
        return dataSource;
    }
}
