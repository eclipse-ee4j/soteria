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


import static org.glassfish.soteria.cdi.AnnotationELPProcessor.emptyIfImmediate;
import static org.glassfish.soteria.cdi.AnnotationELPProcessor.evalELExpression;
import static org.glassfish.soteria.cdi.AnnotationELPProcessor.evalImmediate;

import jakarta.enterprise.util.AnnotationLiteral;
import jakarta.security.enterprise.identitystore.DatabaseIdentityStoreDefinition;
import jakarta.security.enterprise.identitystore.PasswordHash;
import jakarta.security.enterprise.identitystore.IdentityStore.ValidationType;

/**
 * An annotation literal for <code>@DatabaseIdentityStoreDefinition</code>.
 * 
 */
@SuppressWarnings("all")
public class DatabaseIdentityStoreDefinitionAnnotationLiteral extends AnnotationLiteral<DatabaseIdentityStoreDefinition> implements DatabaseIdentityStoreDefinition {
    
    private static final long serialVersionUID = 1L;
    
    private final String dataSourceLookup;
    private final String callerQuery;
    private final String groupsQuery;
    private final Class<? extends PasswordHash> hashAlgorithm;
    private final String[] hashAlgorithmParameters;
    private final int priority;
    private final String priorityExpression;
    private final ValidationType[] useFor;
    private final String useForExpression;
    
    private boolean hasDeferredExpressions;

    public DatabaseIdentityStoreDefinitionAnnotationLiteral(
            
        String dataSourceLookup, 
        String callerQuery, 
        String groupsQuery, 
        Class<? extends PasswordHash> hashAlgorithm,
        String[] hashAlgorithmParameters,
        int priority,
        String priorityExpression,
        ValidationType[] useFor,
        String useForExpression
        
            ) {
        
        this.dataSourceLookup = dataSourceLookup;
        this.callerQuery = callerQuery;
        this.groupsQuery = groupsQuery;
        this.hashAlgorithm = hashAlgorithm;
        this.hashAlgorithmParameters = hashAlgorithmParameters;
        this.priority = priority;
        this.priorityExpression = priorityExpression;
        this.useFor = useFor;
        this.useForExpression = useForExpression;
    }
    
    public static DatabaseIdentityStoreDefinition eval(DatabaseIdentityStoreDefinition in) {
        if (!hasAnyELExpression(in)) {
            return in;
        }
        
        DatabaseIdentityStoreDefinitionAnnotationLiteral out = new DatabaseIdentityStoreDefinitionAnnotationLiteral(
            evalImmediate(in.dataSourceLookup()),
            evalImmediate(in.callerQuery()), 
            evalImmediate(in.groupsQuery()), 
            in.hashAlgorithm(),
            in.hashAlgorithmParameters(),
            evalImmediate(in.priorityExpression(), in.priority()),
            emptyIfImmediate(in.priorityExpression()),
            evalImmediate(in.useForExpression(), in.useFor()),
            emptyIfImmediate(in.useForExpression())
        );
        
        out.setHasDeferredExpressions(hasAnyELExpression(out));
        
        return out;
    }
    
    public static boolean hasAnyELExpression(DatabaseIdentityStoreDefinition in) {
        return AnnotationELPProcessor.hasAnyELExpression(
            in.dataSourceLookup(),
            in.callerQuery(), 
            in.groupsQuery(), 
            in.priorityExpression(),
            in.useForExpression()
       );
    }
    
    @Override
    public String dataSourceLookup() {
        return hasDeferredExpressions? evalELExpression(dataSourceLookup) : dataSourceLookup;
    }
    
    @Override
    public String callerQuery() {
        return hasDeferredExpressions? evalELExpression(callerQuery) : callerQuery;
    }
    
    @Override
    public String groupsQuery() {
        return hasDeferredExpressions? evalELExpression(groupsQuery) : groupsQuery;
    }
    
    @Override
    public Class<? extends PasswordHash> hashAlgorithm() {
        return hashAlgorithm;
    }
    
    @Override
    public String[] hashAlgorithmParameters() {
        return hashAlgorithmParameters;
    }
    
    @Override
    public int priority() {
        return hasDeferredExpressions? evalELExpression(priorityExpression, priority) : priority;
    }
    
    @Override
    public String priorityExpression() {
        return priorityExpression;
    }
    
    @Override
    public ValidationType[] useFor() {
        return hasDeferredExpressions? evalELExpression(useForExpression, useFor) : useFor;
    }
    
    @Override
    public String useForExpression() {
        return useForExpression;
    }
    
    public boolean isHasDeferredExpressions() {
        return hasDeferredExpressions;
    }

    public void setHasDeferredExpressions(boolean hasDeferredExpressions) {
        this.hasDeferredExpressions = hasDeferredExpressions;
    }

}
