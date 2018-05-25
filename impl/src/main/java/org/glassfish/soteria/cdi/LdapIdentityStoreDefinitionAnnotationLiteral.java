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

import static org.glassfish.soteria.cdi.AnnotationELPProcessor.evalELExpression;

import javax.enterprise.util.AnnotationLiteral;
import javax.security.enterprise.identitystore.IdentityStore.ValidationType;
import javax.security.enterprise.identitystore.LdapIdentityStoreDefinition;

/**
 * An annotation literal for <code>@LdapIdentityStoreDefinition</code>.
 * 
 */
@SuppressWarnings("all")
public class LdapIdentityStoreDefinitionAnnotationLiteral extends AnnotationLiteral<LdapIdentityStoreDefinition> implements LdapIdentityStoreDefinition {
    
    private static final long serialVersionUID = 1L;
    
    private final String bindDn;
    private final String bindDnPassword;
    private final String callerBaseDn;
    private final String callerNameAttribute;
    private final String callerSearchBase;
    private final String callerSearchFilter;
    private final LdapSearchScope callerSearchScope;
    private final String callerSearchScopeExpression;
    private final String groupMemberAttribute;
    private final String groupMemberOfAttribute;
    private final String groupNameAttribute;
    private final String groupSearchBase;
    private final String groupSearchFilter;
    private final LdapSearchScope groupSearchScope;
    private final String groupSearchScopeExpression;
    private final int maxResults;
    private final String maxResultsExpression;
    private final int priority;
    private final String priorityExpression;
    private final int readTimeout;
    private final String readTimeoutExpression;
    private final String url;
    private final ValidationType[] useFor;
    private final String useForExpression;
    
    private boolean hasDeferredExpressions;

    public LdapIdentityStoreDefinitionAnnotationLiteral(
            
            String bindDn,
            String bindDnPassword,
            String callerBaseDn,
            String callerNameAttribute,
            String callerSearchBase,
            String callerSearchFilter,
            LdapSearchScope callerSearchScope,
            String callerSearchScopeExpression,
            String groupMemberAttribute,
            String groupMemberOfAttribute,
            String groupNameAttribute,
            String groupSearchBase,
            String groupSearchFilter,
            LdapSearchScope groupSearchScope,
            String groupSearchScopeExpression,
            int maxResults,
            String maxResultsExpression,
            int priority,
            String priorityExpression,
            int readTimeout,
            String readTimeoutExpression,
            String url,
            ValidationType[] useFor,
            String useForExpression
            
            ) {
        
        this.bindDn = bindDn;
        this.bindDnPassword = bindDnPassword;
        this.callerBaseDn = callerBaseDn;
        this.callerNameAttribute = callerNameAttribute;
        this.callerSearchBase = callerSearchBase;
        this.callerSearchFilter = callerSearchFilter;
        this.callerSearchScope = callerSearchScope;
        this.callerSearchScopeExpression = callerSearchScopeExpression;
        this.groupMemberAttribute = groupMemberAttribute;
        this.groupMemberOfAttribute = groupMemberOfAttribute;
        this.groupNameAttribute = groupNameAttribute;
        this.groupSearchBase = groupSearchBase;
        this.groupSearchFilter = groupSearchFilter;
        this.groupSearchScope = groupSearchScope;
        this.groupSearchScopeExpression = groupSearchScopeExpression;
        this.maxResults = maxResults;
        this.maxResultsExpression = maxResultsExpression;
        this.priority = priority;
        this.priorityExpression = priorityExpression;
        this.readTimeout = readTimeout;
        this.readTimeoutExpression = readTimeoutExpression;
        this.url = url;
        this.useFor = useFor;
        this.useForExpression = useForExpression;

    }
    
    public static LdapIdentityStoreDefinition eval(LdapIdentityStoreDefinition in) {
        if (!hasAnyELExpression(in)) {
            return in;
        }
        
        try {
            LdapIdentityStoreDefinitionAnnotationLiteral out =
                new LdapIdentityStoreDefinitionAnnotationLiteral(
                    in.bindDn(),
                    in.bindDnPassword(),
                    in.callerBaseDn(),
                    in.callerNameAttribute(),
                    in.callerSearchBase(),
                    in.callerSearchFilter(),
                    in.callerSearchScope(),
                    in.callerSearchScopeExpression(),
                    in.groupMemberAttribute(),
                    in.groupMemberOfAttribute(),
                    in.groupNameAttribute(),
                    in.groupSearchBase(),
                    in.groupSearchFilter(),
                    in.groupSearchScope(),
                    in.groupSearchScopeExpression(),
                    in.maxResults(),
                    in.maxResultsExpression(),
                    in.priority(),
                    in.priorityExpression(),
                    in.readTimeout(),
                    in.readTimeoutExpression(),
                    in.url(),
                    in.useFor(),
                    in.useForExpression()
                );
            
            out.setHasDeferredExpressions(hasAnyELExpression(out));
            
            return out;
        } catch (Throwable t) {
            t.printStackTrace();
            
            throw t;
        }
    }
    
    public static boolean hasAnyELExpression(LdapIdentityStoreDefinition in) {
        return AnnotationELPProcessor.hasAnyELExpression(
            in.bindDn(),
            in.bindDnPassword(),
            in.callerNameAttribute(),
            in.callerSearchBase(),
            in.callerSearchFilter(),
            in.callerSearchScopeExpression(),
            in.groupMemberAttribute(),
            in.groupMemberOfAttribute(),
            in.groupNameAttribute(),
            in.groupSearchBase(),
            in.groupSearchFilter(),
            in.groupSearchScopeExpression(),
            in.maxResultsExpression(),
            in.priorityExpression(),
            in.readTimeoutExpression(),
            in.url(),
            in.useForExpression()
        );
    }
    
    @Override
    public String bindDn() {
        return hasDeferredExpressions? evalELExpression(bindDn) : bindDn;
    }
    
    @Override
    public String bindDnPassword() {
        return hasDeferredExpressions? evalELExpression(bindDnPassword) : bindDnPassword;
    }
    
    @Override
    public String callerBaseDn() {
        return hasDeferredExpressions? evalELExpression(callerBaseDn) : callerBaseDn;
    }
    
    @Override
    public String callerNameAttribute() {
        return hasDeferredExpressions? evalELExpression(callerNameAttribute) : callerNameAttribute;
    }
    
    @Override
    public String callerSearchBase() {
        return hasDeferredExpressions? evalELExpression(callerSearchBase) : callerSearchBase;
    }
    
    @Override
    public String callerSearchFilter() {
        return hasDeferredExpressions? evalELExpression(callerSearchFilter) : callerSearchFilter;
    }
    
    @Override
    public LdapSearchScope callerSearchScope() {
        return hasDeferredExpressions? evalELExpression(callerSearchScopeExpression, callerSearchScope) : callerSearchScope;
    }
    
    @Override
    public String callerSearchScopeExpression() {
        return hasDeferredExpressions? evalELExpression(callerSearchScopeExpression) : callerSearchScopeExpression;
    }
    
    @Override
    public String groupMemberAttribute() {
        return hasDeferredExpressions? evalELExpression(groupMemberAttribute) : groupMemberAttribute;
    }
    
    @Override
    public String groupMemberOfAttribute() {
        return hasDeferredExpressions? evalELExpression(groupMemberOfAttribute) : groupMemberOfAttribute;
    }
    
    @Override
    public String groupNameAttribute() {
        return hasDeferredExpressions? evalELExpression(groupNameAttribute) : groupNameAttribute;
    }
    
    @Override
    public String groupSearchBase() {
        return hasDeferredExpressions? evalELExpression(groupSearchBase) : groupSearchBase;
    }
    
    @Override
    public String groupSearchFilter() {
        return hasDeferredExpressions? evalELExpression(groupSearchFilter) : groupSearchFilter;
    }
    
    @Override
    public LdapSearchScope groupSearchScope() {
        return hasDeferredExpressions? evalELExpression(groupSearchScopeExpression, groupSearchScope) : groupSearchScope;
    }
    
    @Override
    public String groupSearchScopeExpression() {
        return groupSearchScopeExpression;
    }
    
    @Override
    public int maxResults() {
        return hasDeferredExpressions? evalELExpression(maxResultsExpression, maxResults) : maxResults;
    }
    
    @Override
    public String maxResultsExpression() {
        return maxResultsExpression;
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
    public int readTimeout() {
        return hasDeferredExpressions? evalELExpression(readTimeoutExpression, readTimeout) : readTimeout;
    }
    
    @Override
    public String readTimeoutExpression() {
        return readTimeoutExpression;
    }
    
    @Override
    public String url() {
        return url;
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
