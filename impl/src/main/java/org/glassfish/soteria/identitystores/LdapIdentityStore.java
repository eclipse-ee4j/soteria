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


import javax.naming.AuthenticationException;
import javax.naming.CommunicationException;
import javax.naming.NamingException;
import javax.naming.NameNotFoundException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.InvalidSearchControlsException;
import javax.naming.directory.InvalidSearchFilterException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.LdapName;
import javax.security.enterprise.credential.Credential;
import javax.security.enterprise.credential.UsernamePasswordCredential;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.IdentityStore;
import javax.security.enterprise.identitystore.IdentityStorePermission;
import javax.security.enterprise.identitystore.LdapIdentityStoreDefinition;
import java.util.*;

import static java.lang.String.format;
import static java.util.Arrays.asList;
import static java.util.Collections.*;
import static javax.naming.Context.*;
import static javax.naming.directory.SearchControls.ONELEVEL_SCOPE;
import static javax.naming.directory.SearchControls.SUBTREE_SCOPE;
import static javax.security.enterprise.identitystore.CredentialValidationResult.INVALID_RESULT;
import static javax.security.enterprise.identitystore.CredentialValidationResult.NOT_VALIDATED_RESULT;
import static javax.security.enterprise.identitystore.LdapIdentityStoreDefinition.LdapSearchScope;

public class LdapIdentityStore implements IdentityStore {

    private static final String DEFAULT_USER_FILTER = "(&(%s=%s)(|(objectclass=user)(objectclass=person)(objectclass=inetOrgPerson)(objectclass=organizationalPerson))(!(objectclass=computer)))";
    private static final String DEFAULT_GROUP_FILTER = "(&(%s=%s)(|(objectclass=group)(objectclass=groupofnames)(objectclass=groupofuniquenames)))";

    private final LdapIdentityStoreDefinition ldapIdentityStoreDefinition;
    private final Set<ValidationType> validationTypes;

    // CDI requires a no-arg constructor to be portable
    // It's only used to create the proxy
    protected LdapIdentityStore() {
        this.ldapIdentityStoreDefinition = null;
        this.validationTypes = null;
    }

    public LdapIdentityStore(LdapIdentityStoreDefinition ldapIdentityStoreDefinition) {
        this.ldapIdentityStoreDefinition = ldapIdentityStoreDefinition;
        validationTypes = unmodifiableSet(new HashSet<>(asList(ldapIdentityStoreDefinition.useFor())));
    }

    @Override
    public CredentialValidationResult validate(Credential credential) {
        if (credential instanceof UsernamePasswordCredential) {
            return validate((UsernamePasswordCredential) credential);
        }
        return NOT_VALIDATED_RESULT;
    }

    public CredentialValidationResult validate(UsernamePasswordCredential usernamePasswordCredential) {

        LdapContext searchContext = createSearchLdapContext();
        try {
            String callerDn = getCallerDn(searchContext, usernamePasswordCredential.getCaller());
            return validateCallerAndGetGroups(searchContext, callerDn, usernamePasswordCredential);
        }
        finally {
            closeContext(searchContext);
        }
    }

    private String getCallerDn(LdapContext searchContext, String callerName) {

        String callerDn = null;
        if (!ldapIdentityStoreDefinition.callerBaseDn().isEmpty() &&
                ldapIdentityStoreDefinition.callerSearchBase().isEmpty()) {
            callerDn = String.format("%s=%s,%s", ldapIdentityStoreDefinition.callerNameAttribute(),
                    callerName, ldapIdentityStoreDefinition.callerBaseDn());
        }
        else {
            callerDn = searchCaller(searchContext, callerName);
        }
        return callerDn;
    }

    private CredentialValidationResult validateCallerAndGetGroups(LdapContext searchContext,
            String callerDn, UsernamePasswordCredential usernamePasswordCredential) {

        if (callerDn == null) {
            return INVALID_RESULT;
        }
        
        LdapContext callerContext = createCallerLdapContext(callerDn, new String(usernamePasswordCredential.getPassword().getValue()));
        if (callerContext == null) {
            return INVALID_RESULT;  // either bindDn or bindPassword was invalid
        }
        closeContext(callerContext);

        Set<String> groups = null;
        if (validationTypes().contains(ValidationType.PROVIDE_GROUPS)) {
            groups = retrieveGroupsForCallerDn(searchContext, callerDn);
        }

        return new CredentialValidationResult(
                null, // store id
                usernamePasswordCredential.getCaller(),
                callerDn,
                null, // caller unique id
                groups);
    }

    @Override
    public Set<String> getCallerGroups(CredentialValidationResult validationResult) {

        // Make sure caller has permission to invoke this method
        SecurityManager securityManager = System.getSecurityManager();
        if (securityManager != null) {
            securityManager.checkPermission(new IdentityStorePermission("getGroups"));
        }

        LdapContext searchContext = createSearchLdapContext();
        try {
            String callerDn = validationResult.getCallerDn();
            if (callerDn == null || callerDn.isEmpty()) {
                callerDn = getCallerDn(searchContext, validationResult.getCallerPrincipal().getName());
            }
            return retrieveGroupsForCallerDn(searchContext, callerDn);
        }
        finally {
            closeContext(searchContext);
        }
    }

    private Set<String> retrieveGroupsForCallerDn(LdapContext searchContext, String callerDn) {

        if (callerDn == null || callerDn.isEmpty()) {
            return emptySet();
        }

        if (ldapIdentityStoreDefinition.groupSearchBase().isEmpty() &&
                !ldapIdentityStoreDefinition.groupMemberOfAttribute().isEmpty()) {
            return retrieveGroupsFromCallerObject(callerDn, searchContext);
        }
        else {
            return retrieveGroupsBySearching(callerDn, searchContext);
        }
    }

    private Set<String> retrieveGroupsBySearching(String callerDn, LdapContext searchContext) {

        List<SearchResult> searchResults = searchGroups(searchContext, callerDn);

        Set<String> groups = new HashSet<>();
        try {
            for (SearchResult searchResult : searchResults) {
                Attribute attribute = searchResult.getAttributes().get(ldapIdentityStoreDefinition.groupNameAttribute());
                if (attribute != null) {
                    for (Object group : list(attribute.getAll())) {
                        if (group != null) {
                            groups.add(group.toString());
                        }
                    }
                }
            }
        }
        catch (NamingException e) {
            throw new IdentityStoreRuntimeException(e);
        }
        return groups;
    }

    private Set<String> retrieveGroupsFromCallerObject(String callerDn, LdapContext searchContext) {
        try {
            Attributes attributes = searchContext.getAttributes(callerDn, new String[] { ldapIdentityStoreDefinition.groupMemberOfAttribute() });
            Attribute memberOfAttribute = attributes.get(ldapIdentityStoreDefinition.groupMemberOfAttribute());

            Set<String> groups = new HashSet<>();
            if (memberOfAttribute != null) {
                for (Object group : list(memberOfAttribute.getAll())) {
                    if (group != null) {
                        String groupName = getGroupNameFromDn(group.toString(), ldapIdentityStoreDefinition.groupNameAttribute());
                        if (groupName != null) {
                            groups.add(groupName);
                        }
                    }
                }
            }
            return groups;
        }
        catch (NamingException e) {
            throw new IdentityStoreRuntimeException(e);
        }
    }

    private static String getGroupNameFromDn(String dnString, String groupNameAttribute) throws NamingException {
        LdapName dn = new LdapName(dnString);  // may throw InvalidNameException
        Attribute attribute = dn.getRdn(dn.size()-1).toAttributes().get(groupNameAttribute);
        if (attribute == null) {
            // We were configured with the wrong group name attribute
            throw new IdentityStoreConfigurationException("Group name attribute '" + groupNameAttribute + "' not found for DN: " + dnString);
        }
        return attribute.get(0).toString();
    }

    private String searchCaller(LdapContext searchContext, String callerName) {

        String filter = null;
        if (ldapIdentityStoreDefinition.callerSearchFilter() != null &&
                !ldapIdentityStoreDefinition.callerSearchFilter().trim().isEmpty()) {
            // Filter should have exactly one "%s", where callerName will be substituted.
            filter = format(ldapIdentityStoreDefinition.callerSearchFilter(), callerName);
        }
        else {
            // Use groupMemberAttribute and callerDn to search for groups
            filter = format(DEFAULT_USER_FILTER, ldapIdentityStoreDefinition.callerNameAttribute(), callerName);
        }

        List <SearchResult> callerDn =
                search(searchContext, ldapIdentityStoreDefinition.callerSearchBase(), filter, getCallerSearchControls());

        if (callerDn.size() > 1) {
            // TODO User is found in multiple organizations
        }
        if (callerDn.size() == 1) {
            // get the fully qualified identification like uid=arjan,ou=caller,dc=jsr375,dc=net
            return callerDn.get(0).getNameInNamespace();
        }

        return null;
    }

    private List<SearchResult> searchGroups(LdapContext searchContext, String callerDn) {

        String filter = null;
        if (ldapIdentityStoreDefinition.groupSearchFilter() != null &&
                !ldapIdentityStoreDefinition.groupSearchFilter().trim().isEmpty()) {
            // Filter should have exactly one "%s", where callerDn will be substituted.
            filter = format(ldapIdentityStoreDefinition.groupSearchFilter(), callerDn);
        }
        else {
            // Use groupMemberAttribute and callerDn to search for groups
            filter = format(DEFAULT_GROUP_FILTER, ldapIdentityStoreDefinition.groupMemberAttribute(), callerDn);
        }

        return search(searchContext, ldapIdentityStoreDefinition.groupSearchBase(), filter, getGroupSearchControls());
    }

    private static List<SearchResult> search(LdapContext searchContext, String searchBase, String searchFilter, SearchControls controls) {
        try {
            return list(searchContext.search(searchBase, searchFilter, controls));
        }
        catch (NameNotFoundException e) {
            throw new IdentityStoreConfigurationException("Invalid searchBase", e);
        }
        catch (InvalidSearchFilterException e) {
            throw new IdentityStoreConfigurationException("Invalid search filter", e);
        }
        catch (InvalidSearchControlsException e) {
            throw new IdentityStoreConfigurationException("Invalid search controls", e);
        }
        catch (Exception e) {
            throw new IdentityStoreRuntimeException(e);
        }
    }

    private SearchControls getCallerSearchControls() {
        SearchControls controls = new SearchControls();
        controls.setSearchScope(convertScopeValue(ldapIdentityStoreDefinition.callerSearchScope()));
        controls.setCountLimit((long)ldapIdentityStoreDefinition.maxResults());
        controls.setTimeLimit(ldapIdentityStoreDefinition.readTimeout());
        return controls;
    }

    private SearchControls getGroupSearchControls() {
        SearchControls controls = new SearchControls();
        controls.setSearchScope(convertScopeValue(ldapIdentityStoreDefinition.groupSearchScope()));
        controls.setCountLimit((long)ldapIdentityStoreDefinition.maxResults());
        controls.setTimeLimit(ldapIdentityStoreDefinition.readTimeout());
        controls.setReturningAttributes(new String[]{ldapIdentityStoreDefinition.groupNameAttribute()});
        return controls;
    }

    private static int convertScopeValue(LdapSearchScope searchScope) {
        if (searchScope == LdapSearchScope.ONE_LEVEL) {
            return ONELEVEL_SCOPE;
        }
        else if (searchScope == LdapSearchScope.SUBTREE) {
            return SUBTREE_SCOPE;
        }
        else {
            return ONELEVEL_SCOPE;
        }
    }

    private LdapContext createSearchLdapContext() {
        try {
            return createLdapContext(
                    ldapIdentityStoreDefinition.url(),
                    ldapIdentityStoreDefinition.bindDn(),
                    ldapIdentityStoreDefinition.bindDnPassword());
        }
        catch (AuthenticationException e) {
            throw new IdentityStoreConfigurationException("Bad bindDn or bindPassword for: " + ldapIdentityStoreDefinition.bindDn(), e);
        }
    }

    private LdapContext createCallerLdapContext(String bindDn, String bindDnPassword) {
        try {
            return createLdapContext(
                    ldapIdentityStoreDefinition.url(),
                    bindDn,
                    bindDnPassword);
        }
        catch (AuthenticationException e) {
            return null;
        }
    }

    private static LdapContext createLdapContext(String url, String bindDn, String bindCredential) throws AuthenticationException {
        Hashtable<String, String> environment = new Hashtable<>();

        environment.put(INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        environment.put(PROVIDER_URL, url);

        environment.put(SECURITY_AUTHENTICATION, "simple");
        environment.put(SECURITY_PRINCIPAL, bindDn);
        environment.put(SECURITY_CREDENTIALS, bindCredential);

        try {
            return new InitialLdapContext(environment, null);
        }
        catch (AuthenticationException e) {
            throw e;
        }
        catch (CommunicationException e) {
            throw new IdentityStoreConfigurationException("Bad connection URL: " + url, e);
        }
        catch (Exception e) {
            throw new IdentityStoreRuntimeException(e);
        }
    }

    private static void closeContext(LdapContext ldapContext) {
        try {
            if (ldapContext != null) {
                ldapContext.close();
            }
        } catch (NamingException e) {
            // We can silently ignore this, no?
        }
    }

    @Override
    public int priority() {
        return ldapIdentityStoreDefinition.priority();
    }

    @Override
    public Set<ValidationType> validationTypes() {
        return validationTypes;
    }

}
