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

package org.glassfish.soteria.identitystores.annotation;

import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;
import static jakarta.security.enterprise.identitystore.IdentityStore.ValidationType.PROVIDE_GROUPS;
import static jakarta.security.enterprise.identitystore.IdentityStore.ValidationType.VALIDATE;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import jakarta.security.enterprise.identitystore.IdentityStore;
import jakarta.security.enterprise.identitystore.IdentityStore.ValidationType;

/**
 * Annotation used to define a container provided {@link IdentityStore} that stores
 * caller credentials and identity attributes (together caller identities) in an 
 * in-memory store, and make that implementation available as an enabled CDI bean.
 * 
 * <p>
 * The data in this store is set at definition time only via the {@link #value()} attribute
 * of this annotation.
 * 
 * <p>
 * The following shows an example:
 * 
 * <pre>
 * <code>
 * {@literal @}EmbeddedIdentityStoreDefinition({ 
 *  {@literal @}Credentials(callerName = "peter", password = "secret1", groups = { "foo", "bar" }),
 *  {@literal @}Credentials(callerName = "john", password = "secret2", groups = { "foo", "kaz" }),
 *  {@literal @}Credentials(callerName = "carla", password = "secret3", groups = { "foo" }) })
 * </code>
 * </pre>
 *
 */
@Retention(RUNTIME)
@Target(TYPE)
public @interface EmbeddedIdentityStoreDefinition {

    /**
     * Defines the caller identities stored in the embedded identity store
     * 
     * @return caller identities stored in the embedded identity store
     */
    Credentials[] value() default {};

    /**
     * Determines the order in case multiple IdentityStores are found.
     * @return the priority.
     */
    int priority() default 90;

    /**
     * Determines what the identity store is used for
     * 
     * @return the type the identity store is used for
     */
    ValidationType[] useFor() default {VALIDATE, PROVIDE_GROUPS};

}
