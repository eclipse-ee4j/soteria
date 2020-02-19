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

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.PARAMETER;
import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;

/**
 * <code>Credentials</code> define a single caller identity for
 * use with the {@link EmbeddedIdentityStoreDefinition} annotation. 
 *
 */
@Retention(RUNTIME)
@Target({ TYPE, METHOD, FIELD, PARAMETER })
public @interface Credentials {
    
    /**
     * Name of caller. This is the name a caller uses to authenticate with.
     * 
     * @return Name of caller
     */
    String callerName();

    /**
     * A text-based password used by the caller to authenticate.
     * 
     * @return A text-based password
     */
    String password();

    /**
     * The optional list of groups that the specified caller is in.
     * 
     * @return optional list of groups
     */
    String[] groups() default {};
}
