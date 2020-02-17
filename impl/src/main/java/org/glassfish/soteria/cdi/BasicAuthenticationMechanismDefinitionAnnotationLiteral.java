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
import static org.glassfish.soteria.cdi.AnnotationELPProcessor.evalImmediate;

import jakarta.enterprise.util.AnnotationLiteral;
import jakarta.security.enterprise.authentication.mechanism.http.BasicAuthenticationMechanismDefinition;

/**
 * An annotation literal for <code>@BasicAuthenticationMechanismDefinition</code>.
 * 
 */
@SuppressWarnings("all")
public class BasicAuthenticationMechanismDefinitionAnnotationLiteral extends AnnotationLiteral<BasicAuthenticationMechanismDefinition> implements BasicAuthenticationMechanismDefinition {
    
    private static final long serialVersionUID = 1L;

    private final String realmName;
    
    private boolean hasDeferredExpressions;

    public BasicAuthenticationMechanismDefinitionAnnotationLiteral(String realmName) {
        this.realmName = realmName;
    }
    
    public static BasicAuthenticationMechanismDefinition eval(BasicAuthenticationMechanismDefinition in) {
        if (!hasAnyELExpression(in)) {
            return in;
        }
        
        BasicAuthenticationMechanismDefinitionAnnotationLiteral out =
            new BasicAuthenticationMechanismDefinitionAnnotationLiteral(
                    evalImmediate(in.realmName()));
        
        out.setHasDeferredExpressions(hasAnyELExpression(out));
        
        return out;
    }
    
    public static boolean hasAnyELExpression(BasicAuthenticationMechanismDefinition in) {
        return AnnotationELPProcessor.hasAnyELExpression(
                in.realmName());
    }

    @Override
    public String realmName() {
        return hasDeferredExpressions? evalELExpression(realmName) : realmName;
    }
    
    public boolean isHasDeferredExpressions() {
        return hasDeferredExpressions;
    }

    public void setHasDeferredExpressions(boolean hasDeferredExpressions) {
        this.hasDeferredExpressions = hasDeferredExpressions;
    }
    

    
}
