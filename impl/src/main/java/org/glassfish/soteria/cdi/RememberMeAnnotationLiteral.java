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

import javax.el.ELProcessor;
import javax.enterprise.util.AnnotationLiteral;
import javax.security.enterprise.authentication.mechanism.http.RememberMe;

/**
 * An annotation literal for <code>@RememberMe</code>.
 * 
 */
@SuppressWarnings("all")
public class RememberMeAnnotationLiteral extends AnnotationLiteral<RememberMe> implements RememberMe {
    
    private static final long serialVersionUID = 1L;
    
    private final int cookieMaxAgeSeconds;
    private final String cookieMaxAgeSecondsExpression;
    private final boolean cookieSecureOnly;
    private final String cookieSecureOnlyExpression;
    private final boolean cookieHttpOnly;
    private final String cookieHttpOnlyExpression;
    private final String cookieName;
    private final boolean isRememberMe;
    private final String isRememberMeExpression;
    
    private final ELProcessor elProcessor;
    
    private boolean hasDeferredExpressions;

    public RememberMeAnnotationLiteral(
        
        int cookieMaxAgeSeconds,
        String cookieMaxAgeSecondsExpression,
        boolean cookieSecureOnly,
        String cookieSecureOnlyExpression,
        boolean cookieHttpOnly,
        String cookieHttpOnlyExpression,
        String cookieName,
        boolean isRememberMe,
        String isRememberMeExpression,
        ELProcessor elProcessor
        
            ) {
        
        this.cookieMaxAgeSeconds = cookieMaxAgeSeconds;
        this.cookieMaxAgeSecondsExpression = cookieMaxAgeSecondsExpression;
        this.cookieSecureOnly = cookieSecureOnly;
        this.cookieSecureOnlyExpression = cookieSecureOnlyExpression;
        this.cookieHttpOnly = cookieHttpOnly;
        this.cookieHttpOnlyExpression = cookieHttpOnlyExpression;
        this.cookieName = cookieName;
        this.isRememberMe = isRememberMe;
        this.isRememberMeExpression = isRememberMeExpression;
        this.elProcessor = elProcessor;
        
    }
    
    public static RememberMe eval(RememberMe in, ELProcessor elProcessor) {
        if (!hasAnyELExpression(in)) {
            return in;
        }
        
        try {
            RememberMeAnnotationLiteral out =
                new RememberMeAnnotationLiteral(
                    evalImmediate(elProcessor, in.cookieMaxAgeSecondsExpression(), in.cookieMaxAgeSeconds()), 
                    emptyIfImmediate(in.cookieMaxAgeSecondsExpression()),
                    evalImmediate(elProcessor, in.cookieSecureOnlyExpression(), in.cookieSecureOnly()),
                    emptyIfImmediate(in.cookieSecureOnlyExpression()),
                    evalImmediate(elProcessor, in.cookieHttpOnlyExpression(), in.cookieHttpOnly()),
                    emptyIfImmediate(in.cookieHttpOnlyExpression()),
                    evalImmediate(elProcessor, in.cookieName()),
                    evalImmediate(elProcessor, in.isRememberMeExpression(), in.isRememberMe()),
                    evalImmediate(elProcessor, in.isRememberMeExpression()),
                    elProcessor
                );
        
            out.setHasDeferredExpressions(hasAnyELExpression(out));
        
            return out;
        } catch (Throwable t) {
            t.printStackTrace();
            
            throw t;
        }
    }
    
    public static boolean hasAnyELExpression(RememberMe in) {
        return AnnotationELPProcessor.hasAnyELExpression(
            in.cookieMaxAgeSecondsExpression(),
            in.cookieSecureOnlyExpression(),
            in.cookieHttpOnlyExpression(),
            in.cookieName(),
            in.isRememberMeExpression()
        );
    }
    
    @Override
    public boolean cookieHttpOnly() {
        return hasDeferredExpressions? evalELExpression(elProcessor, cookieHttpOnlyExpression, cookieHttpOnly) : cookieHttpOnly;
    }
    
    @Override
    public String cookieHttpOnlyExpression() {
        return cookieHttpOnlyExpression;
    }
    
    @Override
    public int cookieMaxAgeSeconds() {
        return hasDeferredExpressions? evalELExpression(elProcessor, cookieMaxAgeSecondsExpression, cookieMaxAgeSeconds) : cookieMaxAgeSeconds;
    }
    
    @Override
    public String cookieMaxAgeSecondsExpression() {
        return cookieMaxAgeSecondsExpression;
    }

    @Override
    public boolean cookieSecureOnly() {
        return hasDeferredExpressions? evalELExpression(elProcessor, cookieSecureOnlyExpression, cookieSecureOnly) : cookieSecureOnly;
    }

    @Override
    public String cookieSecureOnlyExpression() {
        return cookieSecureOnlyExpression;
    }

    @Override
    public String cookieName() {
        return hasDeferredExpressions? evalELExpression(elProcessor, cookieName) : cookieName;
    }
    
    @Override
    public boolean isRememberMe() {
        return hasDeferredExpressions? evalELExpression(elProcessor, isRememberMeExpression, isRememberMe) : isRememberMe;
    }

    @Override
    public String isRememberMeExpression() {
        return isRememberMeExpression;
    }
    
    public boolean isHasDeferredExpressions() {
        return hasDeferredExpressions;
    }

    public void setHasDeferredExpressions(boolean hasDeferredExpressions) {
        this.hasDeferredExpressions = hasDeferredExpressions;
    }
}
