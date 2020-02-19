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

package org.glassfish.soteria.cdi;

import static org.glassfish.soteria.cdi.AnnotationELPProcessor.emptyIfImmediate;
import static org.glassfish.soteria.cdi.AnnotationELPProcessor.evalELExpression;
import static org.glassfish.soteria.cdi.AnnotationELPProcessor.evalImmediate;

import jakarta.enterprise.util.AnnotationLiteral;
import jakarta.security.enterprise.authentication.mechanism.http.LoginToContinue;

/**
 * An annotation literal for <code>@LoginToContinue</code>.
 * 
 */
@SuppressWarnings("all")
public class LoginToContinueAnnotationLiteral extends AnnotationLiteral<LoginToContinue> implements LoginToContinue {
    
    private static final long serialVersionUID = 1L;

    private final String loginPage;
    private final boolean useForwardToLogin;
    private final String useForwardToLoginExpression;
    private final String errorPage;
    
    private boolean hasDeferredExpressions;

    public LoginToContinueAnnotationLiteral(String loginPage, boolean useForwardToLogin, String useForwardToLoginExpression, String errorPage) {
        this.loginPage = loginPage;
        this.useForwardToLogin = useForwardToLogin;
        this.useForwardToLoginExpression = useForwardToLoginExpression;
        this.errorPage = errorPage;
    }
    
    public static LoginToContinue eval(LoginToContinue in) {
        if (!hasAnyELExpression(in)) {
            return in;
        }
        
        try {
        LoginToContinueAnnotationLiteral out =
            new LoginToContinueAnnotationLiteral(
                    evalImmediate(in.loginPage()), 
                    evalImmediate(in.useForwardToLoginExpression(), in.useForwardToLogin()), 
                    emptyIfImmediate(in.useForwardToLoginExpression()),
                    evalImmediate(in.errorPage())
            );
        
        out.setHasDeferredExpressions(hasAnyELExpression(out));
        
        return out;
        } catch (Throwable t) {
            t.printStackTrace();
            
            throw t;
        }
    }
    
    public static boolean hasAnyELExpression(LoginToContinue in) {
        return AnnotationELPProcessor.hasAnyELExpression(
            in.loginPage(), 
            in.errorPage(),
            in.useForwardToLoginExpression()
        );
    }

    @Override
    public String loginPage() {
        return hasDeferredExpressions? evalELExpression(loginPage) : loginPage;
    }

    @Override
    public boolean useForwardToLogin() {
        return hasDeferredExpressions? evalELExpression(useForwardToLoginExpression, useForwardToLogin) : useForwardToLogin;
    }
    
    @Override
    public String useForwardToLoginExpression() {
        return useForwardToLoginExpression;
    }

    @Override
    public String errorPage() {
        return hasDeferredExpressions? evalELExpression(errorPage) : errorPage;
    }
    
    public boolean isHasDeferredExpressions() {
        return hasDeferredExpressions;
    }

    public void setHasDeferredExpressions(boolean hasDeferredExpressions) {
        this.hasDeferredExpressions = hasDeferredExpressions;
    }
}
