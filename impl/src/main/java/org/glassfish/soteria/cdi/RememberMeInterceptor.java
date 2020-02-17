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

import static jakarta.interceptor.Interceptor.Priority.PLATFORM_BEFORE;
import static jakarta.security.enterprise.identitystore.CredentialValidationResult.Status.VALID;
import static org.glassfish.soteria.Utils.cleanSubjectMethod;
import static org.glassfish.soteria.Utils.getParam;
import static org.glassfish.soteria.Utils.isImplementationOf;
import static org.glassfish.soteria.Utils.toCallerPrincipal;
import static org.glassfish.soteria.Utils.validateRequestMethod;
import static org.glassfish.soteria.cdi.CdiUtils.getAnnotation;
import static org.glassfish.soteria.servlet.CookieHandler.getCookie;
import static org.glassfish.soteria.servlet.CookieHandler.removeCookie;
import static org.glassfish.soteria.servlet.CookieHandler.saveCookie;

import java.io.Serializable;
import java.lang.annotation.Annotation;
import java.util.Optional;
import java.util.Set;

import javax.annotation.Priority;
import jakarta.el.ELProcessor;
import jakarta.enterprise.inject.Intercepted;
import jakarta.enterprise.inject.spi.Bean;
import jakarta.enterprise.inject.spi.BeanManager;
import jakarta.inject.Inject;
import jakarta.interceptor.AroundInvoke;
import jakarta.interceptor.Interceptor;
import jakarta.interceptor.InvocationContext;
import jakarta.security.enterprise.AuthenticationStatus;
import jakarta.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import jakarta.security.enterprise.authentication.mechanism.http.RememberMe;
import jakarta.security.enterprise.credential.RememberMeCredential;
import jakarta.security.enterprise.identitystore.CredentialValidationResult;
import jakarta.security.enterprise.identitystore.RememberMeIdentityStore;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Interceptor
@RememberMe
@Priority(PLATFORM_BEFORE + 210)
public class RememberMeInterceptor implements Serializable {

    private static final long serialVersionUID = 1L;
    
    @Inject
    private BeanManager beanManager;
    
    @Inject
    @Intercepted
    private Bean<?> interceptedBean;

    @AroundInvoke
    public Object intercept(InvocationContext invocationContext) throws Exception {
        
        // If intercepting HttpAuthenticationMechanism#validateRequest
        if (isImplementationOf(invocationContext.getMethod(), validateRequestMethod)) {
            return validateRequest(
                invocationContext, 
                getParam(invocationContext, 0),  
                getParam(invocationContext, 1),
                getParam(invocationContext, 2));
        }
        
        // If intercepting HttpAuthenticationMechanism#cleanSubject
        if (isImplementationOf(invocationContext.getMethod(), cleanSubjectMethod)) {
            cleanSubject(
                invocationContext, 
                getParam(invocationContext, 0),  
                getParam(invocationContext, 1),
                getParam(invocationContext, 2));
        }
        
        return invocationContext.proceed();
    }
    
    private AuthenticationStatus validateRequest(InvocationContext invocationContext, HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMessageContext) throws Exception {
        
        RememberMeIdentityStore rememberMeIdentityStore = CdiUtils.getBeanReference(RememberMeIdentityStore.class);
        RememberMe rememberMeAnnotation = getRememberMeFromIntercepted(getElProcessor(invocationContext, httpMessageContext), invocationContext);
        
        Cookie rememberMeCookie = getCookie(request, rememberMeAnnotation.cookieName());
        
        if (rememberMeCookie != null) {
            
            // There's a remember me cookie, see if we can use it to authenticate
            
            CredentialValidationResult result = rememberMeIdentityStore.validate(
                new RememberMeCredential(rememberMeCookie.getValue())
            );
            
            if (result.getStatus() == VALID) {
                // The remember me store contained an authenticated identity associated with 
                // the given token, use it to authenticate with the container
                return httpMessageContext.notifyContainerAboutLogin(
                    result.getCallerPrincipal(), result.getCallerGroups());
            } else {
                // The token appears to be no longer valid, or perhaps wasn't valid
                // to begin with. Remove the cookie.
                removeCookie(request, response, rememberMeAnnotation.cookieName());
            }
        }
        
        // Try to authenticate with the next interceptor or actual authentication mechanism
        AuthenticationStatus authstatus = (AuthenticationStatus) invocationContext.proceed();
        
        if (authstatus == AuthenticationStatus.SUCCESS && httpMessageContext.getCallerPrincipal() != null) {
            
            // Authentication succeeded;
            // Check if remember me is wanted by the caller and if so
            // store the authenticated identity in the remember me store
            // and send a cookie with a token that can be used
            // to retrieve this stored identity later
            
            Boolean isRememberMe = true;
            if (rememberMeAnnotation instanceof RememberMeAnnotationLiteral) { // tmp
                isRememberMe = ((RememberMeAnnotationLiteral)rememberMeAnnotation).isRememberMe();
            }
            
            if (isRememberMe) {
                String token = rememberMeIdentityStore.generateLoginToken(
                    toCallerPrincipal(httpMessageContext.getCallerPrincipal()),
                    httpMessageContext.getGroups()
                );
                
                saveCookie(
                    request, response, 
                    rememberMeAnnotation.cookieName(), 
                    token, 
                    rememberMeAnnotation.cookieMaxAgeSeconds(),
                    rememberMeAnnotation.cookieSecureOnly(),
                    rememberMeAnnotation.cookieHttpOnly());
            }
        }
        
        return authstatus;
    }
    
    private void cleanSubject(InvocationContext invocationContext, HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMessageContext) throws Exception {
    
        RememberMeIdentityStore rememberMeIdentityStore = CdiUtils.getBeanReference(RememberMeIdentityStore.class); // TODO ADD CHECKS
        RememberMe rememberMeAnnotation = getRememberMeFromIntercepted(getElProcessor(invocationContext, httpMessageContext), invocationContext);
        
        Cookie rememberMeCookie = getCookie(request, rememberMeAnnotation.cookieName());
        
        if (rememberMeCookie != null) {
            
            // There's a remember me cookie, remove the cookie
            removeCookie(request, response, rememberMeAnnotation.cookieName());
            
            // And remove the token (and with it the authenticated identity) from the store
            rememberMeIdentityStore.removeLoginToken(rememberMeCookie.getValue());
        }

        invocationContext.proceed();
    }
    
    private RememberMe getRememberMeFromIntercepted(ELProcessor elProcessor, InvocationContext invocationContext) {
        Optional<RememberMe> optionalRememberMe = getAnnotation(beanManager, interceptedBean.getBeanClass(), RememberMe.class);
        if (optionalRememberMe.isPresent()) {
            return RememberMeAnnotationLiteral.eval(optionalRememberMe.get(), elProcessor);
        }
        
        @SuppressWarnings("unchecked")
        Set<Annotation> bindings = (Set<Annotation>) invocationContext.getContextData().get("org.jboss.weld.interceptor.bindings");
        if (bindings != null) {
            optionalRememberMe = bindings.stream()
                    .filter(annotation -> annotation.annotationType().equals(RememberMe.class))
                    .findAny()
                    .map(annotation -> RememberMe.class.cast(annotation));
            
            if (optionalRememberMe.isPresent()) {
                return RememberMeAnnotationLiteral.eval(optionalRememberMe.get(), elProcessor);
            }
        }
        
        throw new IllegalStateException("@RememberMe not present on " + interceptedBean.getBeanClass());
    }
    
    private ELProcessor getElProcessor(InvocationContext invocationContext, HttpMessageContext httpMessageContext) {
        ELProcessor elProcessor = new ELProcessor();
        
        elProcessor.getELManager().addELResolver(beanManager.getELResolver());
        elProcessor.defineBean("self", invocationContext.getTarget());
        elProcessor.defineBean("httpMessageContext", httpMessageContext);
        
        return elProcessor;
    }
 
}
