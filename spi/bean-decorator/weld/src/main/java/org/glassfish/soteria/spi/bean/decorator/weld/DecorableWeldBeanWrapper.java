/*
 * Copyright (c) 2018, 2020 Payara Foundation and/or its affiliates and others.
 * All rights reserved.
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
package org.glassfish.soteria.spi.bean.decorator.weld;

import static org.jboss.weld.util.Decorators.getOuterDelegate;

import java.io.Serializable;
import java.util.List;
import java.util.Set;

import org.jboss.weld.bean.BeanIdentifiers;
import org.jboss.weld.bean.RIBean;
import org.jboss.weld.bean.StringBeanIdentifier;
import org.jboss.weld.bean.proxy.ProxyFactory;
import org.jboss.weld.bootstrap.BeanDeployerEnvironment;
import org.jboss.weld.injection.CurrentInjectionPoint;
import org.jboss.weld.manager.BeanManagerImpl;
import org.jboss.weld.util.Proxies;

import jakarta.enterprise.context.spi.CreationalContext;
import jakarta.enterprise.inject.spi.Bean;
import jakarta.enterprise.inject.spi.Decorator;
import jakarta.enterprise.inject.spi.InjectionPoint;
import jakarta.enterprise.inject.spi.PassivationCapable;

/**
 * Sub class of Weld specific Bean that Weld will call back after bean discovery
 * and that can apply CDI decorators using Weld proxies
 *
 * @author Arjan Tijms
 *
 * @param <T> type of bean that will be decorated
 */
public class DecorableWeldBeanWrapper<T> extends RIBean<T> implements Bean<T>, PassivationCapable {

    private final Bean<T> bean;
    private final CurrentInjectionPoint currentInjectionPoint;
    private final boolean isProxyable;
    private Class<T> type;

    private List<Decorator<?>> decorators;
    private Class<T> proxyClass;
    private boolean proxyRequired;
    private boolean isPassivationCapableBean;
    private boolean isPassivationCapableDependency;

    public DecorableWeldBeanWrapper(Bean<T> bean, Class<T> type, BeanManagerImpl beanManager) {
        super(
            bean,
            new StringBeanIdentifier(BeanIdentifiers.forBuiltInBean(beanManager, type, null)),
            beanManager);

        this.bean = bean;
        this.type = type;
        this.currentInjectionPoint = beanManager.getServices().get(CurrentInjectionPoint.class);
        this.isProxyable = Proxies.isTypesProxyable(getTypes(), beanManager.getServices());
    }

    @Override
    public void initializeAfterBeanDiscovery() {
        decorators = beanManager.resolveDecorators(getTypes(), getQualifiers());

        if (!decorators.isEmpty()) {
            proxyClass = new ProxyFactory<T>(getBeanManager().getContextId(), getType(), getTypes(), this).getProxyClass();
        }
    }

    @Override
    protected void internalInitialize(BeanDeployerEnvironment environment) {
        proxyRequired = getScope() != null && isNormalScoped();
        isPassivationCapableBean = Serializable.class.isAssignableFrom(type);
        isPassivationCapableDependency = isNormalScoped() || (isDependent() && isPassivationCapableBean());
    }

    @Override
    public T create(CreationalContext<T> creationalContext) {
        T instance = bean.create(creationalContext);

        if (decorators.isEmpty()) {
            return instance;
        }

        return getOuterDelegate(this, instance, creationalContext, proxyClass, currentInjectionPoint.peek(), getBeanManager(), decorators);
    }

    @Override
    public Class<T> getType() {
        return type;
    }

    @Override
    public Class<?> getBeanClass() {
        return bean.getBeanClass();
    }

    @Override
    public Set<InjectionPoint> getInjectionPoints() {
        return bean.getInjectionPoints();
    }

    @Override
    public String toString() {
        return "DecorableWeldBeanWrapper " + super.toString();
    }

    @Override
    public boolean isProxyable() {
        return isProxyable;
    }

    @Override
    public boolean isProxyRequired() {
        return proxyRequired;
    }

    @Override
    public boolean isPassivationCapableBean() {
        return isPassivationCapableBean;
    }

    @Override
    public boolean isPassivationCapableDependency() {
        return isPassivationCapableDependency;
    }

    @Override
    public void preInitialize() {

    }

    @Override
    public void cleanupAfterBoot() {

    }

}
