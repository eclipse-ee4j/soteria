/*
 * Copyright (c) 2026 Contributors to the Eclipse Foundation.
 * Copyright (c) 2015, 2026 Oracle and/or its affiliates and others.
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
package org.glassfish.soteria.cdi;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import jakarta.enterprise.inject.spi.AfterBeanDiscovery;
import jakarta.enterprise.inject.spi.Bean;
import jakarta.enterprise.inject.spi.PassivationCapable;
import jakarta.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanismHandler;
import jakarta.security.enterprise.identitystore.IdentityStoreHandler;

import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.glassfish.soteria.SoteriaServiceProviders;
import org.glassfish.soteria.cdi.spi.BeanDecorator;
import org.glassfish.soteria.cdi.spi.WebXmlLoginConfig;
import org.glassfish.soteria.cdi.spi.impl.DefaultWebXmlLoginConfig;
import org.junit.Test;

public class CdiExtensionTest {

    @Test
    public void shouldUseDistinctProducerIdsForHandlerBeans() throws Exception {
        CdiExtension extension = new CdiExtension();
        List<Bean<?>> addedBeans = new ArrayList<>();

        BeanDecorator beanDecorator = new BeanDecorator() {
            @Override
            public <T> Bean<T> decorateBean(Bean<T> decorableBean, Class<T> type, jakarta.enterprise.inject.spi.BeanManager beanManager) {
                return decorableBean;
            }
        };

        WebXmlLoginConfig loginConfig = new DefaultWebXmlLoginConfig();

        Map<Class<?>, Object> originalProviders = new HashMap<>(getServiceProviders());
        try {
            Map<Class<?>, Object> serviceProviders = getServiceProviders();
            serviceProviders.clear();
            serviceProviders.put(BeanDecorator.class, beanDecorator);
            serviceProviders.put(WebXmlLoginConfig.class, loginConfig);

            setField(extension, "extraBeans", List.of(new CdiProducer<>().addToId("dummy")));

            AfterBeanDiscovery afterBeanDiscovery = (AfterBeanDiscovery) Proxy.newProxyInstance(
                AfterBeanDiscovery.class.getClassLoader(),
                new Class<?>[] {AfterBeanDiscovery.class},
                (proxy, method, args) -> {
                    if ("addBean".equals(method.getName()) && args != null && args.length == 1 && args[0] instanceof Bean) {
                        addedBeans.add((Bean<?>) args[0]);
                        return null;
                    }

                    throw new AssertionError("Unexpected AfterBeanDiscovery method: " + method);
                });

            extension.afterBean(afterBeanDiscovery, null);
        } finally {
            Map<Class<?>, Object> serviceProviders = getServiceProviders();
            serviceProviders.clear();
            serviceProviders.putAll(originalProviders);
        }

        Bean<?> identityStoreHandlerBean = findBean(addedBeans,
            "org.glassfish.soteria.cdi.CdiProducer interface jakarta.security.enterprise.identitystore.IdentityStoreHandler");
        Bean<?> httpAuthenticationMechanismHandlerBean = findBean(addedBeans,
            "org.glassfish.soteria.cdi.CdiProducer interface jakarta.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanismHandler");

        assertNotNull(identityStoreHandlerBean);
        assertNotNull(httpAuthenticationMechanismHandlerBean);
        assertNotEquals(getBeanId(identityStoreHandlerBean), getBeanId(httpAuthenticationMechanismHandlerBean));
        assertTrue(identityStoreHandlerBean.getTypes().contains(IdentityStoreHandler.class));
        assertTrue(httpAuthenticationMechanismHandlerBean.getTypes().contains(HttpAuthenticationMechanismHandler.class));
        assertEquals(3, addedBeans.size());
    }

    @SuppressWarnings("unchecked")
    private static Map<Class<?>, Object> getServiceProviders() throws Exception {
        Field field = SoteriaServiceProviders.class.getDeclaredField("SERVICE_PROVIDERS");
        field.setAccessible(true);
        return (Map<Class<?>, Object>) field.get(null);
    }

    private static void setField(Object target, String fieldName, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(target, value);
    }

    private static Bean<?> findBean(List<Bean<?>> beans, String id) {
        for (Bean<?> bean : beans) {
            if (id.equals(getBeanId(bean))) {
                return bean;
            }
        }

        return null;
    }

    private static String getBeanId(Bean<?> bean) {
        return ((PassivationCapable) bean).getId();
    }
}
