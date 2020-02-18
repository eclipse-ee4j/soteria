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
package org.glassfish.soteria;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Central registry to load Soteria SPI implementations from.
 *
 * <p>
 * SPI implementations are lazily loaded. This class is thread safe.
 *
 * @author Arjan Tijms
 *
 */
public class SoteriaServiceProviders {

    private static final Map<Class<? extends Object>, Object> SERVICE_PROVIDERS = new ConcurrentHashMap<>();

    public static <T> T getServiceProvider(Class<T> serviceProviderClass) {
        return serviceProviderClass.cast(SERVICE_PROVIDERS.computeIfAbsent(
            serviceProviderClass,
            e -> loadService(e)));
    }

    private static <T> T loadService(Class<T> serviceProviderClass) {
        List<T> defaultService = new ArrayList<>(1);
        List<T> nonDefaultServices = new ArrayList<>();

        ServiceLoader.load(serviceProviderClass).forEach(e -> {
            if (e instanceof DefaultService) {
                defaultService.add(e);
            } else {
                nonDefaultServices.add(e);
            }
        });

        if (nonDefaultServices.size() > 1) {
            throw new IllegalStateException("More than 1 implementation of " + serviceProviderClass + " found.");
        }

        if (defaultService.size() > 1) {
            throw new IllegalStateException("More than 1 implementation of default " + serviceProviderClass + " found.");
        }

        if (nonDefaultServices.size() == 1) {
            return nonDefaultServices.get(0);
        }

        return defaultService.get(0);

    }

}
