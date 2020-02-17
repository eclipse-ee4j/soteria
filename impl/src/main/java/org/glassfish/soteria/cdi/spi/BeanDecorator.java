/*
 * Copyright (c) 2018 Payara Foundation and/or its affiliates and others.
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
package org.glassfish.soteria.cdi.spi;

import jakarta.enterprise.inject.spi.Bean;
import jakarta.enterprise.inject.spi.BeanManager;

/**
 * Implementations of this interface should apply all CDI interceptors in the application
 * to the given bean.
 *
 * <p>
 * This SPI is needed since CDI doesn't have a portable API to apply interceptors to a bean, and neither
 * does it do this automatically.
 *
 * @author Arjan Tijms
 *
 */
public interface BeanDecorator {

    /**
     *
     * @param decorableBean Bean that should have CDI decorators applied
     * @param type main type of the bean
     * @param beanManager the current bean manager
     *
     * @return decorableBean with all CDI decorators for its type applied to it
     */
    <T> Bean<T> decorateBean(Bean<T> decorableBean, Class<T> type, BeanManager beanManager);

}
