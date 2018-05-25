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

import static java.util.Arrays.asList;
import static java.util.Collections.emptySet;
import static java.util.Collections.singleton;
import static java.util.Collections.unmodifiableSet;

import java.lang.annotation.Annotation;
import java.lang.reflect.Type;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Function;

import javax.enterprise.context.Dependent;
import javax.enterprise.context.spi.CreationalContext;
import javax.enterprise.inject.spi.Bean;
import javax.enterprise.inject.spi.InjectionPoint;
import javax.enterprise.inject.spi.PassivationCapable;

// May be replaced by CDI 2.0 bean builder API when ready.
// See http://weld.cdi-spec.org/news/2015/02/25/weld-300Alpha5/#_bean_builder_api
public class CdiProducer<T> implements Bean<T>, PassivationCapable {
    
    private String id = this.getClass().getName();
    private String name;
    private Class<?> beanClass = Object.class;
    private Set<Type> types = singleton(Object.class);
    private Set<Annotation> qualifiers = unmodifiableSet(asSet(new DefaultAnnotationLiteral(), new AnyAnnotationLiteral()));
    private Class<? extends Annotation> scope = Dependent.class;
    private Function<CreationalContext<T>, T> create;
    
    @Override
    public String getId() {
        return id;
    }
    
    @Override
    public String getName() {
        return name;
    }
    
    @Override
    public Class<?> getBeanClass() {
       return beanClass;
    }
    
    @Override
    public Set<Type> getTypes() {
        return types;
    }
    
    @Override
    public Set<Annotation> getQualifiers() {
        return qualifiers;
    }
    
    @Override
    public Class<? extends Annotation> getScope() {
        return scope;
    }
    
    @Override
    public T create(CreationalContext<T> creationalContext) {
        return create.apply(creationalContext);
    }
    
    @Override
    public void destroy(T instance, CreationalContext<T> creationalContext) {
    }
    
    @Override
    public Set<InjectionPoint> getInjectionPoints() {
        return emptySet();
    }
    
    @Override
    public Set<Class<? extends Annotation>> getStereotypes() {
        return emptySet();
    }
    
    @Override
    public boolean isAlternative() {
        return false;
    }

    @Override
    public boolean isNullable() {
        return false;
    }
    
    protected CdiProducer<T> active(boolean active) {
        return this;
    }
    
    protected CdiProducer<T> name(String name) {
        this.name = name;
        return this;
    }
    
    protected CdiProducer<T> create(Function<CreationalContext<T>, T> create) {
        this.create = create;
        return this;
    }
    
    protected CdiProducer<T> beanClass(Class<?> beanClass) {
        this.beanClass = beanClass;
        return this;
    }
    
    protected CdiProducer<T> types(Type... types) {
        this.types = asSet(types);
        return this;
    }
    
    protected CdiProducer<T> beanClassAndType(Class<?> beanClass) {
        beanClass(beanClass);
        types(beanClass);
        return this;
    }
    
    protected CdiProducer<T> qualifiers(Annotation... qualifiers) {
        this.qualifiers = asSet(qualifiers);
        return this;
    }
    
    
    protected CdiProducer<T> scope(Class<? extends Annotation> scope) {
        this.scope = scope;
        return this;
    }
    
    protected CdiProducer<T> addToId(Object object) {
        id = id + " " + object.toString();
        return this;
    }
    
    @SafeVarargs
    protected static <T> Set<T> asSet(T... a) {
        return new HashSet<>(asList(a));
    }
    
}
