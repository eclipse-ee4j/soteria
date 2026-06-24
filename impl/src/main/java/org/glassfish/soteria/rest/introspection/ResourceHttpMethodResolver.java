/*
 * Copyright (c) 2026 Contributors to the Eclipse Foundation.
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
package org.glassfish.soteria.rest.introspection;

import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.container.ResourceInfo;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.Optional;
import java.util.function.Predicate;

import org.glassfish.soteria.utils.AnnotationFinder;

import static org.glassfish.soteria.rest.introspection.RestAnnotations.concreteMethodHasAnyJakartaRESTAnnotation;
import static org.glassfish.soteria.utils.Utils.isAnyNull;

public class ResourceHttpMethodResolver {

    public static String resolveHttpMethodForResource(ResourceInfo resourceInfo) {
        return httpMethod(resourceInfo.getResourceMethod(), resourceInfo.getResourceClass());
    }


    // ### Private methods

    private static String httpMethod(Method method, Class<?> resourceClass) {
        return findMethodAnnotationByMatcher(
                method,
                resourceClass,
                annotation -> annotation.annotationType().isAnnotationPresent(HttpMethod.class))
            .map(annotation -> annotation.annotationType().getAnnotation(HttpMethod.class).value())
            .orElse(null);
    }


    private static Optional<Annotation> findMethodAnnotationByMatcher(Method method, Class<?> resourceClass, Predicate<Annotation> matcher) {
        if (isAnyNull(method, resourceClass, matcher)) {
            return Optional.empty();
        }

        // Look for the target annotation directly on the concrete method first
        for (Annotation annotation : method.getDeclaredAnnotations()) {
            if (matcher.test(annotation)) {
                return Optional.of(annotation);
            }
        }

        if (concreteMethodHasAnyJakartaRESTAnnotation(method)) {
            return Optional.empty();
        }

        // Try to find the annotation in the super classes and interfaces
        return AnnotationFinder.findDeclaredMethodAnnotationByMatcher(method, resourceClass, matcher);
    }

}
