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
package org.glassfish.soteria.utils;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.Optional;
import java.util.function.Predicate;

import static org.glassfish.soteria.utils.Utils.isAnyNull;

public class AnnotationFinder {

    public static <A extends Annotation> Optional<A> findMethodAnnotation(Method method, Class<?> initialClass, Class<A> annotationType) {
        if (isAnyNull(method, initialClass, annotationType)) {
            return Optional.empty();
        }

        // Look for the target annotation directly on the concrete method first
        A direct = method.getDeclaredAnnotation(annotationType);
        if (direct != null) {
            return Optional.of(direct);
        }

        // Try to find the annotation in the super classes and interfaces
        return findDeclaredMethodAnnotation(method, initialClass, annotationType);
    }


    public static <A extends Annotation> Optional<A> findDeclaredMethodAnnotation(Method method, Class<?> initialClass, Class<A> annotationType) {
        Optional<A> fromSuperClass = findDeclaredMethodAnnotationInSuperclasses(initialClass, method, annotationType);

        if (fromSuperClass.isPresent()) {
            return fromSuperClass;
        }

        return findDeclaredMethodAnnotationInInterfaces(initialClass, method, annotationType);
    }

    public static Optional<Annotation> findDeclaredMethodAnnotationByMatcher(Method method, Class<?> initialClass, Predicate<Annotation> matcher) {
        Optional<Annotation> fromSuperClass = findDeclaredMethodAnnotationInSuperclassesByMatcher(initialClass, method, matcher);

        if (fromSuperClass.isPresent()) {
            return fromSuperClass;
        }

        return findDeclaredMethodAnnotationInInterfacesByMatcher(initialClass, method, matcher);
    }

    // ### Private methods

    private static <A extends Annotation> Optional<A> findDeclaredMethodAnnotationInSuperclasses(Class<?> initialClass, Method method, Class<A> annotationType) {
        Class<?> currentClass = initialClass.getSuperclass();

        while (currentClass != null && currentClass != Object.class) {
            Optional<A> found = declaredMethodAnnotation(currentClass, method, annotationType);

            if (found.isPresent()) {
                return found;
            }

            currentClass = currentClass.getSuperclass();
        }

        return Optional.empty();
    }

    private static <A extends Annotation> Optional<A> findDeclaredMethodAnnotationInInterfaces(Class<?> clazz, Method method, Class<A> annotationType) {
        for (Class<?> currentClass = clazz;
                currentClass != null && currentClass != Object.class;
                currentClass = currentClass.getSuperclass()) {

            Optional<A> found = findDeclaredMethodAnnotationInInterfacesOf(
                currentClass,
                method,
                annotationType);

            if (found.isPresent()) {
                return found;
            }
        }

        return Optional.empty();
    }


    private static <A extends Annotation> Optional<A> findDeclaredMethodAnnotationInInterfacesOf(Class<?> type, Method method, Class<A> annotationType) {
        for (Class<?> interfaceType : type.getInterfaces()) {
            Optional<A> found = declaredMethodAnnotation(interfaceType, method, annotationType);

            if (found.isPresent()) {
                return found;
            }

            found = findDeclaredMethodAnnotationInInterfacesOf(interfaceType, method, annotationType);

            if (found.isPresent()) {
                return found;
            }
        }

        return Optional.empty();
    }

    private static <A extends Annotation> Optional<A> declaredMethodAnnotation(Class<?> type, Method method, Class<A> annotationType) {
        try {
            Method candidate = type.getDeclaredMethod(method.getName(), method.getParameterTypes());
            return Optional.ofNullable(candidate.getDeclaredAnnotation(annotationType));
        } catch (NoSuchMethodException e) {
            return Optional.empty();
        }
    }

    private static Optional<Annotation> findDeclaredMethodAnnotationInSuperclassesByMatcher(Class<?> resourceClass, Method method,
            Predicate<Annotation> matcher) {

        Class<?> current = resourceClass.getSuperclass();

        while (current != null && current != Object.class) {
            Optional<Annotation> found =
                declaredMethodAnnotationMatching(current, method, matcher);

            if (found.isPresent()) {
                return found;
            }

            current = current.getSuperclass();
        }

        return Optional.empty();
    }

    private static Optional<Annotation> findDeclaredMethodAnnotationInInterfacesByMatcher(Class<?> resourceClass, Method method, Predicate<Annotation> matcher) {
        for (Class<?> current = resourceClass;
                current != null && current != Object.class;
                current = current.getSuperclass()) {

            Optional<Annotation> found =
                findDeclaredMethodAnnotationMatchingInInterfacesOf(current, method, matcher);

            if (found.isPresent()) {
                return found;
            }
        }

        return Optional.empty();
    }

    private static Optional<Annotation> findDeclaredMethodAnnotationMatchingInInterfacesOf(Class<?> type, Method method, Predicate<Annotation> matcher) {
        for (Class<?> interfaceType : type.getInterfaces()) {

            Optional<Annotation> found = declaredMethodAnnotationMatching(interfaceType, method, matcher);

            if (found.isPresent()) {
                return found;
            }

            found = findDeclaredMethodAnnotationMatchingInInterfacesOf(
                interfaceType,
                method,
                matcher);

            if (found.isPresent()) {
                return found;
            }
        }

        return Optional.empty();
    }

    private static Optional<Annotation> declaredMethodAnnotationMatching(Class<?> type, Method method, Predicate<Annotation> matcher) {
        try {
            Method candidate = type.getDeclaredMethod(method.getName(), method.getParameterTypes());

            for (Annotation annotation : candidate.getDeclaredAnnotations()) {
                if (matcher.test(annotation)) {
                    return Optional.of(annotation);
                }
            }

            return Optional.empty();
        } catch (NoSuchMethodException e) {
            return Optional.empty();
        }
    }

}
