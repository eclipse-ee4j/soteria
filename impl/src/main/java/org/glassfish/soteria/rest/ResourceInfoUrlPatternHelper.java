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
package org.glassfish.soteria.rest;

import static java.util.stream.Collectors.joining;

import jakarta.ws.rs.ApplicationPath;
import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.Application;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;

public final class ResourceInfoUrlPatternHelper {

    private static final String EMPTY_STRING = "";
    private static final String ESCAPED_COLON = "%3A";

    private ResourceInfoUrlPatternHelper() {
    }

    /**
     * Derives a context-relative, unqualified URL pattern name suitable for
     * staging as the name argument of WebResourcePermission.
     *
     * This is not the final qualified URLPatternSpec. The normal constraints
     * transformer will create the qualified form later.
     */
    public static String toStagedUrlPatternName(
            Application application,
            String servletMappingOverride,
            ResourceInfo resourceInfo) {

        String applicationPath = applicationBasePath(application, servletMappingOverride);

        // Portable Jakarta REST: class/interface annotations are not inherited.
        String classPath = classPath(resourceInfo.getResourceClass());

        // Method-level @Path follows Jakarta REST method annotation inheritance.
        String methodPath = findMethodAnnotation(
                resourceInfo.getResourceMethod(),
                resourceInfo.getResourceClass(),
                Path.class)
            .map(Path::value)
            .orElse(EMPTY_STRING);

        String path = joinPath(applicationPath, classPath, methodPath);

        if (containsTemplate(path)) {
            throw new IllegalArgumentException(
                "URI templates are not supported for JACC staging yet: " + path);
        }

        if (path.equals("/")) {
            return EMPTY_STRING;
        }

        return path.replace(":", ESCAPED_COLON);
    }

    public static String httpMethod(ResourceInfo resourceInfo) {
        return httpMethod(resourceInfo.getResourceMethod(), resourceInfo.getResourceClass());
    }

    public static String httpMethod(Method method, Class<?> resourceClass) {
        return findMethodAnnotationMatching(
                method,
                resourceClass,
                annotation -> annotation.annotationType().isAnnotationPresent(HttpMethod.class))
            .map(annotation -> annotation.annotationType().getAnnotation(HttpMethod.class).value())
            .orElse(null);
    }

    /**
     * Finds a method annotation using Jakarta REST method annotation inheritance rules.
     *
     * For Jakarta REST annotations:
     * - direct annotation on the concrete method wins;
     * - if the concrete method declares any Jakarta REST annotation, inheritance is suppressed;
     * - otherwise superclass and interface methods are searched.
     *
     * For non-Jakarta REST annotations, such as security annotations, the suppression
     * rule is not applied.
     */
    public static <A extends Annotation> Optional<A> findMethodAnnotation(
            Method method,
            Class<?> resourceClass,
            Class<A> annotationType) {

        if (method == null || resourceClass == null || annotationType == null) {
            return Optional.empty();
        }

        A direct = method.getDeclaredAnnotation(annotationType);
        if (direct != null) {
            return Optional.of(direct);
        }

        if (isJaxRsAnnotation(annotationType) && concreteMethodHasAnyJaxRsAnnotation(method)) {
            return Optional.empty();
        }

        Optional<A> fromSuperClass =
            findDeclaredMethodAnnotationInSuperclasses(resourceClass, method, annotationType);

        if (fromSuperClass.isPresent()) {
            return fromSuperClass;
        }

        return findDeclaredMethodAnnotationInInterfaces(resourceClass, method, annotationType);
    }

    private static Optional<Annotation> findMethodAnnotationMatching(
            Method method,
            Class<?> resourceClass,
            Predicate<Annotation> matcher) {

        if (method == null || resourceClass == null || matcher == null) {
            return Optional.empty();
        }

        for (Annotation annotation : method.getDeclaredAnnotations()) {
            if (matcher.test(annotation)) {
                return Optional.of(annotation);
            }
        }

        if (concreteMethodHasAnyJaxRsAnnotation(method)) {
            return Optional.empty();
        }

        Optional<Annotation> fromSuperClass =
            findDeclaredMethodAnnotationMatchingInSuperclasses(resourceClass, method, matcher);

        if (fromSuperClass.isPresent()) {
            return fromSuperClass;
        }

        return findDeclaredMethodAnnotationMatchingInInterfaces(resourceClass, method, matcher);
    }

    private static String applicationBasePath(
            Application application,
            String servletMappingOverride) {

        if (servletMappingOverride != null && !servletMappingOverride.isBlank()) {
            return normalizeServletMapping(servletMappingOverride);
        }

        return normalizePathPart(applicationPath(application));
    }

    private static String applicationPath(Application application) {
        if (application == null) {
            return EMPTY_STRING;
        }

        Class<?> type = application.getClass();

        while (type != null && type != Object.class) {
            ApplicationPath applicationPath = type.getDeclaredAnnotation(ApplicationPath.class);

            if (applicationPath != null) {
                return applicationPath.value();
            }

            type = type.getSuperclass();
        }

        return EMPTY_STRING;
    }

    private static String classPath(Class<?> resourceClass) {
        if (resourceClass == null) {
            return EMPTY_STRING;
        }

        Path path = resourceClass.getDeclaredAnnotation(Path.class);
        return path == null ? EMPTY_STRING : path.value();
    }

    public static boolean isSupportedServletMapping(String mapping) {
        if (mapping == null) {
            return false;
        }

        String trimmed = mapping.trim();

        return trimmed.equals("/")
            || trimmed.equals("/*")
            || (trimmed.endsWith("/*") && trimmed.length() > 2);
    }

    public static String normalizeServletMapping(String mapping) {
        if (mapping == null || mapping.isBlank()) {
            return EMPTY_STRING;
        }

        String result = mapping.trim();

        if (result.equals("/") || result.equals("/*")) {
            return EMPTY_STRING;
        }

        if (result.startsWith("*.")) {
            throw new IllegalArgumentException(
                "Extension servlet mappings are not supported for REST JACC staging: " + result);
        }

        if (result.endsWith("/*") && result.length() > 2) {
            return normalizePathPart(result.substring(0, result.length() - 2));
        }

        throw new IllegalArgumentException(
            "Only default and path-prefix servlet mappings are supported for REST JACC staging: " + result);
    }

    private static String joinPath(String... parts) {
        List<String> normalizedParts = new ArrayList<>();

        for (String part : parts) {
            String normalized = normalizePathPart(part);

            if (!normalized.isEmpty()) {
                normalizedParts.add(normalized);
            }
        }

        if (normalizedParts.isEmpty()) {
            return "/";
        }

        return "/" + normalizedParts.stream().collect(joining("/"));
    }

    /**
     * Strips leading and trailing slashes. In Jakarta REST, leading slashes
     * in @Path values are ignored for absolutizing.
     */
    private static String normalizePathPart(String part) {
        if (part == null || part.isBlank()) {
            return EMPTY_STRING;
        }

        String result = part.trim();

        while (result.startsWith("/")) {
            result = result.substring(1);
        }

        while (result.endsWith("/") && !result.isEmpty()) {
            result = result.substring(0, result.length() - 1);
        }

        return result;
    }

    private static boolean containsTemplate(String path) {
        return path.indexOf('{') >= 0 || path.indexOf('}') >= 0;
    }

    private static boolean concreteMethodHasAnyJaxRsAnnotation(Method method) {
        for (Annotation annotation : method.getDeclaredAnnotations()) {
            if (isJaxRsAnnotation(annotation.annotationType())) {
                return true;
            }
        }

        for (Annotation[] parameterAnnotations : method.getParameterAnnotations()) {
            for (Annotation annotation : parameterAnnotations) {
                if (isJaxRsAnnotation(annotation.annotationType())) {
                    return true;
                }
            }
        }

        return false;
    }

    private static boolean isJaxRsAnnotation(Class<? extends Annotation> annotationType) {
        return annotationType.isAnnotationPresent(HttpMethod.class)
            || annotationType.getName().startsWith("jakarta.ws.rs.");
    }

    private static <A extends Annotation> Optional<A> findDeclaredMethodAnnotationInSuperclasses(
            Class<?> resourceClass,
            Method method,
            Class<A> annotationType) {

        Class<?> current = resourceClass.getSuperclass();

        while (current != null && current != Object.class) {
            Optional<A> found = declaredMethodAnnotation(current, method, annotationType);

            if (found.isPresent()) {
                return found;
            }

            current = current.getSuperclass();
        }

        return Optional.empty();
    }

    private static <A extends Annotation> Optional<A> findDeclaredMethodAnnotationInInterfaces(
            Class<?> resourceClass,
            Method method,
            Class<A> annotationType) {

        for (Class<?> current = resourceClass;
                current != null && current != Object.class;
                current = current.getSuperclass()) {

            Optional<A> found = findDeclaredMethodAnnotationInInterfacesOf(
                current,
                method,
                annotationType);

            if (found.isPresent()) {
                return found;
            }
        }

        return Optional.empty();
    }

    private static <A extends Annotation> Optional<A> findDeclaredMethodAnnotationInInterfacesOf(
            Class<?> type,
            Method method,
            Class<A> annotationType) {

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

    private static <A extends Annotation> Optional<A> declaredMethodAnnotation(
            Class<?> type,
            Method method,
            Class<A> annotationType) {

        try {
            Method candidate = type.getDeclaredMethod(method.getName(), method.getParameterTypes());
            return Optional.ofNullable(candidate.getDeclaredAnnotation(annotationType));
        } catch (NoSuchMethodException e) {
            return Optional.empty();
        }
    }

    private static Optional<Annotation> findDeclaredMethodAnnotationMatchingInSuperclasses(
            Class<?> resourceClass,
            Method method,
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

    private static Optional<Annotation> findDeclaredMethodAnnotationMatchingInInterfaces(
            Class<?> resourceClass,
            Method method,
            Predicate<Annotation> matcher) {

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

    private static Optional<Annotation> findDeclaredMethodAnnotationMatchingInInterfacesOf(
            Class<?> type,
            Method method,
            Predicate<Annotation> matcher) {

        for (Class<?> interfaceType : type.getInterfaces()) {
            Optional<Annotation> found =
                declaredMethodAnnotationMatching(interfaceType, method, matcher);

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

    private static Optional<Annotation> declaredMethodAnnotationMatching(
            Class<?> type,
            Method method,
            Predicate<Annotation> matcher) {

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