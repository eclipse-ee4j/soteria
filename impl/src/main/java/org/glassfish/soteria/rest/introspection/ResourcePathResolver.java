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

import jakarta.ws.rs.ApplicationPath;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.Application;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.glassfish.soteria.utils.AnnotationFinder;

import static java.util.stream.Collectors.joining;
import static org.glassfish.soteria.rest.introspection.RestAnnotations.concreteMethodHasAnyJakartaRESTAnnotation;
import static org.glassfish.soteria.rest.introspection.RestAnnotations.isJakartaRESTAnnotation;
import static org.glassfish.soteria.utils.Utils.EMPTY_STRING;
import static org.glassfish.soteria.utils.Utils.isAnyNull;
import static org.glassfish.soteria.utils.Utils.isBlank;
import static org.glassfish.soteria.utils.Utils.isOneOf;

public class ResourcePathResolver {

    /**
     * Gets the application base path on which REST requests are handled
     * @param application
     * @param servletMappingOverride
     * @return
     */
    public static String getRESTApplicationBasePath(Application application, String servletMappingOverride) {
        if (!isBlank(servletMappingOverride)) {
            return normalizeServletMapping(servletMappingOverride);
        }

        // Get the value (if any) of @ApplicationPath at the application level
        return normalizePathPart(getPathFromApplication(application));
    }

    /**
     * Resolves the full path (web app context relative) corresponding to a ResourceInfo.
     */
    public static String resolveFullPathForResource(String applicationPath, ResourceInfo resourceInfo) {
        // Get the value (if any) of @Path at the Class level
        //
        // Portable Jakarta REST: class/interface annotations are not inherited.
        String classPath = getPathFromClass(resourceInfo);

        // Get the value (if any) of @Path at the method level
        //
        // Method-level @Path follows Jakarta REST method annotation inheritance.
        String methodPath = getPathFromMethod(resourceInfo);

        // The final path is a combination of the application, class and method paths
        // E.g. an application mapping REST to /rest, and a resource class mapped to /foo and a method mapped to /bar
        // will become "/rest/foo/bar" as the relative context path
        return joinPath(applicationPath, classPath, methodPath);
    }

    private static String normalizeServletMapping(String mapping) {
        if (isBlank(mapping)) {
            return EMPTY_STRING;
        }

        String result = mapping.trim();

        if (isOneOf(result, "/", "/*")) {
            return EMPTY_STRING;
        }

        if (result.startsWith("*.")) {
            throw new IllegalArgumentException(
                "Extension servlet mappings are not supported for REST Jakarta Authorization staging: " + result);
        }

        if (result.endsWith("/*") && result.length() > 2) {
            return normalizePathPart(result.substring(0, result.length() - 2));
        }

        throw new IllegalArgumentException(
            "Only default and path-prefix servlet mappings are supported for REST Jakarta Authorization staging: " + result);
    }

    private static String getPathFromApplication(Application application) {
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

    private static String getPathFromClass(ResourceInfo resourceInfo) {
        Class<?> resourceClass = resourceInfo.getResourceClass();
        if (resourceClass == null) {
            return EMPTY_STRING;
        }

        Path path = resourceClass.getDeclaredAnnotation(Path.class);
        return path == null ? EMPTY_STRING : path.value();
    }

    private static String getPathFromMethod(ResourceInfo resourceInfo) {
        return findMethodAnnotation(
                resourceInfo.getResourceMethod(),
                resourceInfo.getResourceClass(),
                Path.class)
            .map(Path::value)
            .orElse(EMPTY_STRING);
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
    private static <A extends Annotation> Optional<A> findMethodAnnotation(Method method, Class<?> resourceClass, Class<A> annotationType) {
        if (isAnyNull(method, resourceClass, annotationType)) {
            return Optional.empty();
        }

        // Look for the target annotation directly on the concrete method first
        A direct = method.getDeclaredAnnotation(annotationType);
        if (direct != null) {
            return Optional.of(direct);
        }

        if (isJakartaRESTAnnotation(annotationType) && concreteMethodHasAnyJakartaRESTAnnotation(method)) {
            return Optional.empty();
        }

        // Try to find the annotation in the super classes and interfaces
        return AnnotationFinder.findDeclaredMethodAnnotation(method, resourceClass, annotationType);
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
        if (isBlank(part)) {
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

}
