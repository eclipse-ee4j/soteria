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

import jakarta.annotation.security.DenyAll;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import jakarta.ws.rs.container.ResourceInfo;

import java.lang.reflect.Method;

import org.glassfish.soteria.utils.AnnotationFinder;

import static org.glassfish.soteria.rest.introspection.ResourceSecurityConstraintResolver.SecurityConstraint.denyAll;
import static org.glassfish.soteria.rest.introspection.ResourceSecurityConstraintResolver.SecurityConstraint.permitAll;
import static org.glassfish.soteria.rest.introspection.ResourceSecurityConstraintResolver.SecurityConstraint.rolesAllowed;
import static org.glassfish.soteria.rest.introspection.ResourceSecurityConstraintResolver.SecurityConstraint.SecurityConstraintType.DENY_ALL;
import static org.glassfish.soteria.rest.introspection.ResourceSecurityConstraintResolver.SecurityConstraint.SecurityConstraintType.PERMIT_ALL;
import static org.glassfish.soteria.rest.introspection.ResourceSecurityConstraintResolver.SecurityConstraint.SecurityConstraintType.ROLES_ALLOWED;

public class ResourceSecurityConstraintResolver {

    public static SecurityConstraint resolveSecurityConstraintForResource(ResourceInfo info) {
        Method method = info.getResourceMethod();
        if (method == null) {
            return null;
        }

        Class<?> resourceClass = info.getResourceClass();

        // ### Check Method-level first

        if (AnnotationFinder.findMethodAnnotation(method, resourceClass, DenyAll.class).isPresent()) {
            return denyAll();
        }

        if (AnnotationFinder.findMethodAnnotation(method, resourceClass, PermitAll.class).isPresent()) {
            return permitAll();
        }

        RolesAllowed methodRoles =
            AnnotationFinder.findMethodAnnotation(method, resourceClass, RolesAllowed.class)
                            .orElse(null);

        if (methodRoles != null) {
            return rolesAllowed(methodRoles.value());
        }


        // ### Check Class-level second. Deliberately direct only.

        if (resourceClass.getDeclaredAnnotation(DenyAll.class) != null) {
            return SecurityConstraint.denyAll();
        }

        if (resourceClass.getDeclaredAnnotation(PermitAll.class) != null) {
            return SecurityConstraint.permitAll();
        }

        RolesAllowed classRoles = resourceClass.getDeclaredAnnotation(RolesAllowed.class);
        if (classRoles != null) {
            return SecurityConstraint.rolesAllowed(classRoles.value());
        }

        return null;
    }

    public static record SecurityConstraint(
            SecurityConstraintType type,
            String[] roles) {

        public enum SecurityConstraintType {
            DENY_ALL,
            PERMIT_ALL,
            ROLES_ALLOWED
        }

        static SecurityConstraint denyAll() {
            return new SecurityConstraint(DENY_ALL, new String[0]);
        }

        static SecurityConstraint permitAll() {
            return new SecurityConstraint(PERMIT_ALL, new String[0]);
        }

        static SecurityConstraint rolesAllowed(String[] roles) {
            return new SecurityConstraint(ROLES_ALLOWED, roles.clone());
        }
    }

}
