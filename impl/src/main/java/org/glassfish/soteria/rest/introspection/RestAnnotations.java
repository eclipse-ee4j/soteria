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

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;

public class RestAnnotations {

    public static boolean concreteMethodHasAnyJakartaRESTAnnotation(Method method) {
        for (Annotation annotation : method.getDeclaredAnnotations()) {
            if (isJakartaRESTAnnotation(annotation.annotationType())) {
                return true;
            }
        }

        for (Annotation[] parameterAnnotations : method.getParameterAnnotations()) {
            for (Annotation annotation : parameterAnnotations) {
                if (isJakartaRESTAnnotation(annotation.annotationType())) {
                    return true;
                }
            }
        }

        return false;
    }

    public static boolean isJakartaRESTAnnotation(Class<? extends Annotation> annotationType) {
        return
            annotationType.isAnnotationPresent(HttpMethod.class) ||
            annotationType.getName().startsWith("jakarta.ws.rs.");
    }

}
