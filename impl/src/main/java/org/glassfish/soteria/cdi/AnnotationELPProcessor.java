/*
 * Copyright (c) 2015, 2020 Oracle and/or its affiliates. All rights reserved.
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

import static java.util.Arrays.stream;
import static org.glassfish.soteria.Utils.isEmpty;
import static org.glassfish.soteria.cdi.CdiUtils.getELProcessor;

import java.lang.reflect.Array;

import jakarta.el.ELProcessor;

public class AnnotationELPProcessor {
    
    public static String evalImmediate(String expression) {
        return evalImmediate((ELProcessor)null, expression);
    }
    
    public static String evalImmediate(ELProcessor getELProcessor, String expression) {
        if (!isELExpression(expression) || isDeferredExpression(expression)) {
            return expression;
        }
        
        return (String) getELProcessor(getELProcessor).eval(toRawExpression(expression));
    }
    
    public static boolean evalImmediate(String expression, boolean defaultValue) {
        return evalImmediate(null, expression, defaultValue);
    }
    
    public static boolean evalImmediate(ELProcessor getELProcessor, String expression, boolean defaultValue) {
        if (!isELExpression(expression) || isDeferredExpression(expression)) {
            return defaultValue;
        }
        
        Object outcome = getELProcessor(getELProcessor).eval(toRawExpression(expression));
        if (outcome instanceof Boolean) {
            return (Boolean) outcome;
        }

        throw new IllegalStateException(buildNonBooleanOutcomeMessage(outcome, expression));
    }

    static String buildNonBooleanOutcomeMessage(Object outcome, String expression) {
        return "Expression " + expression + " should evaluate to boolean but evaluated to " +
             outcome == null? " null" : (outcome.getClass() + " " + outcome);
    }
    
    public static int evalImmediate(String expression, int defaultValue) {
        return evalImmediate(null, expression, defaultValue);
    }
    
    public static int evalImmediate(ELProcessor getELProcessor, String expression, int defaultValue) {
        if (!isELExpression(expression) || isDeferredExpression(expression)) {
            return defaultValue;
        }
        
        return (Integer) getELProcessor(getELProcessor).getValue(toRawExpression(expression), Integer.class);
    }
    
    @SuppressWarnings("unchecked")
    public static <T> T evalImmediate(String expression, T defaultValue) {
        if (!isELExpression(expression) || isDeferredExpression(expression)) {
            return defaultValue;
        }
        
        return (T) getELProcessor(getELProcessor(null)).eval(toRawExpression(expression));
    }
    
    public static String emptyIfImmediate(String expression) {
        return isImmediateExpression(expression)? "" : expression;
    }
    
    public static String evalELExpression(String expression) {
        return evalELExpression((ELProcessor)null, expression);
    }
    
    public static String evalELExpression(ELProcessor getELProcessor, String expression) {
        if (!isELExpression(expression)) {
            return expression;
        }
        
        return (String) getELProcessor(getELProcessor).eval(toRawExpression(expression));
    }
    
    public static boolean evalELExpression(String expression, boolean defaultValue) {
        return evalELExpression(null, expression, defaultValue);
    }
    
    public static boolean evalELExpression(ELProcessor getELProcessor, String expression, boolean defaultValue) {
        if (!isELExpression(expression)) {
            return defaultValue;
        }
        
        return (Boolean) getELProcessor(getELProcessor).eval(toRawExpression(expression));
    }
    
    public static <T> T evalELExpression(String expression, T defaultValue) {
        return evalELExpression(null, expression, defaultValue);
    }
    
    @SuppressWarnings("unchecked")
    public static <T> T evalELExpression(ELProcessor getELProcessor, String expression, T defaultValue) {
        if (!isELExpression(expression)) {
            return defaultValue;
        }
        
        Object outcome = getELProcessor(getELProcessor).eval(toRawExpression(expression));
        
        // Convert string representations of enums to their target, if possible
        
        // Convert single enum name to single enum
        if (defaultValue instanceof Enum  && outcome instanceof String) {
            Enum<?> defaultValueEnum = (Enum<?>) defaultValue;
            Enum<?> enumConstant = Enum.valueOf(defaultValueEnum.getClass(), (String) outcome);
            
            return (T) enumConstant;
        }
        
        // Convert single enum name to enum array (multiple enum values not supported)
        if (defaultValue instanceof Enum[]  && outcome instanceof String) {
            Enum<?>[] defaultValueEnum = (Enum<?>[]) defaultValue;
            
            @SuppressWarnings("rawtypes")
            Enum<?> enumConstant = Enum.valueOf( (Class<? extends Enum>) defaultValueEnum.getClass().getComponentType(), (String) outcome);
            
            Enum<?>[] outcomeArray = (Enum<?>[]) Array.newInstance(defaultValueEnum.getClass().getComponentType(), 1);
            outcomeArray[0] = enumConstant;
            
            return (T) outcomeArray;
        }
        
        return (T) outcome;
    }
    
    public static int evalELExpression(String expression, int defaultValue) {
        return evalELExpression(null, expression, defaultValue);
    }
    
    public static int evalELExpression(ELProcessor getELProcessor, String expression, int defaultValue) {
        if (!isELExpression(expression)) {
            return defaultValue;
        }
        
        return (Integer) getELProcessor(getELProcessor).getValue(toRawExpression(expression), Integer.class);
    }
    
    @SafeVarargs
    public static boolean hasAnyELExpression(String... expressions) {
        return stream(expressions).anyMatch(expr -> isELExpression(expr));
    }
    
    private static boolean isELExpression(String expression) {
        return !isEmpty(expression) && (isDeferredExpression(expression) || isImmediateExpression(expression));
    }
    
    private static boolean isDeferredExpression(String expression) {
        return expression.startsWith("#{") && expression.endsWith("}");
    }
    
    private static boolean isImmediateExpression(String expression) {
        return expression.startsWith("${") && expression.endsWith("}");
    }
    
    private static String toRawExpression(String expression) {
        return expression.substring(2, expression.length() -1);
    }
}
