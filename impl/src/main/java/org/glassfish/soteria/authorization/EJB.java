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

package org.glassfish.soteria.authorization;

import static org.glassfish.soteria.Utils.getELProcessor;

import jakarta.ejb.EJBContext;
import javax.naming.InitialContext;
import javax.naming.NamingException; 

public final class EJB {
    
    private EJB() {
        // no instances
    }
    
    public static EJBContext getEJBContext() {
        try {
            return (EJBContext) new InitialContext().lookup("java:comp/EJBContext");
        } catch (NamingException ex) {
            return null;
        }
    }
    
    public static String getCurrentEJBName(EJBContext ejbContext) {
        try {
            switch (ejbContext.getClass().getName()) {
                case "com.sun.ejb.containers.SessionContextImpl":
                case "com.sun.ejb.containers.SingletonContextImpl":
                    String toString = ejbContext.toString();
                    int firstIndex = toString.indexOf(";");
                    if (firstIndex != -1) {
                        return toString.substring(0, firstIndex);
                    }
                    break;
                case "org.jboss.as.ejb3.context.SessionContextImpl":
                    return getELProcessor("ejbContext", ejbContext)
                            .eval("ejbContext.component.componentName")
                            .toString();
            }
        } catch (Exception e) {
            // Ignore
        }
                
        return null;
    }

}
