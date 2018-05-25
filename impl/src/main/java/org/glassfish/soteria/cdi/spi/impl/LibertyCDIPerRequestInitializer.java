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

package org.glassfish.soteria.cdi.spi.impl;

import javax.el.ELProcessor;
import javax.servlet.ServletRequestEvent;
import javax.servlet.http.HttpServletRequest;

import org.glassfish.soteria.cdi.spi.CDIPerRequestInitializer;

/**
 * Hacky (but working) CDI initializer for Liberty. Should probably be moved to an SPI jar
 * later using the necessary Weld types directly and/or implemented by Liberty, should
 * Liberty decide to use and/or support Soteria.  
 * 
 * @author arjan
 *
 */
public class LibertyCDIPerRequestInitializer implements CDIPerRequestInitializer  {

    @Override
    public void init(HttpServletRequest request) {
        Object weldInitialListener = request.getServletContext().getAttribute("org.jboss.weld.servlet.WeldInitialListener");
        ServletRequestEvent event = new ServletRequestEvent(request.getServletContext(), request);
                 
        ELProcessor elProcessor = new ELProcessor();
        elProcessor.defineBean("weldInitialListener", weldInitialListener);
        elProcessor.defineBean("event", event);
        elProcessor.eval("weldInitialListener.requestInitialized(event)");
    }
    
    @Override
    public void destroy(HttpServletRequest request) {
        Object weldInitialListener = request.getServletContext().getAttribute("org.jboss.weld.servlet.WeldInitialListener");
        ServletRequestEvent event = new ServletRequestEvent(request.getServletContext(), request);
                 
        ELProcessor elProcessor = new ELProcessor();
        elProcessor.defineBean("weldInitialListener", weldInitialListener);
        elProcessor.defineBean("event", event);
        elProcessor.eval("weldInitialListener.requestDestroyed(event)");
        
        // EXTRA HACK TO MAKE REQUEST WRAPPING NOT DESTROY FOLLOW UP REQUEST IN LIBERTY 16.0.0.3 and 2016.9 AND EARLIER
        // SHOULD BE REMOVED WHEN LIBERTY NO LONGER STORES THIS PER REQUEST WRAPPER IN THE APPLICATION SCOPE
        if (request.getServletContext().getAttribute("com.ibm.ws.security.jaspi.servlet.request.wrapper") !=  null) {
            request.getServletContext().removeAttribute("com.ibm.ws.security.jaspi.servlet.request.wrapper");
        }
    }
    
}
