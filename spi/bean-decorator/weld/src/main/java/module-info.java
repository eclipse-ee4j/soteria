/*
 * Copyright (c) 2018, 2020 Payara Foundation and/or its affiliates and others.
 * All rights reserved.
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

module org.glassfish.soteria.spi.bean.decorator.weld.weld {

    exports org.glassfish.soteria.spi.bean.decorator.weld;
    
    opens org.glassfish.soteria.spi.bean.decorator.weld;
    
    requires jakarta.cdi;
    requires org.glassfish.soteria;
    requires transitive weld.osgi.bundle;
}
