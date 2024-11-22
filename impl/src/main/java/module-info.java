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

module org.glassfish.soteria {

    exports org.glassfish.soteria;
    exports org.glassfish.soteria.authorization;
    exports org.glassfish.soteria.authorization.spi;
    exports org.glassfish.soteria.authorization.spi.impl;
    exports org.glassfish.soteria.cdi;
    exports org.glassfish.soteria.cdi.spi;
    exports org.glassfish.soteria.cdi.spi.impl;
    exports org.glassfish.soteria.identitystores;
    exports org.glassfish.soteria.identitystores.hash;
    exports org.glassfish.soteria.mechanisms;
    exports org.glassfish.soteria.mechanisms.jaspic;
    exports org.glassfish.soteria.mechanisms.openid;
    exports org.glassfish.soteria.mechanisms.openid.controller;
    exports org.glassfish.soteria.mechanisms.openid.domain;
    exports org.glassfish.soteria.servlet;

    opens org.glassfish.soteria;
    opens org.glassfish.soteria.authorization;
    opens org.glassfish.soteria.authorization.spi;
    opens org.glassfish.soteria.authorization.spi.impl;
    opens org.glassfish.soteria.cdi;
    opens org.glassfish.soteria.cdi.spi;
    opens org.glassfish.soteria.cdi.spi.impl;
    opens org.glassfish.soteria.identitystores;
    opens org.glassfish.soteria.identitystores.hash;
    opens org.glassfish.soteria.mechanisms;
    opens org.glassfish.soteria.mechanisms.jaspic;
    opens org.glassfish.soteria.mechanisms.openid;
    opens org.glassfish.soteria.mechanisms.openid.controller;
    opens org.glassfish.soteria.mechanisms.openid.domain;
    opens org.glassfish.soteria.servlet;
    
    requires static com.nimbusds.jose.jwt;
    requires jakarta.annotation;
    requires static jakarta.ejb;
    requires transitive jakarta.cdi;
    requires jakarta.cdi.el;
    requires jakarta.el;
    requires jakarta.inject;
    requires transitive jakarta.interceptor;
    requires transitive jakarta.security;
    requires jakarta.security.jacc;
    requires static jakarta.ws.rs;
    requires jakarta.xml.bind;
    requires java.logging;
    requires java.naming;
    requires static java.sql;
}
