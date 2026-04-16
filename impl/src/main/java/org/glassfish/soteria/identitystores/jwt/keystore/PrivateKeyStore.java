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
package org.glassfish.soteria.identitystores.jwt.keystore;

import java.security.PrivateKey;
import java.time.Duration;

public class PrivateKeyStore {

    private final RawKeyLoader keyLoader;
    private final KeyParser keyParser;

    public PrivateKeyStore(Duration defaultCacheTTL, String keyLocation) {
        this.keyLoader = new RawKeyLoader(keyLocation, defaultCacheTTL);
        this.keyParser = new KeyParser();
    }

    public PrivateKey getPrivateKey(String keyId) {
        String rawKey = keyLoader.readRawPublicKey();
        if (rawKey == null) {
            throw new IllegalStateException("No PublicKey found");
        }

        return keyParser.createPrivateKey(rawKey, keyId);
    }

}
