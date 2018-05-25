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

package org.glassfish.soteria.identitystores.hash;

public class PasswordHashCompare {

    /**
     * Compare two password hashes for equality. Do not fail fast;
     * continue comparing bytes even if a difference has been found,
     * to reduce the possibility that timing attacks can be used
     * to guess passwords.
     * <p>
     * The two hashes can be different lengths if the hash algorithm
     * or parameters used to generate them weren't the same.
     * <p>
     * Use the length of the first parameter (hash of the password being verified)
     * to determine how many bytes are compared, so that the comparison time
     * doesn't reflect the length of the second parameter (hash of the caller's
     * actual password).
     * <p>
     * Use XOR instead of == to compare characters, to avoid branching.
     * Branches can introduce timing differences depending on the branch
     * taken and the CPU's branch prediction state.
     * 
     * @param array1 Hash of the password to verify.
     * @param array2 Hash of the caller's actual password, for comparison.
     * @return True if the password hashes match, false otherwise.
     */
    public static boolean compareBytes(byte[] array1, byte[] array2) {
        int diff = array1.length ^ array2.length;
        for (int i = 0; i < array1.length; i++) {
            diff |= array1[i] ^ array2[i%array2.length];
        }
        return diff == 0;
    }

    /**
     * Compare two passwords, represented as character arrays.
     * <p>
     * Note that passwords should never be stored as plaintext,
     * but this method may be useful for, e.g., verifying a
     * password stored in encrypted form in a database, and
     * decrypted for comparison.
     * <p>
     * Behavior and theory operation are the same as for
     * {@link #compareBytes(byte[], byte[]) compareBytes},
     * except that the parameters are character arrays.
     * 
     * @param array1 The password to verify.
     * @param array2 The caller's actual password, for comparison.
     * @return True if the passwords match, false otherwise.
     */
    public static boolean compareChars(char[] array1, char[] array2) {
        int diff = array1.length ^ array2.length;
        for (int i = 0; i < array1.length; i++) {
            diff |= array1[i] ^ array2[i%array2.length];
        }
        return diff == 0;
    }
}
