/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is Android Sync Client.
 *
 * The Initial Developer of the Original Code is
 * the Mozilla Foundation.
 * Portions created by the Initial Developer are Copyright (C) 2011
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 * Jason Voll
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

package com.signicat.services.blockchain.crypto;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/*
 * A standards-compliant implementation of RFC 5869
 * for HMAC-based Key Derivation Function.
 * HMAC uses HMAC SHA256 standard.
 */
public class HKDF {
    private HKDF() {}

    public static final int BLOCKSIZE     = 256 / 8;
    public static final byte[] HMAC_INPUT = "Sync-AES_256_CBC-HMAC256".getBytes(StandardCharsets.UTF_8);

    /*
     * Step 1 of RFC 5869
     * Get sha256HMAC Bytes
     * Input: salt (message), ikm (input keyring material)
     * Output: PRK (pseudorandom key)
     */
    public static byte[] hkdfExtract(final byte[] salt, final byte[] ikm) {
        return digestBytes(ikm, makeHMACHasher(salt));
    }

    /*
     * Step 2 of RFC 5869.
     * Input: PRK from step 1, info, length.
     * Output: OKM (output keyring material).
     */
    public static byte[] hkdfExpand(final byte[] prk, final byte[] info, final int len) {
        final Mac hmacHasher = makeHMACHasher(prk);

        byte[] t  = {};
        byte[] tn = {};

        final int iterations = (int) Math.ceil(((double)len) / ((double)BLOCKSIZE));
        for (int i = 0; i < iterations; i++) {
            tn = digestBytes(concatAll(
                    tn, info, hex2Byte(Integer.toHexString(i + 1))), hmacHasher);
            t = concatAll(t, tn);
        }

        return Arrays.copyOfRange(t, 0, len);
    }

    /*
     * Make HMAC key
     * Input: key (salt)
     * Output: Key HMAC-Key
     */
    private static Key makeHMACKey(final byte[] key) {
        final byte[] nonZeroLengthKey = key.length == 0 ? new byte[BLOCKSIZE] : key;
        return new SecretKeySpec(nonZeroLengthKey, "HmacSHA256");
    }

    /*
     * Make an HMAC hasher
     * Input: Key hmacKey
     * Ouput: An HMAC Hasher
     */
    private static Mac makeHMACHasher(final byte[] key) {
        try {
            final Mac hmacHasher = Mac.getInstance("hmacSHA256");
            hmacHasher.init(makeHMACKey(key));
            return hmacHasher;
        } catch (final NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    /*
     * Hash bytes with given hasher
     * Input: message to hash, HMAC hasher
     * Output: hashed byte[].
     */
    private static byte[] digestBytes(final byte[] message, final Mac hasher) {
        hasher.update(message);
        final byte[] ret = hasher.doFinal();
        hasher.reset();
        return ret;
    }

    /*
 * Helper to convert Hex String to Byte Array
 * Input: Hex string
 * Output: byte[] version of hex string
 */
    private static byte[] hex2Byte(final String str) {
        final String paddedStr = str.length() % 2 == 1 ? "0" + str : str;

        final byte[] bytes = new byte[paddedStr.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(paddedStr.substring(2 * i, 2 * i + 2), 16);
        }
        return bytes;
    }

    /*
     * Helper for array concatenation.
     * Input: At least two byte[]
     * Output: A concatenated version of them
     */
    private static byte[] concatAll(final byte[] first, final byte[]... rest) {
        int totalLength = first.length;
        for (final byte[] array : rest) {
            totalLength += array.length;
        }

        final byte[] result = Arrays.copyOf(first, totalLength);
        int offset = first.length;

        for (final byte[] array : rest) {
            System.arraycopy(array, 0, result, offset, array.length);
            offset += array.length;
        }
        return result;
    }
}
