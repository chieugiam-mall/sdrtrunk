/*
 * *****************************************************************************
 * Copyright (C) 2014-2025 Dennis Sheirer
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 * ****************************************************************************
 */

// Part of the crypto subsystem for RC4/DES/AES decryption key management.
package io.github.dsheirer.crypto;

/**
 * Model class holding a Key ID (KID), algorithm name, and raw key bytes.
 * The actual key bytes are never exposed in string form; only a masked
 * representation is available for display.
 */
public class EncryptionKey
{
    private final String mKid;
    private final String mAlgorithm;
    private final byte[] mKeyBytes;

    /**
     * Constructs an EncryptionKey.
     *
     * @param kid       Key ID string, e.g. "0001"
     * @param algorithm One of "RC4", "DES", or "AES"
     * @param keyBytes  Raw key bytes
     */
    public EncryptionKey(String kid, String algorithm, byte[] keyBytes)
    {
        mKid = kid;
        mAlgorithm = algorithm;
        mKeyBytes = keyBytes.clone();
    }

    /**
     * Returns the Key ID.
     */
    public String getKid()
    {
        return mKid;
    }

    /**
     * Returns the algorithm name (RC4, DES, or AES).
     */
    public String getAlgorithm()
    {
        return mAlgorithm;
    }

    /**
     * Returns a masked representation of the key, showing only the last 2 bytes
     * in hex. The full key is never returned as a string.
     */
    public String getMaskedKey()
    {
        if(mKeyBytes.length >= 2)
        {
            return "\u2022\u2022\u2022\u2022" +
                String.format("%02X%02X", mKeyBytes[mKeyBytes.length - 2], mKeyBytes[mKeyBytes.length - 1]);
        }
        return "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022";
    }

    /**
     * Returns a copy of the raw key bytes. Only intended for use by DecryptionEngine.
     */
    public byte[] getRawKey()
    {
        return mKeyBytes.clone();
    }
}
