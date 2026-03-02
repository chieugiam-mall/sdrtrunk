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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Decryption engine supporting RC4 (ARCFOUR), DES, and AES algorithms.
 * Keys are stored in a thread-safe map keyed by their KID string.
 * KID "0000" is always pre-loaded with a default all-zero AES-128 key.
 */
public class DecryptionEngine
{
    private static final Logger mLog = LoggerFactory.getLogger(DecryptionEngine.class);

    private final Map<String, EncryptionKey> mKeys = new ConcurrentHashMap<>();

    /**
     * Constructs a DecryptionEngine and registers the default KID "0000"
     * bootstrap key (all-zero 16-byte AES-128).
     */
    public DecryptionEngine()
    {
        addKey("0000", "AES", new byte[16]);
    }

    /**
     * Adds or replaces a key for the given KID.
     *
     * @param kid       Key ID string
     * @param algorithm One of "RC4", "DES", or "AES"
     * @param keyBytes  Raw key bytes
     */
    public void addKey(String kid, String algorithm, byte[] keyBytes)
    {
        mKeys.put(kid, new EncryptionKey(kid, algorithm, keyBytes));
    }

    /**
     * Removes the key for the given KID.
     *
     * @param kid Key ID string
     */
    public void removeKey(String kid)
    {
        mKeys.remove(kid);
    }

    /**
     * Decrypts the provided ciphertext using the key registered for the given KID.
     *
     * @param kid        Key ID string
     * @param ciphertext Encrypted bytes
     * @return Decrypted bytes, or an empty byte array on failure
     */
    public byte[] decrypt(String kid, byte[] ciphertext)
    {
        EncryptionKey key = mKeys.get(kid);

        if(key == null)
        {
            mLog.warn("No key found for KID [{}]", kid);
            return new byte[0];
        }

        try
        {
            return decryptWithKey(key, ciphertext);
        }
        catch(Exception e)
        {
            mLog.error("Decryption failed for KID [{}] algorithm [{}]", kid, key.getAlgorithm(), e);
            return new byte[0];
        }
    }

    /**
     * Performs the actual decryption dispatch based on algorithm.
     */
    private byte[] decryptWithKey(EncryptionKey key, byte[] ciphertext) throws Exception
    {
        String algorithm = key.getAlgorithm();
        byte[] rawKey = key.getRawKey();

        switch(algorithm)
        {
            case "RC4":
                return decryptRC4(rawKey, ciphertext);
            case "DES":
                return decryptDES(rawKey, ciphertext);
            case "AES":
                return decryptAES(rawKey, ciphertext);
            default:
                mLog.error("Unknown algorithm [{}]", algorithm);
                return new byte[0];
        }
    }

    private byte[] decryptRC4(byte[] rawKey, byte[] ciphertext) throws Exception
    {
        SecretKey secretKey = new SecretKeySpec(rawKey, "ARCFOUR");
        Cipher cipher = Cipher.getInstance("ARCFOUR");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(ciphertext);
    }

    private byte[] decryptDES(byte[] rawKey, byte[] ciphertext) throws Exception
    {
        SecretKey secretKey = new SecretKeySpec(rawKey, "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(ciphertext);
    }

    private byte[] decryptAES(byte[] rawKey, byte[] ciphertext) throws Exception
    {
        SecretKey secretKey = new SecretKeySpec(rawKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(ciphertext);
    }

    /**
     * Returns an unmodifiable list of all registered encryption keys.
     */
    public List<EncryptionKey> getKeys()
    {
        return Collections.unmodifiableList(new ArrayList<>(mKeys.values()));
    }
}
