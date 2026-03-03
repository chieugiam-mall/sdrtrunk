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

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
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
 * Keys must be explicitly added via {@link #addKey(String, String, byte[])} before decryption is attempted.
 */
public class DecryptionEngine
{
    private static final Logger mLog = LoggerFactory.getLogger(DecryptionEngine.class);

    private final Map<String, EncryptionKey> mKeys = new ConcurrentHashMap<>();

    /**
     * Constructs an empty DecryptionEngine.  Keys must be added via {@link #addKey(String, String, byte[])}
     * before decryption can be performed.
     */
    public DecryptionEngine()
    {
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
            mLog.debug("No key found for KID [{}] - skipping decryption", kid);
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

    /**
     * Decrypts the provided ciphertext using the key registered for the given KID, incorporating the message
     * indicator (MI) as additional key material for stream ciphers such as RC4.
     *
     * @param kid             Key ID string
     * @param messageIndicator 9-byte message indicator / initialization vector (may be null or empty)
     * @param ciphertext      Encrypted bytes
     * @return Decrypted bytes, or an empty byte array on failure
     */
    public byte[] decrypt(String kid, byte[] messageIndicator, byte[] ciphertext)
    {
        EncryptionKey key = mKeys.get(kid);

        if(key == null)
        {
            mLog.debug("No key found for KID [{}] - skipping decryption", kid);
            return new byte[0];
        }

        try
        {
            if("RC4".equals(key.getAlgorithm()) && messageIndicator != null && messageIndicator.length > 0)
            {
                return decryptRC4WithMI(key.getRawKey(), messageIndicator, ciphertext);
            }

            return decryptWithKey(key, ciphertext);
        }
        catch(Exception e)
        {
            mLog.error("Decryption failed for KID [{}] algorithm [{}]", kid, key.getAlgorithm(), e);
            return new byte[0];
        }
    }

    /**
     * Decrypts using RC4 (ARCFOUR) with a null (all-zero) key combined with the message indicator.
     * This is used for Motorola ADP (40-bit RC4) calls with key ID 0 (null key), where no key has been
     * registered in the engine.  The null key for 40-bit ADP is 5 zero bytes.
     *
     * @param messageIndicator per-call message indicator bytes
     * @param keyLength        length of the null key in bytes (e.g. 5 for 40-bit ADP)
     * @param ciphertext       encrypted bytes
     * @return decrypted bytes, or an empty byte array on failure
     */
    public byte[] decryptWithNullKeyRC4(byte[] messageIndicator, int keyLength, byte[] ciphertext)
    {
        try
        {
            byte[] nullKey = new byte[keyLength];
            return decryptRC4WithMI(nullKey, messageIndicator, ciphertext);
        }
        catch(Exception e)
        {
            mLog.error("Null-key RC4 decryption failed", e);
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

    /**
     * Decrypts using RC4 (ARCFOUR) with a key seed derived by combining the user key and the message indicator.
     * The key seed is formed by concatenating the MI bytes followed by the raw key bytes, providing per-call
     * uniqueness consistent with P25 ADP usage.
     */
    private byte[] decryptRC4WithMI(byte[] rawKey, byte[] mi, byte[] ciphertext) throws Exception
    {
        byte[] keySeed = new byte[mi.length + rawKey.length];
        System.arraycopy(mi, 0, keySeed, 0, mi.length);
        System.arraycopy(rawKey, 0, keySeed, mi.length, rawKey.length);
        SecretKey secretKey = new SecretKeySpec(keySeed, "ARCFOUR");
        Cipher cipher = Cipher.getInstance("ARCFOUR");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(ciphertext);
    }

    private byte[] decryptDES(byte[] rawKey, byte[] ciphertext) throws Exception
    {
        // ECB mode is used here for compatibility with P25/DMR radio protocol encrypted payloads,
        // which do not use IV-based modes for over-the-air transmission.
        SecretKey secretKey = new SecretKeySpec(rawKey, "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(ciphertext);
    }

    private byte[] decryptAES(byte[] rawKey, byte[] ciphertext) throws Exception
    {
        // ECB mode is used here for compatibility with P25/DMR radio protocol encrypted payloads,
        // which do not use IV-based modes for over-the-air transmission.
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

    /**
     * Saves all registered keys to the specified JSON file.
     * Each entry contains "kid", "algorithm", and "key" (hex-encoded).
     *
     * @param filePath destination file path
     * @throws IOException on write failure
     */
    public void save(Path filePath) throws IOException
    {
        List<Map<String, String>> list = new ArrayList<>();

        for(EncryptionKey key : getKeys())
        {
            Map<String, String> entry = new LinkedHashMap<>();
            entry.put("kid", key.getKid());
            entry.put("algorithm", key.getAlgorithm());
            entry.put("key", bytesToHex(key.getRawKey()));
            list.add(entry);
        }

        Gson gson = new Gson();
        Files.write(filePath, gson.toJson(list).getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Loads keys from the specified JSON file into this engine.
     * Existing keys are not cleared; entries in the file are added/replaced.
     * Silently returns if the file does not exist.
     *
     * @param filePath source file path
     * @throws IOException on read failure
     */
    public void load(Path filePath) throws IOException
    {
        if(!Files.exists(filePath))
        {
            return;
        }

        String json = new String(Files.readAllBytes(filePath), StandardCharsets.UTF_8);
        Gson gson = new Gson();
        Type listType = new TypeToken<List<Map<String, String>>>()
        {
        }.getType();
        List<Map<String, String>> list = gson.fromJson(json, listType);

        if(list == null)
        {
            return;
        }

        for(Map<String, String> entry : list)
        {
            String kid = entry.get("kid");
            String algorithm = entry.get("algorithm");
            byte[] keyBytes = hexToBytes(entry.get("key"));

            if(kid != null && algorithm != null && keyBytes != null)
            {
                addKey(kid, algorithm, keyBytes);
            }
            else
            {
                mLog.warn("Skipping malformed key entry in [{}]: kid={} algorithm={} keyPresent={}",
                        filePath, kid, algorithm, keyBytes != null);
            }
        }
    }

    /**
     * Encodes a byte array as an uppercase hex string.
     *
     * @param bytes byte array to encode
     * @return hex string
     */
    private static String bytesToHex(byte[] bytes)
    {
        StringBuilder sb = new StringBuilder(bytes.length * 2);

        for(byte b : bytes)
        {
            sb.append(String.format("%02X", b));
        }

        return sb.toString();
    }

    /**
     * Parses a hex string into a byte array.
     *
     * @param hex Hex string (even length, valid hex digits). May be null or empty.
     * @return Parsed byte array, or null if the input is null, empty, or invalid.
     */
    public static byte[] hexToBytes(String hex)
    {
        if(hex == null || hex.isEmpty() || hex.length() % 2 != 0)
        {
            return null;
        }

        try
        {
            byte[] bytes = new byte[hex.length() / 2];
            for(int i = 0; i < hex.length(); i += 2)
            {
                bytes[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
            }
            return bytes;
        }
        catch(NumberFormatException e)
        {
            return null;
        }
    }
}
