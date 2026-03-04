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
import javax.crypto.spec.IvParameterSpec;
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
        String upperKid = kid.toUpperCase();
        mKeys.put(upperKid, new EncryptionKey(upperKid, algorithm, keyBytes));
    }

    /**
     * Removes the key for the given KID.
     *
     * @param kid Key ID string
     */
    public void removeKey(String kid)
    {
        mKeys.remove(kid.toUpperCase());
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
        EncryptionKey key = mKeys.get(kid.toUpperCase());

        if(key == null)
        {
            mLog.warn("No key found for KID [{}] - skipping decryption (ciphertextLen={})", kid,
                    ciphertext != null ? ciphertext.length : 0);
            return new byte[0];
        }

        try
        {
            return decryptWithKey(key, ciphertext);
        }
        catch(Exception e)
        {
            mLog.error("Decryption failed for KID [{}] algorithm [{}] ciphertextLen=[{}]",
                    kid, key.getAlgorithm(), ciphertext != null ? ciphertext.length : 0, e);
            return new byte[0];
        }
    }

    /**
     * Returns the raw key bytes for the given KID if registered, or null if not found.
     * Intended for talkgroup key caching in audio modules.
     *
     * @param kid Key ID string
     * @return Raw key bytes copy, or null if not found
     */
    public byte[] getRawKeyBytesForKID(String kid)
    {
        EncryptionKey key = mKeys.get(kid.toUpperCase());
        return key != null ? key.getRawKey() : null;
    }

    /**
     * Returns the algorithm name for the given KID if registered, or null if not found.
     *
     * @param kid Key ID string
     * @return Algorithm string (e.g. "RC4", "DES", "AES"), or null if not found
     */
    public String getAlgorithmForKID(String kid)
    {
        EncryptionKey key = mKeys.get(kid.toUpperCase());
        return key != null ? key.getAlgorithm() : null;
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
        EncryptionKey key = mKeys.get(kid.toUpperCase());

        if(key == null)
        {
            mLog.warn("No key found for KID [{}] - skipping decryption (miLen={} ciphertextLen={})", kid,
                    messageIndicator != null ? messageIndicator.length : 0,
                    ciphertext != null ? ciphertext.length : 0);
            return new byte[0];
        }

        try
        {
            if(messageIndicator != null && messageIndicator.length > 0)
            {
                if("RC4".equals(key.getAlgorithm()))
                {
                    return decryptRC4WithMI(key.getRawKey(), messageIndicator, ciphertext);
                }
                if("DES".equals(key.getAlgorithm()))
                {
                    return decryptDESOFB(key.getRawKey(), messageIndicator, ciphertext);
                }
                if("AES".equals(key.getAlgorithm()))
                {
                    return decryptAESOFB(key.getRawKey(), messageIndicator, ciphertext);
                }
            }

            return decryptWithKey(key, ciphertext);
        }
        catch(Exception e)
        {
            mLog.error("Decryption failed for KID [{}] algorithm [{}] ciphertextLen=[{}]",
                    kid, key.getAlgorithm(), ciphertext != null ? ciphertext.length : 0, e);
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
        mLog.warn("Attempting null-key RC4 decryption (keyLen={} miLen={} ciphertextLen={})", keyLength,
                messageIndicator != null ? messageIndicator.length : 0,
                ciphertext != null ? ciphertext.length : 0);
        try
        {
            byte[] nullKey = new byte[keyLength];
            return decryptRC4WithMI(nullKey, messageIndicator, ciphertext);
        }
        catch(Exception e)
        {
            mLog.error("Null-key RC4 decryption failed (ciphertextLen={})",
                    ciphertext != null ? ciphertext.length : 0, e);
            return new byte[0];
        }
    }

    /**
     * Decrypts the provided ciphertext using the given raw RC4 key combined with the message indicator.
     * This method is used for per-talkgroup alias-based key lookup, where the caller supplies the raw
     * key bytes directly rather than looking them up by KID.
     *
     * @param messageIndicator per-call message indicator bytes (may be null or empty, falls back to plain RC4)
     * @param rawKey           raw key bytes for the RC4 cipher
     * @param ciphertext       encrypted bytes
     * @return decrypted bytes, or an empty byte array on failure
     */
    public byte[] decryptWithRC4Key(byte[] messageIndicator, byte[] rawKey, byte[] ciphertext)
    {
        try
        {
            byte[] result;
            if(messageIndicator != null && messageIndicator.length > 0)
            {
                result = decryptRC4WithMI(rawKey, messageIndicator, ciphertext);
            }
            else
            {
                result = decryptRC4(rawKey, ciphertext);
            }
            if(result.length > 0)
            {
                mLog.info("RC4 alias-key decryption succeeded (ciphertextLen={})",
                        ciphertext != null ? ciphertext.length : 0);
            }
            return result;
        }
        catch(Exception e)
        {
            mLog.error("RC4 alias-key decryption failed (ciphertextLen={})",
                    ciphertext != null ? ciphertext.length : 0, e);
            return new byte[0];
        }
    }

    /**
     * Decrypts the provided ciphertext using the given algorithm name and raw key bytes.
     * This method is used for per-talkgroup alias-based key lookup for non-RC4 algorithms.
     *
     * @param algorithm  algorithm name: "DES" or "AES"
     * @param rawKey     raw key bytes
     * @param ciphertext encrypted bytes
     * @return decrypted bytes, or an empty byte array on failure
     */
    public byte[] decryptWithAlgorithmAndKey(String algorithm, byte[] rawKey, byte[] ciphertext)
    {
        return decryptWithAlgorithmAndKey(algorithm, rawKey, null, ciphertext);
    }

    /**
     * Decrypts the provided ciphertext using the given algorithm name, raw key bytes, and optional message
     * indicator.  When a non-null message indicator is provided, DES and AES use OFB mode with the MI as the
     * initialization vector, consistent with P25 DES-OFB and AES-OFB specifications.
     *
     * @param algorithm        algorithm name: "DES" or "AES"
     * @param rawKey           raw key bytes
     * @param messageIndicator per-call message indicator bytes (may be null for ECB fallback)
     * @param ciphertext       encrypted bytes
     * @return decrypted bytes, or an empty byte array on failure
     */
    public byte[] decryptWithAlgorithmAndKey(String algorithm, byte[] rawKey, byte[] messageIndicator,
                                             byte[] ciphertext)
    {
        try
        {
            if(messageIndicator != null && messageIndicator.length > 0)
            {
                if("DES".equals(algorithm))
                {
                    return decryptDESOFB(rawKey, messageIndicator, ciphertext);
                }
                if("AES".equals(algorithm))
                {
                    return decryptAESOFB(rawKey, messageIndicator, ciphertext);
                }
            }

            EncryptionKey tempKey = new EncryptionKey("alias", algorithm, rawKey);
            return decryptWithKey(tempKey, ciphertext);
        }
        catch(Exception e)
        {
            mLog.error("Alias-key decryption failed for algorithm [{}]", algorithm, e);
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
     * First tries the seed order MI||Key (consistent with P25 ADP usage), validates the result with a
     * simple heuristic, and falls back to the alternate Key||MI order if the first result appears invalid.
     * Returns the first result if neither order passes validation, to maintain backward compatibility.
     */
    private byte[] decryptRC4WithMI(byte[] rawKey, byte[] mi, byte[] ciphertext) throws Exception
    {
        // First attempt: MI || Key (standard P25 ADP order)
        byte[] keySeed1 = new byte[mi.length + rawKey.length];
        System.arraycopy(mi, 0, keySeed1, 0, mi.length);
        System.arraycopy(rawKey, 0, keySeed1, mi.length, rawKey.length);
        SecretKey secretKey1 = new SecretKeySpec(keySeed1, "ARCFOUR");
        Cipher cipher1 = Cipher.getInstance("ARCFOUR");
        cipher1.init(Cipher.DECRYPT_MODE, secretKey1);
        byte[] result1 = cipher1.doFinal(ciphertext);

        if(isPlausibleDecryption(result1))
        {
            return result1;
        }

        // Second attempt: Key || MI (alternate Motorola/OP25 order)
        byte[] keySeed2 = new byte[rawKey.length + mi.length];
        System.arraycopy(rawKey, 0, keySeed2, 0, rawKey.length);
        System.arraycopy(mi, 0, keySeed2, rawKey.length, mi.length);
        SecretKey secretKey2 = new SecretKeySpec(keySeed2, "ARCFOUR");
        Cipher cipher2 = Cipher.getInstance("ARCFOUR");
        cipher2.init(Cipher.DECRYPT_MODE, secretKey2);
        byte[] result2 = cipher2.doFinal(ciphertext);

        if(isPlausibleDecryption(result2))
        {
            mLog.debug("RC4+MI decryption succeeded with Key||MI seed order (fell back from MI||Key)");
            return result2;
        }

        // Neither order passed validation; return first result for backward compatibility
        return result1;
    }

    /**
     * Returns true if the decrypted bytes appear plausible — i.e., not all bytes are identical.
     * This is a simple heuristic used to detect obviously wrong RC4 key seed ordering.
     *
     * @param bytes decrypted byte array to validate
     * @return true if at least two bytes differ, false if all bytes are identical or the array is empty
     */
    private boolean isPlausibleDecryption(byte[] bytes)
    {
        if(bytes == null || bytes.length == 0)
        {
            return false;
        }
        byte first = bytes[0];
        for(int i = 1; i < bytes.length; i++)
        {
            if(bytes[i] != first)
            {
                return true;
            }
        }
        return false;
    }

    private byte[] decryptDES(byte[] rawKey, byte[] ciphertext) throws Exception
    {
        // ECB mode is used here for compatibility with P25/DMR radio protocol encrypted payloads,
        // which do not use IV-based modes for over-the-air transmission.
        SecretKey secretKey = new SecretKeySpec(rawKey, "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        int originalLength = ciphertext.length;
        int blockSize = cipher.getBlockSize(); // 8 for DES

        if(originalLength % blockSize != 0)
        {
            int paddedLength = ((originalLength / blockSize) + 1) * blockSize;
            byte[] padded = new byte[paddedLength];
            System.arraycopy(ciphertext, 0, padded, 0, originalLength);
            byte[] decrypted = cipher.doFinal(padded);
            byte[] trimmed = new byte[originalLength];
            System.arraycopy(decrypted, 0, trimmed, 0, originalLength);
            return trimmed;
        }

        return cipher.doFinal(ciphertext);
    }

    private byte[] decryptAES(byte[] rawKey, byte[] ciphertext) throws Exception
    {
        // ECB mode is used here for compatibility with P25/DMR radio protocol encrypted payloads,
        // which do not use IV-based modes for over-the-air transmission.
        SecretKey secretKey = new SecretKeySpec(rawKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        int originalLength = ciphertext.length;
        int blockSize = cipher.getBlockSize(); // 16 for AES

        if(originalLength % blockSize != 0)
        {
            int paddedLength = ((originalLength / blockSize) + 1) * blockSize;
            byte[] padded = new byte[paddedLength];
            System.arraycopy(ciphertext, 0, padded, 0, originalLength);
            byte[] decrypted = cipher.doFinal(padded);
            byte[] trimmed = new byte[originalLength];
            System.arraycopy(decrypted, 0, trimmed, 0, originalLength);
            return trimmed;
        }

        return cipher.doFinal(ciphertext);
    }

    /**
     * Decrypts using DES in OFB (Output Feedback) mode with the message indicator as the initialization vector.
     * P25 DES-OFB (algorithm ID 0x81) uses the first 8 bytes of the MI as the 64-bit IV.
     * OFB mode operates as a stream cipher so no block-alignment padding is needed.
     *
     * @param rawKey     8-byte DES key
     * @param iv         message indicator bytes (first 8 bytes used as IV)
     * @param ciphertext encrypted bytes
     * @return decrypted bytes
     */
    private byte[] decryptDESOFB(byte[] rawKey, byte[] iv, byte[] ciphertext) throws Exception
    {
        SecretKey secretKey = new SecretKeySpec(rawKey, "DES");
        byte[] desIv = new byte[8];
        System.arraycopy(iv, 0, desIv, 0, Math.min(iv.length, 8));
        IvParameterSpec ivSpec = new IvParameterSpec(desIv);
        Cipher cipher = Cipher.getInstance("DES/OFB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        return cipher.doFinal(ciphertext);
    }

    /**
     * Decrypts using AES in OFB (Output Feedback) mode with the message indicator as the initialization vector.
     * P25 AES-256 (algorithm ID 0x84) and AES-128-OFB (algorithm ID 0x89) use the MI zero-padded to 16 bytes
     * as the 128-bit IV.
     * OFB mode operates as a stream cipher so no block-alignment padding is needed.
     *
     * @param rawKey     16-byte (AES-128) or 32-byte (AES-256) key
     * @param iv         message indicator bytes (zero-padded to 16 bytes for the IV)
     * @param ciphertext encrypted bytes
     * @return decrypted bytes
     */
    private byte[] decryptAESOFB(byte[] rawKey, byte[] iv, byte[] ciphertext) throws Exception
    {
        SecretKey secretKey = new SecretKeySpec(rawKey, "AES");
        byte[] aesIv = new byte[16];
        System.arraycopy(iv, 0, aesIv, 0, Math.min(iv.length, 16));
        IvParameterSpec ivSpec = new IvParameterSpec(aesIv);
        Cipher cipher = Cipher.getInstance("AES/OFB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
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
