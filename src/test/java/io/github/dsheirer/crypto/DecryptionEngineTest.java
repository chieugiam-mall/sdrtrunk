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

package io.github.dsheirer.crypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Tests for the DecryptionEngine class.
 */
public class DecryptionEngineTest
{
    /**
     * Tests that adding a key allows subsequent RC4 decryption.
     */
    @Test
    public void testRC4DecryptRoundTrip()
    {
        DecryptionEngine engine = new DecryptionEngine();

        byte[] key = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05};
        engine.addKey("0001", "RC4", key);

        // Encrypt plaintext with RC4 manually to produce ciphertext
        byte[] plaintext = new byte[]{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00};
        byte[] ciphertext = encryptRC4Direct(key, plaintext);

        // Decrypt using the engine
        byte[] decrypted = engine.decrypt("0001", ciphertext);

        assertArrayEquals(plaintext, decrypted, "RC4 decryption should recover plaintext");
    }

    /**
     * Tests that decryption returns an empty array when the KID is not registered.
     */
    @Test
    public void testDecryptMissingKidReturnsEmpty()
    {
        DecryptionEngine engine = new DecryptionEngine();
        byte[] result = engine.decrypt("FFFF", new byte[]{0x01, 0x02});
        assertEquals(0, result.length, "Missing KID should return empty byte array");
    }

    /**
     * Tests RC4 decryption with a message indicator (MI).
     * Verifies that encrypt with key+MI seed and decrypt with engine also recovers plaintext.
     */
    @Test
    public void testRC4DecryptWithMIRoundTrip()
    {
        DecryptionEngine engine = new DecryptionEngine();

        byte[] key = new byte[]{0x0A, 0x0B, 0x0C, 0x0D, 0x0E};
        byte[] mi = new byte[]{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, (byte)0x80, (byte)0x90};
        engine.addKey("0002", "RC4", key);

        byte[] plaintext = new byte[18]; // typical IMBE frame size
        for(int i = 0; i < plaintext.length; i++)
        {
            plaintext[i] = (byte)(i + 1);
        }

        // Encrypt by combining MI + key as seed (matching decryptRC4WithMI logic)
        byte[] keySeed = new byte[mi.length + key.length];
        System.arraycopy(mi, 0, keySeed, 0, mi.length);
        System.arraycopy(key, 0, keySeed, mi.length, key.length);
        byte[] ciphertext = encryptRC4Direct(keySeed, plaintext);

        // Decrypt using engine with MI
        byte[] decrypted = engine.decrypt("0002", mi, ciphertext);

        assertArrayEquals(plaintext, decrypted, "RC4+MI decryption should recover plaintext");
    }

    /**
     * Tests that adding and removing a key works correctly.
     */
    @Test
    public void testAddAndRemoveKey()
    {
        DecryptionEngine engine = new DecryptionEngine();

        byte[] key = new byte[]{0x01};
        engine.addKey("ABCD", "RC4", key);
        assertEquals(2, engine.getKeys().size(), "Should have default key plus added key");

        engine.removeKey("ABCD");
        assertEquals(1, engine.getKeys().size(), "Should only have default key after removal");
    }

    /**
     * Tests that decryption with null MI falls back to plain RC4 decryption.
     */
    @Test
    public void testRC4DecryptWithNullMIFallsBack()
    {
        DecryptionEngine engine = new DecryptionEngine();

        byte[] key = new byte[]{0x05, 0x06, 0x07, 0x08, 0x09};
        engine.addKey("0003", "RC4", key);

        byte[] plaintext = new byte[]{(byte)0xAA, (byte)0xBB, (byte)0xCC};
        byte[] ciphertext = encryptRC4Direct(key, plaintext);

        // Passing null MI should fall back to plain decrypt
        byte[] decrypted = engine.decrypt("0003", null, ciphertext);
        assertArrayEquals(plaintext, decrypted, "RC4 decrypt with null MI should fall back to plain decrypt");
    }

    /**
     * Tests that DES decryption round-trips correctly for P25/DMR 8-byte payloads.
     * DES requires an 8-byte key and operates on 8-byte blocks.
     */
    @Test
    public void testDESDecryptRoundTrip()
    {
        DecryptionEngine engine = new DecryptionEngine();

        byte[] key = new byte[]{0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xAB, (byte)0xCD, (byte)0xEF};
        engine.addKey("0010", "DES", key);

        // 8-byte block (no padding / ECB mode)
        byte[] plaintext = new byte[]{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte)0x88};
        byte[] ciphertext = encryptDESDirect(key, plaintext);

        byte[] decrypted = engine.decrypt("0010", ciphertext);

        assertArrayEquals(plaintext, decrypted, "DES decryption should recover plaintext");
    }

    /**
     * Tests that AES-128 decryption round-trips correctly for P25/DMR 16-byte payloads.
     * AES-128 requires a 16-byte key and operates on 16-byte blocks.
     */
    @Test
    public void testAES128DecryptRoundTrip()
    {
        DecryptionEngine engine = new DecryptionEngine();

        byte[] key = new byte[16];
        for(int i = 0; i < key.length; i++)
        {
            key[i] = (byte)(i + 1);
        }
        engine.addKey("0020", "AES", key);

        // 16-byte block (no padding / ECB mode)
        byte[] plaintext = new byte[16];
        for(int i = 0; i < plaintext.length; i++)
        {
            plaintext[i] = (byte)(0x10 + i);
        }
        byte[] ciphertext = encryptAESDirect(key, plaintext);

        byte[] decrypted = engine.decrypt("0020", ciphertext);

        assertArrayEquals(plaintext, decrypted, "AES-128 decryption should recover plaintext");
    }

    /**
     * Tests that AES-256 decryption round-trips correctly.
     * AES-256 requires a 32-byte key and operates on 16-byte blocks.
     */
    @Test
    public void testAES256DecryptRoundTrip()
    {
        DecryptionEngine engine = new DecryptionEngine();

        byte[] key = new byte[32];
        for(int i = 0; i < key.length; i++)
        {
            key[i] = (byte)(i + 1);
        }
        engine.addKey("0030", "AES", key);

        // 16-byte block (no padding / ECB mode)
        byte[] plaintext = new byte[]{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                      (byte)0x88, (byte)0x99, (byte)0xAA, (byte)0xBB,
                                      (byte)0xCC, (byte)0xDD, (byte)0xEE, (byte)0xFF};
        byte[] ciphertext = encryptAESDirect(key, plaintext);

        byte[] decrypted = engine.decrypt("0030", ciphertext);

        assertArrayEquals(plaintext, decrypted, "AES-256 decryption should recover plaintext");
    }

    /**
     * Tests the hexToBytes utility method with valid, null, and invalid inputs.
     */
    @Test
    public void testHexToBytes()
    {
        byte[] result = DecryptionEngine.hexToBytes("AABB");
        assertArrayEquals(new byte[]{(byte)0xAA, (byte)0xBB}, result, "Valid hex should parse correctly");

        assertNull(DecryptionEngine.hexToBytes(null), "Null input should return null");
        assertNull(DecryptionEngine.hexToBytes(""), "Empty input should return null");
        assertNull(DecryptionEngine.hexToBytes("A"), "Odd-length hex should return null");
        assertNull(DecryptionEngine.hexToBytes("ZZ"), "Invalid hex chars should return null");
    }

    /**
     * Tests that decryption using the MI variant falls back to plain DES when MI is null.
     */
    @Test
    public void testDESDecryptWithNullMIFallsBack()
    {
        DecryptionEngine engine = new DecryptionEngine();

        byte[] key = new byte[]{0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xAB, (byte)0xCD, (byte)0xEF};
        engine.addKey("0040", "DES", key);

        byte[] plaintext = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        byte[] ciphertext = encryptDESDirect(key, plaintext);

        byte[] decrypted = engine.decrypt("0040", null, ciphertext);

        assertArrayEquals(plaintext, decrypted, "DES decrypt with null MI should fall back to plain decrypt");
    }

    /**
     * Tests that decryption using the MI variant falls back to plain AES when MI is null.
     */
    @Test
    public void testAESDecryptWithNullMIFallsBack()
    {
        DecryptionEngine engine = new DecryptionEngine();

        byte[] key = new byte[16];
        for(int i = 0; i < key.length; i++)
        {
            key[i] = (byte)(0x20 + i);
        }
        engine.addKey("0050", "AES", key);

        byte[] plaintext = new byte[16];
        for(int i = 0; i < plaintext.length; i++)
        {
            plaintext[i] = (byte)(0x30 + i);
        }
        byte[] ciphertext = encryptAESDirect(key, plaintext);

        byte[] decrypted = engine.decrypt("0050", null, ciphertext);

        assertArrayEquals(plaintext, decrypted, "AES decrypt with null MI should fall back to plain decrypt");
    }

    /**
     * Helper method to encrypt bytes using Java's DES/ECB/NoPadding cipher.
     */
    private static byte[] encryptDESDirect(byte[] key, byte[] plaintext)
    {
        try
        {
            javax.crypto.spec.SecretKeySpec secretKey = new javax.crypto.spec.SecretKeySpec(key, "DES");
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("DES/ECB/NoPadding");
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, secretKey);
            return cipher.doFinal(plaintext);
        }
        catch(Exception e)
        {
            throw new RuntimeException("Test helper DES encryption failed", e);
        }
    }

    /**
     * Helper method to encrypt bytes using Java's AES/ECB/NoPadding cipher.
     */
    private static byte[] encryptAESDirect(byte[] key, byte[] plaintext)
    {
        try
        {
            javax.crypto.spec.SecretKeySpec secretKey = new javax.crypto.spec.SecretKeySpec(key, "AES");
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, secretKey);
            return cipher.doFinal(plaintext);
        }
        catch(Exception e)
        {
            throw new RuntimeException("Test helper AES encryption failed", e);
        }
    }

    /**
     * Helper method to encrypt bytes using Java's RC4 (ARCFOUR) cipher.
     */
    private static byte[] encryptRC4Direct(byte[] key, byte[] plaintext)
    {
        try
        {
            javax.crypto.spec.SecretKeySpec secretKey = new javax.crypto.spec.SecretKeySpec(key, "ARCFOUR");
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("ARCFOUR");
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, secretKey);
            return cipher.doFinal(plaintext);
        }
        catch(Exception e)
        {
            throw new RuntimeException("Test helper encryption failed", e);
        }
    }
}
