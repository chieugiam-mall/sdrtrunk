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
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Tests for the DecryptionEngine class.
 */
public class DecryptionEngineTest
{
    @TempDir
    Path tempDir;
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
        assertEquals(1, engine.getKeys().size(), "Should have one key after adding");

        engine.removeKey("ABCD");
        assertEquals(0, engine.getKeys().size(), "Should have no keys after removal");
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
     * Tests that save() writes keys to disk and load() restores them into a fresh engine.
     */
    @Test
    public void testSaveAndLoad() throws IOException
    {
        DecryptionEngine engine = new DecryptionEngine();
        engine.addKey("0001", "AES", new byte[]{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10});
        engine.addKey("0002", "RC4", new byte[]{0x11, 0x22, 0x33});

        Path file = tempDir.resolve("test_keys.json");
        engine.save(file);

        DecryptionEngine loaded = new DecryptionEngine();
        loaded.load(file);

        assertEquals(2, loaded.getKeys().size(), "Loaded engine should have 2 keys");
        assertEquals(1, loaded.getKeys().stream().filter(k -> "0001".equals(k.getKid())).count(),
                "KID 0001 should be present");
        assertEquals(1, loaded.getKeys().stream().filter(k -> "0002".equals(k.getKid())).count(),
                "KID 0002 should be present");
    }

    /**
     * Tests that load() on a non-existent file is silently ignored.
     */
    @Test
    public void testLoadMissingFileIsIgnored() throws IOException
    {
        DecryptionEngine engine = new DecryptionEngine();
        engine.load(tempDir.resolve("nonexistent.json"));
        assertEquals(0, engine.getKeys().size(), "Loading a missing file should leave engine empty");
    }

    /**
     * Tests that save() followed by load() preserves key bytes faithfully.
     */
    @Test
    public void testSaveAndLoadPreservesKeyBytes() throws IOException
    {
        byte[] key = new byte[]{0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xAB, (byte)0xCD, (byte)0xEF};
        DecryptionEngine engine = new DecryptionEngine();
        engine.addKey("0010", "DES", key);

        Path file = tempDir.resolve("keys.json");
        engine.save(file);

        DecryptionEngine loaded = new DecryptionEngine();
        loaded.load(file);

        assertEquals(1, loaded.getKeys().size());
        assertArrayEquals(key, loaded.getKeys().get(0).getRawKey(), "Key bytes should survive save/load round-trip");
    }

    /**
     * Tests that decryptWithNullKeyRC4 correctly decrypts data encrypted with a null (all-zero) key.
     * This simulates Motorola ADP (40-bit RC4) with key ID 0 (null key).
     */
    @Test
    public void testDecryptWithNullKeyRC4RoundTrip()
    {
        DecryptionEngine engine = new DecryptionEngine();

        byte[] mi = new byte[]{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, (byte)0x80, (byte)0x90};
        byte[] nullKey = new byte[5]; // 40-bit null key (all zeros)
        byte[] plaintext = new byte[18]; // typical IMBE frame size
        for(int i = 0; i < plaintext.length; i++)
        {
            plaintext[i] = (byte)(i + 0x40);
        }

        // Encrypt with null key + MI (same as decryptRC4WithMI logic: seed = MI + key)
        byte[] keySeed = new byte[mi.length + nullKey.length];
        System.arraycopy(mi, 0, keySeed, 0, mi.length);
        System.arraycopy(nullKey, 0, keySeed, mi.length, nullKey.length);
        byte[] ciphertext = encryptRC4Direct(keySeed, plaintext);

        // Decrypt using the null-key method
        byte[] decrypted = engine.decryptWithNullKeyRC4(mi, 5, ciphertext);

        assertArrayEquals(plaintext, decrypted, "decryptWithNullKeyRC4 should recover plaintext encrypted with null key");
    }

    /**
     * Tests that decryptWithNullKeyRC4 returns empty bytes when ciphertext is null-equivalent empty.
     */
    @Test
    public void testDecryptWithNullKeyRC4EmptyCiphertext()
    {
        DecryptionEngine engine = new DecryptionEngine();
        byte[] mi = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
        // RC4 of empty returns empty - not an error
        byte[] result = engine.decryptWithNullKeyRC4(mi, 5, new byte[0]);
        assertEquals(0, result.length, "Empty ciphertext should produce empty result");
    }

    /**
     * Tests that decryptWithRC4Key correctly decrypts using a supplied raw key + MI.
     * This is the method used for per-talkgroup alias-based key lookup.
     */
    @Test
    public void testDecryptWithRC4KeyRoundTrip()
    {
        DecryptionEngine engine = new DecryptionEngine();

        byte[] key = new byte[]{0x0A, 0x0B, 0x0C, 0x0D, 0x0E};
        byte[] mi = new byte[]{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, (byte)0x80, (byte)0x90};
        byte[] plaintext = new byte[18];
        for(int i = 0; i < plaintext.length; i++)
        {
            plaintext[i] = (byte)(i + 0x50);
        }

        // Encrypt using MI+key seed (matching decryptRC4WithMI logic)
        byte[] keySeed = new byte[mi.length + key.length];
        System.arraycopy(mi, 0, keySeed, 0, mi.length);
        System.arraycopy(key, 0, keySeed, mi.length, key.length);
        byte[] ciphertext = encryptRC4Direct(keySeed, plaintext);

        byte[] decrypted = engine.decryptWithRC4Key(mi, key, ciphertext);

        assertArrayEquals(plaintext, decrypted, "decryptWithRC4Key should recover plaintext");
    }

    /**
     * Tests that decryptWithRC4Key with null MI falls back to plain RC4.
     */
    @Test
    public void testDecryptWithRC4KeyNullMIFallsBack()
    {
        DecryptionEngine engine = new DecryptionEngine();

        byte[] key = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05};
        byte[] plaintext = new byte[]{0x11, 0x22, 0x33, 0x44, 0x55};
        byte[] ciphertext = encryptRC4Direct(key, plaintext);

        byte[] decrypted = engine.decryptWithRC4Key(null, key, ciphertext);

        assertArrayEquals(plaintext, decrypted, "decryptWithRC4Key with null MI should fall back to plain RC4");
    }

    /**
     * Tests that decryptWithAlgorithmAndKey works for AES.
     */
    @Test
    public void testDecryptWithAlgorithmAndKeyAES()
    {
        DecryptionEngine engine = new DecryptionEngine();

        byte[] key = new byte[16];
        for(int i = 0; i < key.length; i++)
        {
            key[i] = (byte)(i + 1);
        }
        byte[] plaintext = new byte[16];
        for(int i = 0; i < plaintext.length; i++)
        {
            plaintext[i] = (byte)(0x40 + i);
        }
        byte[] ciphertext = encryptAESDirect(key, plaintext);

        byte[] decrypted = engine.decryptWithAlgorithmAndKey("AES", key, ciphertext);

        assertArrayEquals(plaintext, decrypted, "decryptWithAlgorithmAndKey AES should recover plaintext");
    }

    /**
     * Tests that decryptWithAlgorithmAndKey returns empty for unknown algorithm.
     */
    @Test
    public void testDecryptWithAlgorithmAndKeyUnknownAlgorithmReturnsEmpty()
    {
        DecryptionEngine engine = new DecryptionEngine();
        byte[] key = new byte[]{0x01, 0x02, 0x03};
        byte[] result = engine.decryptWithAlgorithmAndKey("UNKNOWN", key, new byte[]{0x01, 0x02});
        assertEquals(0, result.length, "Unknown algorithm should return empty byte array");
    }

    /**
     * Tests that DES decryption works with a non-block-aligned ciphertext (18-byte IMBE frame).
     * The engine should zero-pad to a block boundary, decrypt, and trim back to the original length.
     */
    @Test
    public void testDESDecryptNonBlockAligned()
    {
        DecryptionEngine engine = new DecryptionEngine();

        byte[] key = new byte[]{0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xAB, (byte)0xCD, (byte)0xEF};
        engine.addKey("CC10", "DES", key);

        // Simulate an 18-byte IMBE frame (18 % 8 != 0)
        byte[] plaintext = new byte[18];
        for(int i = 0; i < plaintext.length; i++)
        {
            plaintext[i] = (byte)(i + 1);
        }

        // Encrypt the padded block, then trim to 18 bytes to simulate over-the-air ciphertext
        byte[] padded = new byte[24]; // next multiple of 8 after 18
        System.arraycopy(plaintext, 0, padded, 0, plaintext.length);
        byte[] encryptedPadded = encryptDESDirect(key, padded);
        byte[] ciphertext = new byte[18];
        System.arraycopy(encryptedPadded, 0, ciphertext, 0, 18);

        byte[] decrypted = engine.decrypt("CC10", ciphertext);

        assertEquals(18, decrypted.length, "Decrypted length should match original ciphertext length");
        // Only the first 16 bytes (2 full DES blocks) can round-trip correctly;
        // the partial 3rd block is corrupted by zero-padding different ciphertext bytes.
        assertArrayEquals(Arrays.copyOfRange(plaintext, 0, 16), Arrays.copyOfRange(decrypted, 0, 16),
            "DES decryption of full blocks in non-block-aligned ciphertext should recover plaintext");
    }

    /**
     * Tests that AES decryption works with a non-block-aligned ciphertext (18-byte payload, 18 % 16 != 0).
     * The engine should zero-pad to a block boundary, decrypt, and trim back to the original length.
     */
    @Test
    public void testAESDecryptNonBlockAligned()
    {
        DecryptionEngine engine = new DecryptionEngine();

        byte[] key = new byte[16];
        for(int i = 0; i < key.length; i++)
        {
            key[i] = (byte)(i + 1);
        }
        engine.addKey("CC20", "AES", key);

        // 18-byte payload (18 % 16 != 0)
        byte[] plaintext = new byte[18];
        for(int i = 0; i < plaintext.length; i++)
        {
            plaintext[i] = (byte)(0x10 + i);
        }

        // Encrypt the padded block, then trim to 18 bytes to simulate over-the-air ciphertext
        byte[] padded = new byte[32]; // next multiple of 16 after 18
        System.arraycopy(plaintext, 0, padded, 0, plaintext.length);
        byte[] encryptedPadded = encryptAESDirect(key, padded);
        byte[] ciphertext = new byte[18];
        System.arraycopy(encryptedPadded, 0, ciphertext, 0, 18);

        byte[] decrypted = engine.decrypt("CC20", ciphertext);

        assertEquals(18, decrypted.length, "Decrypted length should match original ciphertext length");
        // Only the first 16 bytes (1 full AES block) can round-trip correctly;
        // the partial 2nd block is corrupted by zero-padding different ciphertext bytes.
        assertArrayEquals(Arrays.copyOfRange(plaintext, 0, 16), Arrays.copyOfRange(decrypted, 0, 16),
            "AES decryption of full block in non-block-aligned ciphertext should recover plaintext");
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

    /**
     * Tests that decryptRC4WithMI falls back to Key||MI seed order when MI||Key produces all-identical bytes.
     * This verifies the dual-order feature handles Motorola/OP25 systems that use Key||MI concatenation.
     *
     * The plaintext is crafted so that decrypting with the wrong seed (MI||Key) produces all 0x42 bytes
     * (fails the "not all identical" heuristic), causing the engine to fall back to the correct Key||MI order.
     */
    @Test
    public void testRC4DecryptWithKeyMIOrderFallback()
    {
        DecryptionEngine engine = new DecryptionEngine();

        byte[] key = new byte[]{0x0A, 0x0B, 0x0C, 0x0D, 0x0E};
        byte[] mi = new byte[]{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, (byte)0x80, (byte)0x90};
        engine.addKey("TEST1", "RC4", key);

        int frameSize = 18;

        // Compute keystreams for both seed orders by encrypting zeros
        byte[] wrongSeed = new byte[mi.length + key.length]; // MI || Key
        System.arraycopy(mi, 0, wrongSeed, 0, mi.length);
        System.arraycopy(key, 0, wrongSeed, mi.length, key.length);

        byte[] correctSeed = new byte[key.length + mi.length]; // Key || MI
        System.arraycopy(key, 0, correctSeed, 0, key.length);
        System.arraycopy(mi, 0, correctSeed, key.length, mi.length);

        byte[] wrongKeystream = encryptRC4Direct(wrongSeed, new byte[frameSize]);
        byte[] correctKeystream = encryptRC4Direct(correctSeed, new byte[frameSize]);

        // Craft plaintext so MI||Key decryption produces all 0x42 (fails the all-identical heuristic).
        // Construction: plaintext[i] = wrongKeystream[i] XOR correctKeystream[i] XOR 0x42
        // Then: ciphertext[i] = correctKeystream[i] XOR plaintext[i]
        //                     = correctKeystream[i] XOR wrongKeystream[i] XOR correctKeystream[i] XOR 0x42
        //                     = wrongKeystream[i] XOR 0x42
        // So: RC4_decrypt(wrongSeed, ciphertext)[i] = wrongKeystream[i] XOR ciphertext[i]
        //                                           = wrongKeystream[i] XOR wrongKeystream[i] XOR 0x42 = 0x42
        // And: RC4_decrypt(correctSeed, ciphertext)[i] = correctKeystream[i] XOR ciphertext[i] = plaintext[i]
        byte[] plaintext = new byte[frameSize];
        for(int i = 0; i < frameSize; i++)
        {
            plaintext[i] = (byte)(wrongKeystream[i] ^ correctKeystream[i] ^ 0x42);
        }

        // Encrypt plaintext with correct seed (Key || MI)
        byte[] ciphertext = encryptRC4Direct(correctSeed, plaintext);

        // Engine should fall back to Key||MI order and recover plaintext
        byte[] decrypted = engine.decrypt("TEST1", mi, ciphertext);

        assertArrayEquals(plaintext, decrypted, "RC4+MI decryption should fall back to Key||MI seed order");
    }

    /**
     * Regression test: verifies that MI||Key seed order (the original P25 ADP behavior) still works correctly.
     * Ensures the dual-order feature does not break the standard case.
     */
    @Test
    public void testRC4DecryptWithMIKeyOrderRegression()
    {
        DecryptionEngine engine = new DecryptionEngine();

        byte[] key = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05};
        byte[] mi = new byte[]{(byte)0xAA, (byte)0xBB, (byte)0xCC, (byte)0xDD, (byte)0xEE, (byte)0xFF, 0x11, 0x22, 0x33};
        engine.addKey("TEST2", "RC4", key);

        byte[] plaintext = new byte[18];
        for(int i = 0; i < plaintext.length; i++)
        {
            plaintext[i] = (byte)(i + 0x20);
        }

        // Encrypt with MI||Key seed (standard P25 ADP order)
        byte[] miKeySeed = new byte[mi.length + key.length];
        System.arraycopy(mi, 0, miKeySeed, 0, mi.length);
        System.arraycopy(key, 0, miKeySeed, mi.length, key.length);
        byte[] ciphertext = encryptRC4Direct(miKeySeed, plaintext);

        // Engine should succeed with the primary MI||Key order
        byte[] decrypted = engine.decrypt("TEST2", mi, ciphertext);

        assertArrayEquals(plaintext, decrypted, "RC4+MI decryption should still work with standard MI||Key seed order");
    }

    /**
     * Tests that addKey normalizes KID to uppercase and lookup succeeds regardless of input case.
     */
    @Test
    public void testAddKeyNormalizesKIDToUpperCase()
    {
        DecryptionEngine engine = new DecryptionEngine();

        byte[] key = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05};
        engine.addKey("cc14", "RC4", key);

        // Should be stored as "CC14" - getKeys() should reflect uppercase
        assertEquals(1, engine.getKeys().size(), "Should have one key");
        assertEquals("CC14", engine.getKeys().get(0).getKid(), "KID should be stored as uppercase");
    }

    /**
     * Tests that decrypt with an uppercase KID finds a key stored with lowercase KID.
     */
    @Test
    public void testDecryptCaseInsensitiveLowerAddUpperLookup()
    {
        DecryptionEngine engine = new DecryptionEngine();

        byte[] key = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05};
        engine.addKey("cc14", "RC4", key);

        byte[] plaintext = new byte[]{0x11, 0x22, 0x33, 0x44, 0x55};
        byte[] ciphertext = encryptRC4Direct(key, plaintext);

        // Lookup with uppercase KID (as produced by String.format("%04X", ...))
        byte[] decrypted = engine.decrypt("CC14", ciphertext);

        assertArrayEquals(plaintext, decrypted, "decrypt with uppercase KID should find key stored with lowercase KID");
    }

    /**
     * Tests that decrypt with a mixed-case KID finds the key.
     */
    @Test
    public void testDecryptCaseInsensitiveMixedCase()
    {
        DecryptionEngine engine = new DecryptionEngine();

        byte[] key = new byte[]{0x0A, 0x0B, 0x0C, 0x0D, 0x0E};
        engine.addKey("Cc14", "RC4", key);

        byte[] plaintext = new byte[]{0x11, 0x22, 0x33};
        byte[] ciphertext = encryptRC4Direct(key, plaintext);

        byte[] decrypted = engine.decrypt("cC14", ciphertext);

        assertArrayEquals(plaintext, decrypted, "decrypt with mixed-case KID should find key");
    }

    /**
     * Tests that removeKey with lowercase KID removes a key stored with uppercase KID.
     */
    @Test
    public void testRemoveKeyCaseInsensitive()
    {
        DecryptionEngine engine = new DecryptionEngine();

        byte[] key = new byte[]{0x01};
        engine.addKey("CC14", "RC4", key);
        assertEquals(1, engine.getKeys().size(), "Should have one key after adding");

        engine.removeKey("cc14");
        assertEquals(0, engine.getKeys().size(), "Should have no keys after case-insensitive removal");
    }

    /**
     * Tests that getRawKeyBytesForKID is case-insensitive.
     */
    @Test
    public void testGetRawKeyBytesForKIDCaseInsensitive()
    {
        DecryptionEngine engine = new DecryptionEngine();

        byte[] key = new byte[]{0x01, 0x02, 0x03};
        engine.addKey("cc14", "RC4", key);

        byte[] retrieved = engine.getRawKeyBytesForKID("CC14");
        assertArrayEquals(key, retrieved, "getRawKeyBytesForKID should be case-insensitive");
    }

    /**
     * Tests that getAlgorithmForKID returns the algorithm for the given KID case-insensitively.
     */
    @Test
    public void testGetAlgorithmForKIDCaseInsensitive()
    {
        DecryptionEngine engine = new DecryptionEngine();

        byte[] key = new byte[]{0x01, 0x02, 0x03};
        engine.addKey("cc14", "DES", key);

        assertEquals("DES", engine.getAlgorithmForKID("CC14"), "getAlgorithmForKID should be case-insensitive");
        assertNull(engine.getAlgorithmForKID("FFFF"), "getAlgorithmForKID should return null for unknown KID");
    }

    /**
     * Tests that DES-OFB decryption with a message indicator round-trips correctly.
     * P25 DES-OFB (algorithm ID 0x81) uses the first 8 bytes of the 9-byte MI as the 64-bit IV.
     */
    @Test
    public void testDESOFBDecryptWithMIRoundTrip()
    {
        DecryptionEngine engine = new DecryptionEngine();

        byte[] key = new byte[]{0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xAB, (byte)0xCD, (byte)0xEF};
        byte[] mi = new byte[]{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, (byte)0x80, (byte)0x90};
        engine.addKey("0081", "DES", key);

        byte[] plaintext = new byte[18]; // typical IMBE frame size
        for(int i = 0; i < plaintext.length; i++)
        {
            plaintext[i] = (byte)(i + 1);
        }

        byte[] ciphertext = encryptDESOFBDirect(key, mi, plaintext);
        byte[] decrypted = engine.decrypt("0081", mi, ciphertext);

        assertArrayEquals(plaintext, decrypted, "DES-OFB decryption with MI should recover plaintext");
    }

    /**
     * Tests that AES-256-OFB decryption with a message indicator round-trips correctly.
     * P25 AES-256 (algorithm ID 0x84) uses the 9-byte MI zero-padded to 16 bytes as the 128-bit IV.
     */
    @Test
    public void testAES256OFBDecryptWithMIRoundTrip()
    {
        DecryptionEngine engine = new DecryptionEngine();

        byte[] key = new byte[32];
        for(int i = 0; i < key.length; i++)
        {
            key[i] = (byte)(i + 1);
        }
        byte[] mi = new byte[]{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, (byte)0x80, (byte)0x90};
        engine.addKey("0084", "AES", key);

        byte[] plaintext = new byte[18]; // typical IMBE frame size
        for(int i = 0; i < plaintext.length; i++)
        {
            plaintext[i] = (byte)(0x40 + i);
        }

        byte[] ciphertext = encryptAESOFBDirect(key, mi, plaintext);
        byte[] decrypted = engine.decrypt("0084", mi, ciphertext);

        assertArrayEquals(plaintext, decrypted, "AES-256-OFB decryption with MI should recover plaintext");
    }

    /**
     * Tests that AES-128-OFB decryption with a message indicator round-trips correctly.
     * P25 AES-128-OFB (algorithm ID 0x89) uses the 9-byte MI zero-padded to 16 bytes as the 128-bit IV.
     */
    @Test
    public void testAES128OFBDecryptWithMIRoundTrip()
    {
        DecryptionEngine engine = new DecryptionEngine();

        byte[] key = new byte[16];
        for(int i = 0; i < key.length; i++)
        {
            key[i] = (byte)(0x20 + i);
        }
        byte[] mi = new byte[]{(byte)0xAA, (byte)0xBB, (byte)0xCC, (byte)0xDD, (byte)0xEE, (byte)0xFF, 0x11, 0x22, 0x33};
        engine.addKey("0089", "AES", key);

        byte[] plaintext = new byte[18];
        for(int i = 0; i < plaintext.length; i++)
        {
            plaintext[i] = (byte)(0x60 + i);
        }

        byte[] ciphertext = encryptAESOFBDirect(key, mi, plaintext);
        byte[] decrypted = engine.decrypt("0089", mi, ciphertext);

        assertArrayEquals(plaintext, decrypted, "AES-128-OFB decryption with MI should recover plaintext");
    }

    /**
     * Tests that decryptWithAlgorithmAndKey works for DES-OFB when MI is provided.
     */
    @Test
    public void testDecryptWithAlgorithmAndKeyDESOFB()
    {
        DecryptionEngine engine = new DecryptionEngine();

        byte[] key = new byte[]{0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xAB, (byte)0xCD, (byte)0xEF};
        byte[] mi = new byte[]{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, (byte)0x80, (byte)0x90};

        byte[] plaintext = new byte[18];
        for(int i = 0; i < plaintext.length; i++)
        {
            plaintext[i] = (byte)(i + 0x30);
        }

        byte[] ciphertext = encryptDESOFBDirect(key, mi, plaintext);
        byte[] decrypted = engine.decryptWithAlgorithmAndKey("DES", key, mi, ciphertext);

        assertArrayEquals(plaintext, decrypted, "decryptWithAlgorithmAndKey DES-OFB should recover plaintext");
    }

    /**
     * Tests that decryptWithAlgorithmAndKey works for AES-OFB when MI is provided.
     */
    @Test
    public void testDecryptWithAlgorithmAndKeyAESOFB()
    {
        DecryptionEngine engine = new DecryptionEngine();

        byte[] key = new byte[32];
        for(int i = 0; i < key.length; i++)
        {
            key[i] = (byte)(i + 1);
        }
        byte[] mi = new byte[]{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, (byte)0x80, (byte)0x90};

        byte[] plaintext = new byte[18];
        for(int i = 0; i < plaintext.length; i++)
        {
            plaintext[i] = (byte)(0x50 + i);
        }

        byte[] ciphertext = encryptAESOFBDirect(key, mi, plaintext);
        byte[] decrypted = engine.decryptWithAlgorithmAndKey("AES", key, mi, ciphertext);

        assertArrayEquals(plaintext, decrypted, "decryptWithAlgorithmAndKey AES-OFB should recover plaintext");
    }

    /**
     * Tests that DES with null MI in the 3-arg decrypt method still uses ECB mode (backward compatibility).
     */
    @Test
    public void testDESDecryptWithNullMIStillUsesECB()
    {
        DecryptionEngine engine = new DecryptionEngine();

        byte[] key = new byte[]{0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xAB, (byte)0xCD, (byte)0xEF};
        engine.addKey("0099", "DES", key);

        byte[] plaintext = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        byte[] ciphertext = encryptDESDirect(key, plaintext);

        // With null MI, should fall back to ECB mode
        byte[] decrypted = engine.decrypt("0099", null, ciphertext);

        assertArrayEquals(plaintext, decrypted, "DES decrypt with null MI should still use ECB mode");
    }

    /**
     * Tests that AES with empty MI in the 3-arg decrypt method still uses ECB mode (backward compatibility).
     */
    @Test
    public void testAESDecryptWithEmptyMIStillUsesECB()
    {
        DecryptionEngine engine = new DecryptionEngine();

        byte[] key = new byte[16];
        for(int i = 0; i < key.length; i++)
        {
            key[i] = (byte)(0x20 + i);
        }
        engine.addKey("009A", "AES", key);

        byte[] plaintext = new byte[16];
        for(int i = 0; i < plaintext.length; i++)
        {
            plaintext[i] = (byte)(0x30 + i);
        }
        byte[] ciphertext = encryptAESDirect(key, plaintext);

        // With empty MI, should fall back to ECB mode
        byte[] decrypted = engine.decrypt("009A", new byte[0], ciphertext);

        assertArrayEquals(plaintext, decrypted, "AES decrypt with empty MI should still use ECB mode");
    }

    /**
     * Helper method to encrypt bytes using Java's DES/OFB/NoPadding cipher with an IV derived from the MI.
     */
    private static byte[] encryptDESOFBDirect(byte[] key, byte[] mi, byte[] plaintext)
    {
        try
        {
            javax.crypto.spec.SecretKeySpec secretKey = new javax.crypto.spec.SecretKeySpec(key, "DES");
            byte[] desIv = new byte[8];
            System.arraycopy(mi, 0, desIv, 0, Math.min(mi.length, 8));
            javax.crypto.spec.IvParameterSpec ivSpec = new javax.crypto.spec.IvParameterSpec(desIv);
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("DES/OFB/NoPadding");
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, secretKey, ivSpec);
            return cipher.doFinal(plaintext);
        }
        catch(Exception e)
        {
            throw new RuntimeException("Test helper DES-OFB encryption failed", e);
        }
    }

    /**
     * Helper method to encrypt bytes using Java's AES/OFB/NoPadding cipher with an IV derived from the MI.
     */
    private static byte[] encryptAESOFBDirect(byte[] key, byte[] mi, byte[] plaintext)
    {
        try
        {
            javax.crypto.spec.SecretKeySpec secretKey = new javax.crypto.spec.SecretKeySpec(key, "AES");
            byte[] aesIv = new byte[16];
            System.arraycopy(mi, 0, aesIv, 0, Math.min(mi.length, 16));
            javax.crypto.spec.IvParameterSpec ivSpec = new javax.crypto.spec.IvParameterSpec(aesIv);
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/OFB/NoPadding");
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, secretKey, ivSpec);
            return cipher.doFinal(plaintext);
        }
        catch(Exception e)
        {
            throw new RuntimeException("Test helper AES-OFB encryption failed", e);
        }
    }
}
