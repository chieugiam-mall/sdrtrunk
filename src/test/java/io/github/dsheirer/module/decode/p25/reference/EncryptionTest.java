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

package io.github.dsheirer.module.decode.p25.reference;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Tests for the Encryption enum fromValue() lookup.
 */
public class EncryptionTest
{
    @Test
    public void testFromValueAesCbc()
    {
        assertEquals(Encryption.AES_CBC, Encryption.fromValue(0x88),
            "AES-CBC (0x88) should resolve to AES_CBC, not UNKNOWN");
    }

    @Test
    public void testFromValueAes128Ofb()
    {
        assertEquals(Encryption.AES_128_OFB, Encryption.fromValue(0x89),
            "AES-128-OFB (0x89) should resolve to AES_128_OFB, not UNKNOWN");
    }

    @Test
    public void testFromValueDesOfb()
    {
        assertEquals(Encryption.DES_OFB, Encryption.fromValue(0x81));
    }

    @Test
    public void testFromValueAes256()
    {
        assertEquals(Encryption.AES_256, Encryption.fromValue(0x84));
    }

    @Test
    public void testFromValueAes128()
    {
        assertEquals(Encryption.AES_128, Encryption.fromValue(0x85));
    }

    @Test
    public void testFromValueUnencrypted()
    {
        assertEquals(Encryption.UNENCRYPTED, Encryption.fromValue(0x80));
    }

    @Test
    public void testFromValueUnknown()
    {
        assertEquals(Encryption.UNKNOWN, Encryption.fromValue(0xFF));
    }

    @Test
    public void testToDecryptionAlgorithmDesOfb()
    {
        assertEquals("DES", Encryption.DES_OFB.toDecryptionAlgorithm(),
            "DES-OFB (0x81) should map to DES decryption algorithm");
    }

    @Test
    public void testToDecryptionAlgorithmAes256()
    {
        assertEquals("AES", Encryption.AES_256.toDecryptionAlgorithm(),
            "AES-256 (0x84) should map to AES decryption algorithm");
    }

    @Test
    public void testToDecryptionAlgorithmAes128()
    {
        assertEquals("AES", Encryption.AES_128.toDecryptionAlgorithm(),
            "AES-128 (0x85) should map to AES decryption algorithm");
    }

    @Test
    public void testToDecryptionAlgorithmAesCbc()
    {
        assertEquals("AES", Encryption.AES_CBC.toDecryptionAlgorithm(),
            "AES-CBC (0x88) should map to AES decryption algorithm");
    }

    @Test
    public void testToDecryptionAlgorithmAes128Ofb()
    {
        assertEquals("AES", Encryption.AES_128_OFB.toDecryptionAlgorithm(),
            "AES-128-OFB (0x89) should map to AES decryption algorithm");
    }

    @Test
    public void testToDecryptionAlgorithmMotorolaAdp()
    {
        assertEquals("RC4", Encryption.MOTOROLA_ADP.toDecryptionAlgorithm(),
            "Motorola ADP (0xAA) should map to RC4 decryption algorithm");
    }

    @Test
    public void testToDecryptionAlgorithmDesXl()
    {
        assertEquals("DES", Encryption.DES_XL.toDecryptionAlgorithm(),
            "DES-XL (0x9F) should map to DES decryption algorithm");
    }

    @Test
    public void testToDecryptionAlgorithmDvpXl()
    {
        assertEquals("RC4", Encryption.DVP_XL.toDecryptionAlgorithm(),
            "DVP-XL (0xA1) should map to RC4 decryption algorithm");
    }

    @Test
    public void testToDecryptionAlgorithmTripleDes2Key()
    {
        assertEquals("DES", Encryption.TRIPLE_DES_2_KEY.toDecryptionAlgorithm(),
            "2-Key Triple DES (0x82) should map to DES decryption algorithm");
    }

    @Test
    public void testToDecryptionAlgorithmTripleDes3Key()
    {
        assertEquals("DES", Encryption.TRIPLE_DES_3_KEY.toDecryptionAlgorithm(),
            "3-Key Triple DES (0x83) should map to DES decryption algorithm");
    }

    @Test
    public void testToDecryptionAlgorithmMotorolaAf()
    {
        assertEquals("AES", Encryption.MOTOROLA_AF.toDecryptionAlgorithm(),
            "Motorola AES-256-GCM (0xAF) should map to AES decryption algorithm");
    }

    @Test
    public void testToDecryptionAlgorithmUnencrypted()
    {
        assertNull(Encryption.UNENCRYPTED.toDecryptionAlgorithm(),
            "UNENCRYPTED should return null for decryption algorithm");
    }

    @Test
    public void testToDecryptionAlgorithmUnknown()
    {
        assertNull(Encryption.UNKNOWN.toDecryptionAlgorithm(),
            "UNKNOWN should return null for decryption algorithm");
    }

    @Test
    public void testToDecryptionAlgorithmStaticMethod()
    {
        assertEquals("DES", Encryption.toDecryptionAlgorithm(0x81),
            "Static toDecryptionAlgorithm(0x81) should return DES");
        assertEquals("AES", Encryption.toDecryptionAlgorithm(0x84),
            "Static toDecryptionAlgorithm(0x84) should return AES");
        assertEquals("RC4", Encryption.toDecryptionAlgorithm(0xAA),
            "Static toDecryptionAlgorithm(0xAA) should return RC4");
        assertNull(Encryption.toDecryptionAlgorithm(0x80),
            "Static toDecryptionAlgorithm(0x80) should return null for UNENCRYPTED");
        assertNull(Encryption.toDecryptionAlgorithm(0xFF),
            "Static toDecryptionAlgorithm(0xFF) should return null for unknown");
    }
}
