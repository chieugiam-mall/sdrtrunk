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

package io.github.dsheirer.alias.id.encryption;

import io.github.dsheirer.alias.id.AliasIDType;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for the EncryptionKeyID alias ID class.
 */
public class EncryptionKeyIDTest
{
    /**
     * Tests that a valid RC4 key ID is correctly constructed and parses key bytes.
     */
    @Test
    public void testValidRC4KeyID()
    {
        EncryptionKeyID keyID = new EncryptionKeyID("RC4", "0A0B0C0D0E");

        assertEquals(AliasIDType.ENCRYPTION_KEY, keyID.getType());
        assertEquals("RC4", keyID.getAlgorithm());
        assertEquals("0A0B0C0D0E", keyID.getKey());
        assertTrue(keyID.isValid(), "Valid RC4 key should be valid");
        assertFalse(keyID.isAudioIdentifier(), "Encryption key is not an audio identifier");

        byte[] expected = new byte[]{0x0A, 0x0B, 0x0C, 0x0D, 0x0E};
        assertArrayEquals(expected, keyID.getRawKeyBytes(), "Key bytes should match parsed hex");
    }

    /**
     * Tests that a valid AES key ID is correctly constructed.
     */
    @Test
    public void testValidAESKeyID()
    {
        EncryptionKeyID keyID = new EncryptionKeyID("AES", "0102030405060708090A0B0C0D0E0F10");

        assertEquals("AES", keyID.getAlgorithm());
        assertTrue(keyID.isValid(), "Valid AES key should be valid");
        assertEquals(16, keyID.getRawKeyBytes().length, "AES-128 key should be 16 bytes");
    }

    /**
     * Tests that an empty key string is flagged as invalid.
     */
    @Test
    public void testEmptyKeyIsInvalid()
    {
        EncryptionKeyID keyID = new EncryptionKeyID("RC4", "");

        assertFalse(keyID.isValid(), "Empty key should be invalid");
        assertNull(keyID.getRawKeyBytes(), "Empty key should return null raw bytes");
    }

    /**
     * Tests that an odd-length hex string is flagged as invalid.
     */
    @Test
    public void testOddLengthKeyIsInvalid()
    {
        EncryptionKeyID keyID = new EncryptionKeyID("RC4", "0A0");

        assertFalse(keyID.isValid(), "Odd-length hex key should be invalid");
        assertNull(keyID.getRawKeyBytes(), "Odd-length key should return null raw bytes");
    }

    /**
     * Tests that an invalid hex string is flagged as invalid.
     */
    @Test
    public void testInvalidHexKeyIsInvalid()
    {
        EncryptionKeyID keyID = new EncryptionKeyID("RC4", "XXYY");

        assertFalse(keyID.isValid(), "Invalid hex key should be invalid");
        assertNull(keyID.getRawKeyBytes(), "Invalid hex key should return null raw bytes");
    }

    /**
     * Tests that an empty algorithm is flagged as invalid.
     */
    @Test
    public void testEmptyAlgorithmIsInvalid()
    {
        EncryptionKeyID keyID = new EncryptionKeyID("", "AABB");

        assertFalse(keyID.isValid(), "Empty algorithm should be invalid");
    }

    /**
     * Tests that the default constructor produces an invalid object (requires configuration).
     */
    @Test
    public void testDefaultConstructorProducesInvalidObject()
    {
        EncryptionKeyID keyID = new EncryptionKeyID();

        assertFalse(keyID.isValid(), "Default-constructed EncryptionKeyID should be invalid (empty key)");
    }

    /**
     * Tests that toString produces a masked key representation.
     */
    @Test
    public void testToStringMasksKey()
    {
        EncryptionKeyID keyID = new EncryptionKeyID("RC4", "0A0B0C0D0E");

        String str = keyID.toString();
        assertTrue(str.contains("RC4"), "toString should contain algorithm name");
        assertTrue(str.contains("0D0E"), "toString should show last 4 hex chars");
        assertFalse(str.contains("0A0B"), "toString should not expose full key");
    }

    /**
     * Tests that matches() always returns false (encryption key IDs are not matching identifiers).
     */
    @Test
    public void testMatchesReturnsFalse()
    {
        EncryptionKeyID keyID1 = new EncryptionKeyID("RC4", "AABB");
        EncryptionKeyID keyID2 = new EncryptionKeyID("RC4", "AABB");

        assertFalse(keyID1.matches(keyID2), "matches() should always return false");
    }
}
