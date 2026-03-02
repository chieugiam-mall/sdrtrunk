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
}
