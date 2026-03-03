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

package io.github.dsheirer.module.decode.p25.phase1.message.hdu;

import io.github.dsheirer.bits.BinaryMessage;
import io.github.dsheirer.module.decode.p25.identifier.encryption.APCO25EncryptionKey;
import io.github.dsheirer.module.decode.p25.reference.Encryption;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for HeaderData encryption detection, including the null-algorithm/null-key unencrypted fix.
 */
public class HeaderDataTest
{
    // HDU binary message bit layout used by HeaderData:
    //   MI_A: bits 0-35, MI_B: bits 36-71, VENDOR_ID: 72-79,
    //   ALGORITHM_ID: 80-87, KEY_ID: 88-103, TALKGROUP_ID: 104-119
    private static final int MESSAGE_SIZE = 120;

    /**
     * Creates a BinaryMessage for HeaderData with the specified algorithm and key,
     * all other fields (MI, vendor, talkgroup) set to zero.
     */
    private BinaryMessage buildMessage(int algorithm, int key)
    {
        BinaryMessage message = new BinaryMessage(MESSAGE_SIZE);
        // Set algorithm in bits 80-87
        for(int i = 0; i < 8; i++)
        {
            if((algorithm & (1 << (7 - i))) != 0)
            {
                message.set(80 + i);
            }
        }
        // Set key in bits 88-103
        for(int i = 0; i < 16; i++)
        {
            if((key & (1 << (15 - i))) != 0)
            {
                message.set(88 + i);
            }
        }
        return message;
    }

    /**
     * When algorithm=0, key=0, and MI is all zeros, HeaderData should report unencrypted.
     * This prevents calls that have all-zero encryption fields from being silently dropped.
     */
    @Test
    public void testAlgorithmZeroKeyZeroZeroMiIsUnencrypted()
    {
        // All bits zero: algorithm=0, key=0, MI=all zeros
        BinaryMessage message = new BinaryMessage(MESSAGE_SIZE);
        HeaderData headerData = new HeaderData(message);

        assertFalse(headerData.isEncryptedAudio(),
            "algorithm=0, key=0, zero MI should be treated as UNENCRYPTED");
        APCO25EncryptionKey encryptionKey = assertInstanceOf(APCO25EncryptionKey.class,
            headerData.getEncryptionKey().getValue(), "Encryption key should be an APCO25EncryptionKey");
        assertEquals(Encryption.UNENCRYPTED, encryptionKey.getEncryptionAlgorithm(),
            "Encryption algorithm should be overridden to UNENCRYPTED");
    }

    /**
     * When algorithm=0x80 (UNENCRYPTED), isEncryptedAudio() should return false.
     */
    @Test
    public void testUnencryptedAlgorithmIsNotEncrypted()
    {
        BinaryMessage message = buildMessage(Encryption.UNENCRYPTED.getValue(), 0);
        HeaderData headerData = new HeaderData(message);

        assertFalse(headerData.isEncryptedAudio(), "UNENCRYPTED algorithm should report not encrypted");
    }

    /**
     * When algorithm=ADP (0xAA), key=0, MI=all zeros, HeaderData should still report encrypted
     * (the null-key fallback is handled in the audio module, not here).
     */
    @Test
    public void testAdpAlgorithmKeyZeroIsEncrypted()
    {
        BinaryMessage message = buildMessage(Encryption.MOTOROLA_ADP.getValue(), 0);
        HeaderData headerData = new HeaderData(message);

        assertTrue(headerData.isEncryptedAudio(),
            "ADP algorithm with key=0 should still be treated as encrypted (null-key fallback in audio module)");
    }

    /**
     * When algorithm=AES_256 (0x84) with a non-zero key, isEncryptedAudio() should return true.
     */
    @Test
    public void testAes256IsEncrypted()
    {
        BinaryMessage message = buildMessage(Encryption.AES_256.getValue(), 0x0001);
        HeaderData headerData = new HeaderData(message);

        assertTrue(headerData.isEncryptedAudio(), "AES-256 with key=1 should be encrypted");
    }
}
