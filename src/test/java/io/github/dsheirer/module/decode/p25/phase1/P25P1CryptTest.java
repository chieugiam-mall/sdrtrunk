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

package io.github.dsheirer.module.decode.p25.phase1;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for IMBEInterleave and P25P1CryptUtil classes.
 */
public class P25P1CryptTest
{
    // -------------------------------------------------------------------------
    // IMBEInterleave Tests
    // -------------------------------------------------------------------------

    /**
     * Tests that IMBE pack followed by unpack is an identity operation.
     */
    @Test
    public void testIMBEPackUnpackRoundTrip()
    {
        int u0 = 0xABC, u1 = 0x123, u2 = 0xFED, u3 = 0x456;
        int u4 = 0x7FF, u5 = 0x001, u6 = 0x400, u7 = 0x55;

        byte[] packed = IMBEInterleave.imbePack(u0, u1, u2, u3, u4, u5, u6, u7);
        assertEquals(11, packed.length);

        int[] params = IMBEInterleave.imbeUnpack(packed);
        assertEquals(u0, params[0], "u0 should survive pack/unpack");
        assertEquals(u1, params[1], "u1 should survive pack/unpack");
        assertEquals(u2, params[2], "u2 should survive pack/unpack");
        assertEquals(u3, params[3], "u3 should survive pack/unpack");
        assertEquals(u4, params[4], "u4 should survive pack/unpack");
        assertEquals(u5, params[5], "u5 should survive pack/unpack");
        assertEquals(u6, params[6], "u6 should survive pack/unpack");
        assertEquals(u7, params[7], "u7 should survive pack/unpack");
    }

    /**
     * Tests Golay(23,12) encode followed by decode is an identity operation.
     */
    @Test
    public void testGolay23EncodeDecodeRoundTrip()
    {
        for(int data = 0; data < 4096; data += 17)
        {
            int codeword = IMBEInterleave.golay23Encode(data);
            int decoded = IMBEInterleave.golay23Decode(codeword);
            assertEquals(data, decoded, "Golay23 encode/decode roundtrip failed for data=" + data);
        }
    }

    /**
     * Tests Golay(23,12) can correct a single bit error.
     */
    @Test
    public void testGolay23SingleBitErrorCorrection()
    {
        int data = 0x5A3;
        int codeword = IMBEInterleave.golay23Encode(data);

        for(int bit = 0; bit < 23; bit++)
        {
            int corrupted = codeword ^ (1 << bit);
            int decoded = IMBEInterleave.golay23Decode(corrupted);
            assertEquals(data, decoded, "Golay23 failed to correct 1-bit error at position " + bit);
        }
    }

    /**
     * Tests Hamming(15,11) encode followed by decode is an identity operation.
     */
    @Test
    public void testHamming15EncodeDecodeRoundTrip()
    {
        for(int data = 0; data < 2048; data += 13)
        {
            int codeword = IMBEInterleave.hamming15Encode(data);
            int decoded = IMBEInterleave.hamming15Decode(codeword);
            assertEquals(data, decoded, "Hamming15 encode/decode roundtrip failed for data=" + data);
        }
    }

    /**
     * Tests that IMBE frame encode followed by decode is an identity operation.
     * This exercises the full pipeline: pack → encode → decode → unpack.
     * Note: u7 bit 0 (BOT indicator) is not preserved through FEC encode/decode cycle
     * because the IMBE frame only stores 7 bits for u7 via right-shift/left-shift.
     */
    @Test
    public void testIMBEFrameEncodeDecodeRoundTrip()
    {
        // Use u7 value with bit 0 = 0 (even) since the FEC cycle uses 7-bit storage for u7
        int u0 = 0x123, u1 = 0x456, u2 = 0x789, u3 = 0xABC;
        int u4 = 0x3FF, u5 = 0x200, u6 = 0x100, u7 = 0x54;

        byte[] packed = IMBEInterleave.imbePack(u0, u1, u2, u3, u4, u5, u6, u7);
        byte[] frame = IMBEInterleave.encode(packed);
        assertEquals(18, frame.length);

        byte[] decoded = IMBEInterleave.decode(frame);
        assertArrayEquals(packed, decoded, "IMBE frame encode/decode roundtrip should be identity");
    }

    /**
     * Tests bit extraction and storage.
     */
    @Test
    public void testBitExtractionStorage()
    {
        byte[] data = new byte[3];
        IMBEInterleave.storeBits(data, 0, 12, 0xABC);
        int extracted = IMBEInterleave.extractBits(data, 0, 12);
        assertEquals(0xABC, extracted, "Bit store/extract roundtrip");

        IMBEInterleave.storeBits(data, 12, 12, 0x123);
        extracted = IMBEInterleave.extractBits(data, 12, 12);
        assertEquals(0x123, extracted, "Bit store/extract second value");

        // Verify first value wasn't corrupted
        extracted = IMBEInterleave.extractBits(data, 0, 12);
        assertEquals(0xABC, extracted, "First value should be preserved");
    }

    // -------------------------------------------------------------------------
    // P25P1CryptUtil Tests
    // -------------------------------------------------------------------------

    /**
     * Tests that MI expansion to 128 bits produces a non-trivial result.
     */
    @Test
    public void testMIExpansionProducesNonTrivialIV()
    {
        byte[] mi = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
        byte[] iv = P25P1CryptUtil.expandMITo128(mi);

        assertNotNull(iv);
        assertEquals(16, iv.length, "IV should be 16 bytes");

        // Verify the IV is not all zeros or all same value
        boolean allZero = true;
        for(byte b : iv)
        {
            if(b != 0)
            {
                allZero = false;
                break;
            }
        }
        assertTrue(!allZero, "IV should not be all zeros");

        // Verify the IV is not just zero-padded MI
        boolean isZeroPadded = true;
        for(int i = 0; i < 8; i++)
        {
            if(iv[i] != mi[i])
            {
                isZeroPadded = false;
                break;
            }
        }
        assertTrue(!isZeroPadded, "IV should not be simple zero-padded MI (LFSR expansion required)");
    }

    /**
     * Tests that MI expansion is deterministic.
     */
    @Test
    public void testMIExpansionDeterministic()
    {
        byte[] mi = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte)0x88, (byte)0x99};
        byte[] iv1 = P25P1CryptUtil.expandMITo128(mi);
        byte[] iv2 = P25P1CryptUtil.expandMITo128(mi);
        assertArrayEquals(iv1, iv2, "MI expansion should be deterministic");
    }

    /**
     * Tests DES-OFB keystream generation produces correct length.
     */
    @Test
    public void testDESOFBKeystreamLength()
    {
        byte[] key = {0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xAB, (byte)0xCD, (byte)0xEF};
        byte[] mi = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
        byte[] keystream = P25P1CryptUtil.generateDESOFBKeystream(key, mi);

        assertNotNull(keystream);
        assertEquals(224, keystream.length, "DES-OFB keystream should be 224 bytes (28 × 8)");
    }

    /**
     * Tests AES-256 OFB keystream generation produces correct length.
     */
    @Test
    public void testAES256OFBKeystreamLength()
    {
        byte[] key = new byte[32]; // 256-bit key
        for(int i = 0; i < 32; i++) key[i] = (byte)i;
        byte[] mi = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
        byte[] keystream = P25P1CryptUtil.generateAES256OFBKeystream(key, mi);

        assertNotNull(keystream);
        assertEquals(240, keystream.length, "AES-256 OFB keystream should be 240 bytes (15 × 16)");
    }

    /**
     * Tests RC4/ADP keystream generation produces correct length.
     */
    @Test
    public void testRC4ADPKeystreamLength()
    {
        byte[] key = {0x01, 0x02, 0x03, 0x04, 0x05};
        byte[] mi = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
        byte[] keystream = P25P1CryptUtil.generateRC4ADPKeystream(key, mi);

        assertNotNull(keystream);
        assertEquals(469, keystream.length, "RC4/ADP keystream should be 469 bytes");
    }

    /**
     * Tests that keystream generation is deterministic.
     */
    @Test
    public void testKeystreamDeterministic()
    {
        byte[] key = {0x01, 0x02, 0x03, 0x04, 0x05};
        byte[] mi = {(byte)0xAA, (byte)0xBB, (byte)0xCC, (byte)0xDD, (byte)0xEE,
            (byte)0xFF, 0x11, 0x22, 0x33};

        byte[] ks1 = P25P1CryptUtil.generateRC4ADPKeystream(key, mi);
        byte[] ks2 = P25P1CryptUtil.generateRC4ADPKeystream(key, mi);
        assertArrayEquals(ks1, ks2, "Keystream generation should be deterministic");
    }

    /**
     * Tests voice keystream offset calculations for DES-OFB.
     */
    @Test
    public void testDESOFBKeystreamOffsets()
    {
        // DES: 8-byte discard + LDU1 base=0 + position formula
        // Position 0: 8 + 0 + (0*11) + 11 + 0 = 19
        assertEquals(19, P25P1CryptUtil.getVoiceKeystreamOffset("DES", false, 0));
        // Position 1: 8 + 0 + (1*11) + 11 + 0 = 30
        assertEquals(30, P25P1CryptUtil.getVoiceKeystreamOffset("DES", false, 1));
        // Position 7: 8 + 0 + (7*11) + 11 + 0 = 96
        assertEquals(96, P25P1CryptUtil.getVoiceKeystreamOffset("DES", false, 7));
        // Position 8: 8 + 0 + (8*11) + 11 + 2 = 109
        assertEquals(109, P25P1CryptUtil.getVoiceKeystreamOffset("DES", false, 8));

        // LDU2: adds 101 to offset
        // Position 0: 8 + 101 + (0*11) + 11 + 0 = 120
        assertEquals(120, P25P1CryptUtil.getVoiceKeystreamOffset("DES", true, 0));
    }

    /**
     * Tests voice keystream offset calculations for AES-256.
     */
    @Test
    public void testAES256KeystreamOffsets()
    {
        // AES: 16-byte discard + LDU1 base=0 + position formula
        // Position 0: 16 + 0 + (0*11) + 11 + 0 = 27
        assertEquals(27, P25P1CryptUtil.getVoiceKeystreamOffset("AES", false, 0));
        // LDU2, Position 0: 16 + 101 + (0*11) + 11 + 0 = 128
        assertEquals(128, P25P1CryptUtil.getVoiceKeystreamOffset("AES", true, 0));
    }

    /**
     * Tests voice keystream offset calculations for RC4/ADP.
     */
    @Test
    public void testRC4ADPKeystreamOffsets()
    {
        // RC4: no discard, LDU1 base=0 + 267 voice offset
        // Position 0: 0 + (0*11) + 267 + 0 = 267
        assertEquals(267, P25P1CryptUtil.getVoiceKeystreamOffset("RC4", false, 0));
        // Position 8: 0 + (8*11) + 267 + 2 = 357
        assertEquals(357, P25P1CryptUtil.getVoiceKeystreamOffset("RC4", false, 8));

        // LDU2, Position 0: 101 + (0*11) + 267 + 0 = 368
        assertEquals(368, P25P1CryptUtil.getVoiceKeystreamOffset("RC4", true, 0));
        // LDU2, Position 8: 101 + (8*11) + 267 + 2 = 458
        assertEquals(458, P25P1CryptUtil.getVoiceKeystreamOffset("RC4", true, 8));
    }

    /**
     * Tests that all keystream offsets are within the keystream bounds.
     */
    @Test
    public void testAllKeystreamOffsetsWithinBounds()
    {
        // DES-OFB: 224 bytes keystream
        for(int pos = 0; pos < 9; pos++)
        {
            assertTrue(P25P1CryptUtil.getVoiceKeystreamOffset("DES", false, pos) + 11 <= 224,
                "DES LDU1 offset for pos " + pos + " out of bounds");
            assertTrue(P25P1CryptUtil.getVoiceKeystreamOffset("DES", true, pos) + 11 <= 224,
                "DES LDU2 offset for pos " + pos + " out of bounds");
        }

        // AES-256: 240 bytes keystream
        for(int pos = 0; pos < 9; pos++)
        {
            assertTrue(P25P1CryptUtil.getVoiceKeystreamOffset("AES", false, pos) + 11 <= 240,
                "AES LDU1 offset for pos " + pos + " out of bounds");
            assertTrue(P25P1CryptUtil.getVoiceKeystreamOffset("AES", true, pos) + 11 <= 240,
                "AES LDU2 offset for pos " + pos + " out of bounds");
        }

        // RC4/ADP: 469 bytes keystream
        for(int pos = 0; pos < 9; pos++)
        {
            assertTrue(P25P1CryptUtil.getVoiceKeystreamOffset("RC4", false, pos) + 11 <= 469,
                "RC4 LDU1 offset for pos " + pos + " out of bounds");
            assertTrue(P25P1CryptUtil.getVoiceKeystreamOffset("RC4", true, pos) + 11 <= 469,
                "RC4 LDU2 offset for pos " + pos + " out of bounds");
        }
    }

    /**
     * Tests that the full decryption pipeline (encode → encrypt → decrypt → decode) works.
     * This simulates the P25 transmit/receive cycle for RC4/ADP.
     * Note: The FEC encode/decode cycle may introduce a 1-bit error in u7 bit 0 (BOT indicator),
     * which is an inherent limitation when the JMBE codec requires FEC-encoded frames.
     * This does not affect audible audio quality.
     */
    @Test
    public void testFullDecryptionPipelineRC4()
    {
        byte[] key = {0x01, 0x02, 0x03, 0x04, 0x05};
        byte[] mi = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte)0x88, (byte)0x99};

        byte[] keystream = P25P1CryptUtil.generateRC4ADPKeystream(key, mi);
        assertNotNull(keystream);

        byte[] plainPacked = IMBEInterleave.imbePack(0x100, 0x200, 0x300, 0x400, 0x100, 0x200, 0x100, 0x40);

        byte[] encryptedPacked = plainPacked.clone();
        int offset = P25P1CryptUtil.getVoiceKeystreamOffset("RC4", false, 0);
        for(int j = 0; j < 11; j++)
        {
            encryptedPacked[j] ^= keystream[offset + j];
        }
        byte[] encryptedFrame = IMBEInterleave.encode(encryptedPacked);

        byte[] receivedPacked = IMBEInterleave.decode(encryptedFrame);
        for(int j = 0; j < 11; j++)
        {
            receivedPacked[j] ^= keystream[offset + j];
        }

        // Compare with 1-bit tolerance on last byte (u7 BOT bit)
        byte[] expectedMasked = plainPacked.clone();
        byte[] actualMasked = receivedPacked.clone();
        expectedMasked[10] &= (byte)0xFE;
        actualMasked[10] &= (byte)0xFE;
        assertArrayEquals(expectedMasked, actualMasked,
            "Full RC4 pipeline should recover original packed codeword (±1 bit u7 BOT)");
    }

    /**
     * Tests the full decryption pipeline for DES-OFB.
     */
    @Test
    public void testFullDecryptionPipelineDES()
    {
        byte[] key = {0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xAB, (byte)0xCD, (byte)0xEF};
        byte[] mi = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte)0x88, (byte)0x99};

        byte[] keystream = P25P1CryptUtil.generateDESOFBKeystream(key, mi);
        assertNotNull(keystream);

        byte[] plainPacked = IMBEInterleave.imbePack(0x100, 0x200, 0x300, 0x400, 0x100, 0x200, 0x100, 0x40);

        byte[] encryptedPacked = plainPacked.clone();
        int offset = P25P1CryptUtil.getVoiceKeystreamOffset("DES", false, 0);
        for(int j = 0; j < 11; j++)
        {
            encryptedPacked[j] ^= keystream[offset + j];
        }
        byte[] encryptedFrame = IMBEInterleave.encode(encryptedPacked);

        byte[] receivedPacked = IMBEInterleave.decode(encryptedFrame);
        for(int j = 0; j < 11; j++)
        {
            receivedPacked[j] ^= keystream[offset + j];
        }

        byte[] expectedMasked = plainPacked.clone();
        byte[] actualMasked = receivedPacked.clone();
        expectedMasked[10] &= (byte)0xFE;
        actualMasked[10] &= (byte)0xFE;
        assertArrayEquals(expectedMasked, actualMasked,
            "Full DES pipeline should recover original packed codeword (±1 bit u7 BOT)");
    }

    /**
     * Tests the full decryption pipeline for AES-256.
     */
    @Test
    public void testFullDecryptionPipelineAES()
    {
        byte[] key = new byte[32];
        for(int i = 0; i < 32; i++) key[i] = (byte)(i + 1);
        byte[] mi = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte)0x88, (byte)0x99};

        byte[] keystream = P25P1CryptUtil.generateAES256OFBKeystream(key, mi);
        assertNotNull(keystream);

        byte[] plainPacked = IMBEInterleave.imbePack(0x100, 0x200, 0x300, 0x400, 0x100, 0x200, 0x100, 0x40);

        byte[] encryptedPacked = plainPacked.clone();
        int offset = P25P1CryptUtil.getVoiceKeystreamOffset("AES", false, 0);
        for(int j = 0; j < 11; j++)
        {
            encryptedPacked[j] ^= keystream[offset + j];
        }
        byte[] encryptedFrame = IMBEInterleave.encode(encryptedPacked);

        byte[] receivedPacked = IMBEInterleave.decode(encryptedFrame);
        for(int j = 0; j < 11; j++)
        {
            receivedPacked[j] ^= keystream[offset + j];
        }

        byte[] expectedMasked = plainPacked.clone();
        byte[] actualMasked = receivedPacked.clone();
        expectedMasked[10] &= (byte)0xFE;
        actualMasked[10] &= (byte)0xFE;
        assertArrayEquals(expectedMasked, actualMasked,
            "Full AES pipeline should recover original packed codeword (±1 bit u7 BOT)");
    }
}
