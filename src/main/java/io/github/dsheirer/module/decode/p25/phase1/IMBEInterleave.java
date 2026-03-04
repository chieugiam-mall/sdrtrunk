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

/**
 * Utility for converting between 18-byte (144-bit) IMBE frames (with FEC) and 11-byte (88-bit)
 * packed IMBE codewords (voice-only data) as required for P25 voice encryption/decryption.
 *
 * P25 encryption operates on the 88-bit packed voice codeword, not the 144-bit FEC-encoded frame.
 * This class provides the decode (frame → codeword) and encode (codeword → frame) operations
 * needed to properly apply the keystream at the correct level.
 *
 * The 144-bit IMBE frame structure is:
 *   - Bits [0..22]:   Golay(23,12) codeword 1 → 12 data bits (u0)
 *   - Bits [23..45]:  Golay(23,12) codeword 2 → 12 data bits (u1), PN-scrambled
 *   - Bits [46..68]:  Golay(23,12) codeword 3 → 12 data bits (u2), PN-scrambled
 *   - Bits [69..91]:  Golay(23,12) codeword 4 → 12 data bits (u3), PN-scrambled
 *   - Bits [92..106]: Hamming(15,11) codeword 1 → 11 data bits (u4), PN-scrambled
 *   - Bits [107..121]: Hamming(15,11) codeword 2 → 11 data bits (u5), PN-scrambled
 *   - Bits [122..136]: Hamming(15,11) codeword 3 → 11 data bits (u6), PN-scrambled
 *   - Bits [137..143]: 7 unprotected data bits (u7)
 *
 * The 88-bit packed codeword is: u0(12) | u1(12) | u2(12) | u3(12) | u4(11) | u5(11) | u6(11) | u7(7)
 */
public class IMBEInterleave
{
    /** Golay(23,12) generator matrix checksums (same as in edac/Golay23.java) */
    private static final int[] GOLAY23_CHECKSUMS = {
        0x63A, 0x31D, 0x7B4, 0x3DA, 0x1ED, 0x6CC, 0x366, 0x1B3,
        0x6E3, 0x54B, 0x49F, 0x475
    };

    /** Hamming(15,11) generator matrix checksums (same as in edac/Hamming15.java) */
    private static final int[] HAMMING15_CHECKSUMS = {
        0x9, 0xD, 0xF, 0xE, 0x7, 0xA, 0x5, 0xB, 0xC, 0x6, 0x3
    };

    private IMBEInterleave() {}

    /**
     * Decodes an 18-byte (144-bit) IMBE frame into an 11-byte (88-bit) packed codeword.
     * Performs Golay(23,12) and Hamming(15,11) FEC decoding with PN descrambling
     * to extract the 8 IMBE voice parameters, then packs them into 11 bytes.
     *
     * @param frame 18-byte IMBE frame (144 bits)
     * @return 11-byte packed codeword (88 bits of voice data)
     */
    public static byte[] decode(byte[] frame)
    {
        // Extract Golay(23,12) and Hamming(15,11) codewords from the 144-bit frame
        int v0 = extractBits(frame, 0, 23);
        int v1 = extractBits(frame, 23, 23);
        int v2 = extractBits(frame, 46, 23);
        int v3 = extractBits(frame, 69, 23);
        int v4 = extractBits(frame, 92, 15);
        int v5 = extractBits(frame, 107, 15);
        int v6 = extractBits(frame, 122, 15);
        int v7 = extractBits(frame, 137, 7);

        // Golay decode v0 to get u0 (12 bits)
        int u0 = golay23Decode(v0);

        // Generate PN sequence seeded from u0
        int[] pn = {u0 << 4};
        int m1 = pngen23(pn);
        int u1 = golay23Decode(v1 ^ m1);

        int m2 = pngen23(pn);
        int u2 = golay23Decode(v2 ^ m2);

        int m3 = pngen23(pn);
        int u3 = golay23Decode(v3 ^ m3);

        int m4 = pngen15(pn);
        int u4 = hamming15Decode(v4 ^ m4);

        int m5 = pngen15(pn);
        int u5 = hamming15Decode(v5 ^ m5);

        int m6 = pngen15(pn);
        int u6 = hamming15Decode(v6 ^ m6);

        // u7 is the 7 unprotected bits, shifted left by 1 (BOT bit convention)
        int u7 = v7 << 1;

        return imbePack(u0, u1, u2, u3, u4, u5, u6, u7);
    }

    /**
     * Encodes an 11-byte (88-bit) packed codeword into an 18-byte (144-bit) IMBE frame.
     * Unpacks the voice parameters, applies Golay(23,12) and Hamming(15,11) FEC encoding
     * with PN scrambling to produce a valid IMBE frame.
     *
     * @param packed 11-byte packed codeword
     * @return 18-byte IMBE frame (144 bits)
     */
    public static byte[] encode(byte[] packed)
    {
        int[] params = imbeUnpack(packed);
        int u0 = params[0], u1 = params[1], u2 = params[2], u3 = params[3];
        int u4 = params[4], u5 = params[5], u6 = params[6], u7 = params[7];

        int[] pn = {u0 << 4};

        int c0 = golay23Encode(u0);

        int m1 = pngen23(pn);
        int c1 = golay23Encode(u1) ^ m1;

        int m2 = pngen23(pn);
        int c2 = golay23Encode(u2) ^ m2;

        int m3 = pngen23(pn);
        int c3 = golay23Encode(u3) ^ m3;

        int m4 = pngen15(pn);
        int c4 = hamming15Encode(u4) ^ m4;

        int m5 = pngen15(pn);
        int c5 = hamming15Encode(u5) ^ m5;

        int m6 = pngen15(pn);
        int c6 = hamming15Encode(u6) ^ m6;

        int c7 = u7 >>> 1;

        byte[] frame = new byte[18];
        storeBits(frame, 0, 23, c0);
        storeBits(frame, 23, 23, c1);
        storeBits(frame, 46, 23, c2);
        storeBits(frame, 69, 23, c3);
        storeBits(frame, 92, 15, c4);
        storeBits(frame, 107, 15, c5);
        storeBits(frame, 122, 15, c6);
        storeBits(frame, 137, 7, c7);

        return frame;
    }

    // -------------------------------------------------------------------------
    // IMBE Pack / Unpack (88 bits ↔ 11 bytes)
    // -------------------------------------------------------------------------

    /**
     * Packs 8 IMBE voice parameters into an 11-byte packed codeword.
     * u0..u3 are 12 bits each; u4..u6 are 11 bits each; u7 is 7 bits (stored in lower 7 bits).
     */
    static byte[] imbePack(int u0, int u1, int u2, int u3, int u4, int u5, int u6, int u7)
    {
        byte[] cw = new byte[11];
        cw[0] = (byte)((u0 >>> 4) & 0xFF);
        cw[1] = (byte)(((u0 & 0xF) << 4) | ((u1 >>> 8) & 0x0F));
        cw[2] = (byte)(u1 & 0xFF);
        cw[3] = (byte)((u2 >>> 4) & 0xFF);
        cw[4] = (byte)(((u2 & 0xF) << 4) | ((u3 >>> 8) & 0x0F));
        cw[5] = (byte)(u3 & 0xFF);
        cw[6] = (byte)((u4 >>> 3) & 0xFF);
        cw[7] = (byte)(((u4 & 0x7) << 5) | ((u5 >>> 6) & 0x1F));
        cw[8] = (byte)(((u5 & 0x3F) << 2) | ((u6 >>> 9) & 0x03));
        cw[9] = (byte)((u6 >>> 1) & 0xFF);
        cw[10] = (byte)(((u6 & 0x1) << 7) | (u7 & 0x7F));
        return cw;
    }

    /**
     * Unpacks an 11-byte packed codeword into 8 IMBE voice parameters.
     * Returns [u0, u1, u2, u3, u4, u5, u6, u7].
     */
    static int[] imbeUnpack(byte[] cw)
    {
        int u0 = ((cw[0] & 0xFF) << 4) | ((cw[1] & 0xF0) >>> 4);
        int u1 = ((cw[1] & 0x0F) << 8) | (cw[2] & 0xFF);
        int u2 = ((cw[3] & 0xFF) << 4) | ((cw[4] & 0xF0) >>> 4);
        int u3 = ((cw[4] & 0x0F) << 8) | (cw[5] & 0xFF);
        int u4 = ((cw[6] & 0xFF) << 3) | ((cw[7] & 0xE0) >>> 5);
        int u5 = ((cw[7] & 0x1F) << 6) | ((cw[8] & 0xFF) >>> 2);
        int u6 = ((cw[8] & 0x03) << 9) | ((cw[9] & 0xFF) << 1) | ((cw[10] & 0x80) >>> 7);
        int u7 = cw[10] & 0x7F;
        return new int[]{u0, u1, u2, u3, u4, u5, u6, u7};
    }

    // -------------------------------------------------------------------------
    // Golay(23,12) Encode / Decode
    // -------------------------------------------------------------------------

    /**
     * Encodes a 12-bit data word into a 23-bit Golay(23,12) codeword.
     */
    static int golay23Encode(int data12)
    {
        int checksum = 0;
        for(int i = 0; i < 12; i++)
        {
            if((data12 & (1 << (11 - i))) != 0)
            {
                checksum ^= GOLAY23_CHECKSUMS[i];
            }
        }
        return (data12 << 11) | checksum;
    }

    /**
     * Decodes a 23-bit Golay(23,12) codeword to extract the 12-bit data word.
     * Performs error correction for up to 3 bit errors.
     * Returns the 12 data bits (upper 12 bits of the corrected codeword).
     */
    static int golay23Decode(int codeword23)
    {
        int syndrome = golay23Syndrome(codeword23);
        if(syndrome == 0)
        {
            return (codeword23 >>> 11) & 0xFFF;
        }

        // Try to correct errors by searching for the error pattern
        if(Integer.bitCount(syndrome) <= 3)
        {
            codeword23 ^= syndrome;
            return (codeword23 >>> 11) & 0xFFF;
        }

        // Try flipping one bit in the data portion and recomputing syndrome
        for(int i = 0; i < 23; i++)
        {
            int flipped = codeword23 ^ (1 << (22 - i));
            int s = golay23Syndrome(flipped);
            if(Integer.bitCount(s) <= 2)
            {
                flipped ^= s;
                return (flipped >>> 11) & 0xFFF;
            }
        }

        // Unable to correct; return data bits as-is
        return (codeword23 >>> 11) & 0xFFF;
    }

    /**
     * Computes the syndrome for a 23-bit Golay(23,12) codeword.
     */
    private static int golay23Syndrome(int codeword23)
    {
        int data = (codeword23 >>> 11) & 0xFFF;
        int receivedCheck = codeword23 & 0x7FF;
        int computedCheck = 0;
        for(int i = 0; i < 12; i++)
        {
            if((data & (1 << (11 - i))) != 0)
            {
                computedCheck ^= GOLAY23_CHECKSUMS[i];
            }
        }
        return receivedCheck ^ computedCheck;
    }

    // -------------------------------------------------------------------------
    // Hamming(15,11) Encode / Decode
    // -------------------------------------------------------------------------

    /**
     * Encodes an 11-bit data word into a 15-bit Hamming(15,11) codeword.
     */
    static int hamming15Encode(int data11)
    {
        int checksum = 0;
        for(int i = 0; i < 11; i++)
        {
            if((data11 & (1 << (10 - i))) != 0)
            {
                checksum ^= HAMMING15_CHECKSUMS[i];
            }
        }
        return (data11 << 4) | checksum;
    }

    /**
     * Decodes a 15-bit Hamming(15,11) codeword to extract the 11-bit data word.
     * Returns the 11 data bits.
     */
    static int hamming15Decode(int codeword15)
    {
        int data = (codeword15 >>> 4) & 0x7FF;
        int receivedCheck = codeword15 & 0xF;
        int computedCheck = 0;
        for(int i = 0; i < 11; i++)
        {
            if((data & (1 << (10 - i))) != 0)
            {
                computedCheck ^= HAMMING15_CHECKSUMS[i];
            }
        }
        int syndrome = receivedCheck ^ computedCheck;
        if(syndrome != 0)
        {
            // Try to correct single-bit error using syndrome lookup
            int[] fullChecksums = {0x9, 0xD, 0xF, 0xE, 0x7, 0xA, 0x5, 0xB, 0xC, 0x6, 0x3, 0x8, 0x4, 0x2, 0x1};
            for(int i = 0; i < 15; i++)
            {
                if(fullChecksums[i] == syndrome)
                {
                    codeword15 ^= (1 << (14 - i));
                    break;
                }
            }
            data = (codeword15 >>> 4) & 0x7FF;
        }
        return data;
    }

    // -------------------------------------------------------------------------
    // PN Sequence Generators
    // -------------------------------------------------------------------------

    /**
     * Generates a 23-bit PN value, updating the seed in pn[0].
     */
    static int pngen23(int[] pn)
    {
        int n = 0;
        for(int i = 22; i >= 0; i--)
        {
            pn[0] = (173 * pn[0] + 13849) & 0xFFFF;
            if((pn[0] & 32768) != 0)
            {
                n += (1 << i);
            }
        }
        return n;
    }

    /**
     * Generates a 15-bit PN value, updating the seed in pn[0].
     */
    static int pngen15(int[] pn)
    {
        int n = 0;
        for(int i = 14; i >= 0; i--)
        {
            pn[0] = (173 * pn[0] + 13849) & 0xFFFF;
            if((pn[0] & 32768) != 0)
            {
                n += (1 << i);
            }
        }
        return n;
    }

    // -------------------------------------------------------------------------
    // Bit extraction / storage helpers
    // -------------------------------------------------------------------------

    /**
     * Extracts 'length' bits starting at 'bitOffset' from the byte array, returned as an int.
     */
    static int extractBits(byte[] data, int bitOffset, int length)
    {
        int result = 0;
        for(int i = 0; i < length; i++)
        {
            int byteIndex = (bitOffset + i) / 8;
            int bitIndex = 7 - ((bitOffset + i) % 8);
            if(byteIndex < data.length && ((data[byteIndex] >>> bitIndex) & 1) != 0)
            {
                result |= (1 << (length - 1 - i));
            }
        }
        return result;
    }

    /**
     * Stores 'length' bits of 'value' starting at 'bitOffset' in the byte array.
     */
    static void storeBits(byte[] data, int bitOffset, int length, int value)
    {
        for(int i = length - 1; i >= 0; i--)
        {
            int byteIndex = (bitOffset + (length - 1 - i)) / 8;
            int bitIndex = 7 - ((bitOffset + (length - 1 - i)) % 8);
            if(byteIndex < data.length)
            {
                if((value & (1 << i)) != 0)
                {
                    data[byteIndex] |= (byte)(1 << bitIndex);
                }
                else
                {
                    data[byteIndex] &= (byte)(~(1 << bitIndex));
                }
            }
        }
    }
}
