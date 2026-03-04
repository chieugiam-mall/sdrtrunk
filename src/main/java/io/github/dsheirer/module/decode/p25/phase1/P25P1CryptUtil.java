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

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * P25 Phase 1 cryptographic utilities for voice decryption.
 *
 * Implements the P25 LFSR-based message indicator expansion and keystream generation
 * for DES-OFB, AES-256 OFB, and Motorola ADP (RC4) algorithms, matching the approach
 * used by the OP25 boatbod project.
 *
 * In P25 Phase 1 (FDMA), encryption operates on 11-byte packed IMBE voice codewords
 * at specific offsets within a pre-computed keystream that covers the entire superframe
 * (LDU1 + LDU2).
 */
public class P25P1CryptUtil
{
    private static final Logger mLog = LoggerFactory.getLogger(P25P1CryptUtil.class);

    /** Size of a packed IMBE codeword in bytes (88 bits) */
    public static final int PACKED_CODEWORD_SIZE = 11;

    /** Number of voice codewords per LDU */
    public static final int VOICE_CODEWORDS_PER_LDU = 9;

    private P25P1CryptUtil() {}

    // -------------------------------------------------------------------------
    // P25 LFSR (Linear Feedback Shift Register)
    // Polynomial: C(x) = x^64 + x^62 + x^46 + x^38 + x^27 + x^15 + 1
    // -------------------------------------------------------------------------

    /**
     * Steps the P25 LFSR by one position.
     * Returns a two-element array: [0] = overflow bit (MSB before shift), [1] = new LFSR state.
     */
    static long[] stepLFSR(long lfsr)
    {
        long ovBit = (lfsr >>> 63) & 0x1L;
        long fbBit = ((lfsr >>> 63) ^ (lfsr >>> 61) ^ (lfsr >>> 45) ^ (lfsr >>> 37)
            ^ (lfsr >>> 26) ^ (lfsr >>> 14)) & 0x1L;
        lfsr = (lfsr << 1) | fbBit;
        return new long[]{ovBit, lfsr};
    }

    /**
     * Expands a 72-bit message indicator (MI) to a 128-bit initialization vector (IV)
     * using the P25 LFSR, as required for AES-256 OFB mode.
     *
     * The first 64 bits of the MI seed the LFSR. After 64 steps, the overflow bits
     * form the first 8 bytes of the IV, and the LFSR state forms the last 8 bytes.
     *
     * @param mi 9-byte message indicator (only first 8 bytes are used)
     * @return 16-byte IV suitable for AES
     */
    public static byte[] expandMITo128(byte[] mi)
    {
        long lfsr = 0;
        for(int i = 0; i < 8 && i < mi.length; i++)
        {
            lfsr = (lfsr << 8) | (mi[i] & 0xFFL);
        }

        long overflow = 0;
        for(int i = 0; i < 64; i++)
        {
            long[] result = stepLFSR(lfsr);
            overflow = (overflow << 1) | result[0];
            lfsr = result[1];
        }

        byte[] iv = new byte[16];
        for(int i = 7; i >= 0; i--)
        {
            iv[i] = (byte)(lfsr & 0xFF);
            lfsr >>>= 8;
        }
        for(int i = 15; i >= 8; i--)
        {
            iv[i] = (byte)(overflow & 0xFF);
            overflow >>>= 8;
        }
        return iv;
    }

    /**
     * Advances the message indicator to the next value in the sequence using the P25 LFSR.
     * Used when the LDU2 ESS data fails CRC and a new MI cannot be extracted.
     *
     * @param mi 9-byte message indicator (modified in place; byte 8 is zeroed)
     */
    public static void cycleMI(byte[] mi)
    {
        long lfsr = 0;
        for(int i = 0; i < 8 && i < mi.length; i++)
        {
            lfsr = (lfsr << 8) | (mi[i] & 0xFFL);
        }

        for(int cnt = 0; cnt < 64; cnt++)
        {
            long[] result = stepLFSR(lfsr);
            lfsr = result[1];
        }

        for(int i = 7; i >= 0; i--)
        {
            mi[i] = (byte)(lfsr & 0xFF);
            lfsr >>>= 8;
        }
        if(mi.length > 8)
        {
            mi[8] = 0;
        }
    }

    // -------------------------------------------------------------------------
    // Keystream Generation
    // -------------------------------------------------------------------------

    /**
     * Generates DES-OFB keystream for P25 Phase 1 superframe decryption.
     * Produces 224 bytes (28 rounds × 8 bytes per DES block) of keystream.
     * The first 8 bytes constitute a discard round per the P25 specification.
     *
     * @param key 8-byte DES key
     * @param mi  9-byte message indicator (first 8 bytes used as IV)
     * @return 224-byte keystream, or null on error
     */
    public static byte[] generateDESOFBKeystream(byte[] key, byte[] mi)
    {
        try
        {
            byte[] desIv = new byte[8];
            System.arraycopy(mi, 0, desIv, 0, Math.min(mi.length, 8));

            SecretKey secretKey = new SecretKeySpec(key, "DES");
            Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            byte[] keystream = new byte[224];
            byte[] block = desIv;
            for(int i = 0; i < 28; i++)
            {
                block = cipher.doFinal(block);
                System.arraycopy(block, 0, keystream, i * 8, 8);
            }
            return keystream;
        }
        catch(Exception e)
        {
            mLog.error("Failed to generate DES-OFB keystream", e);
            return null;
        }
    }

    /**
     * Generates AES-256 OFB keystream for P25 Phase 1 superframe decryption.
     * The MI is expanded to 128 bits using the P25 LFSR before use as the IV.
     * Produces 240 bytes (15 rounds × 16 bytes per AES block) of keystream.
     * The first 16 bytes constitute a discard round per the P25 specification.
     *
     * @param key 32-byte AES-256 key
     * @param mi  9-byte message indicator
     * @return 240-byte keystream, or null on error
     */
    public static byte[] generateAES256OFBKeystream(byte[] key, byte[] mi)
    {
        try
        {
            byte[] iv = expandMITo128(mi);

            SecretKey secretKey = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            byte[] keystream = new byte[240];
            byte[] block = iv;
            for(int i = 0; i < 15; i++)
            {
                block = cipher.doFinal(block);
                System.arraycopy(block, 0, keystream, i * 16, 16);
            }
            return keystream;
        }
        catch(Exception e)
        {
            mLog.error("Failed to generate AES-256 OFB keystream", e);
            return null;
        }
    }

    /**
     * Generates RC4/ADP keystream for P25 Phase 1 superframe decryption.
     * Uses a 13-byte key seed: Key[0..4] || MI[0..7].
     * Produces 469 bytes of keystream via the standard RC4 KSA + PRGA.
     *
     * If the supplied key is shorter than 5 bytes, it is zero-padded on the left.
     * If longer than 5 bytes, only the first 5 bytes are used (ADP uses 40-bit keys).
     *
     * @param key ADP key (nominally 5 bytes / 40 bits)
     * @param mi  9-byte message indicator (first 8 bytes used)
     * @return 469-byte keystream, or null on error
     */
    public static byte[] generateRC4ADPKeystream(byte[] key, byte[] mi)
    {
        try
        {
            byte[] adpKey = new byte[13];
            int padLen = Math.max(5 - key.length, 0);
            for(int i = padLen; i < 5; i++)
            {
                adpKey[i] = key[i - padLen];
            }
            for(int i = 5; i < 13; i++)
            {
                adpKey[i] = (i - 5 < mi.length) ? mi[i - 5] : 0;
            }

            int[] S = new int[256];
            int[] K = new int[256];
            for(int i = 0; i < 256; i++)
            {
                K[i] = adpKey[i % 13] & 0xFF;
                S[i] = i;
            }

            int j = 0;
            for(int i = 0; i < 256; i++)
            {
                j = (j + S[i] + K[i]) & 0xFF;
                int tmp = S[i]; S[i] = S[j]; S[j] = tmp;
            }

            byte[] keystream = new byte[469];
            int si = 0;
            j = 0;
            for(int k = 0; k < 469; k++)
            {
                si = (si + 1) & 0xFF;
                j = (j + S[si]) & 0xFF;
                int tmp = S[si]; S[si] = S[j]; S[j] = tmp;
                keystream[k] = (byte)(S[(S[si] + S[j]) & 0xFF]);
            }
            return keystream;
        }
        catch(Exception e)
        {
            mLog.error("Failed to generate RC4/ADP keystream", e);
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // Keystream Offset Calculation for P25 Phase 1 FDMA
    // -------------------------------------------------------------------------

    /**
     * Returns the keystream offset for a given voice codeword position within an LDU.
     *
     * The P25 superframe keystream covers both voice and non-voice data.
     * Voice codewords (11 bytes each) are at specific positions within the keystream,
     * with gaps for the Link Control Word (LCW), Encryption Sync Parameters (ESP),
     * Low Speed Data (LSD), and reserved bytes.
     *
     * @param algorithm "DES", "AES", or "RC4"
     * @param isLDU2    true if processing LDU2, false for LDU1
     * @param position  voice codeword index within the LDU (0-8)
     * @return byte offset into the keystream for the start of this voice codeword's 11 bytes
     */
    public static int getVoiceKeystreamOffset(String algorithm, boolean isLDU2, int position)
    {
        int offset;

        if("RC4".equals(algorithm))
        {
            // RC4/ADP: no discard round; LDU1 base=0, LDU2 base=101
            offset = isLDU2 ? 101 : 0;
            // Voice starts at offset 267 within each LDU, with 11 bytes per codeword
            // and a 2-byte LSD gap after codeword 7 (between positions 7 and 8)
            offset += (position * 11) + 267 + (position < 8 ? 0 : 2);
        }
        else if("DES".equals(algorithm))
        {
            // DES-OFB: 8-byte discard round; LDU1 base=0, LDU2 base=101
            offset = 8 + (isLDU2 ? 101 : 0);
            // Voice starts after 11 bytes of LCW/reserved data, with 11 bytes per codeword
            // and a 2-byte LSD gap after codeword 7
            offset += (position * 11) + 11 + (position < 8 ? 0 : 2);
        }
        else
        {
            // AES-256: 16-byte discard round; LDU1 base=0, LDU2 base=101
            offset = 16 + (isLDU2 ? 101 : 0);
            offset += (position * 11) + 11 + (position < 8 ? 0 : 2);
        }

        return offset;
    }

    /**
     * Decrypts a list of 11-byte packed IMBE codewords from a single LDU using the provided
     * keystream. Each codeword is XOR'd with the 11 keystream bytes at the calculated offset.
     *
     * @param keystream  full superframe keystream
     * @param algorithm  "DES", "AES", or "RC4"
     * @param isLDU2     true if processing LDU2
     * @param packedCodewords  list of 9 packed 11-byte codewords (modified in place)
     */
    public static void decryptPackedCodewords(byte[] keystream, String algorithm, boolean isLDU2,
                                              byte[][] packedCodewords)
    {
        for(int i = 0; i < packedCodewords.length && i < VOICE_CODEWORDS_PER_LDU; i++)
        {
            int offset = getVoiceKeystreamOffset(algorithm, isLDU2, i);
            if(offset + PACKED_CODEWORD_SIZE <= keystream.length)
            {
                for(int j = 0; j < PACKED_CODEWORD_SIZE; j++)
                {
                    packedCodewords[i][j] ^= keystream[offset + j];
                }
            }
            else
            {
                mLog.warn("Keystream too short: need offset {} + {} but only have {} bytes",
                    offset, PACKED_CODEWORD_SIZE, keystream.length);
            }
        }
    }
}
