/*
 * *****************************************************************************
 * Copyright (C) 2014-2024 Dennis Sheirer
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
package io.github.dsheirer.module.decode.p25.audio;

import io.github.dsheirer.alias.Alias;
import io.github.dsheirer.alias.AliasList;
import io.github.dsheirer.alias.id.encryption.EncryptionKeyID;
import io.github.dsheirer.audio.codec.mbe.ImbeAudioModule;
import io.github.dsheirer.audio.squelch.SquelchState;
import io.github.dsheirer.audio.squelch.SquelchStateEvent;
import io.github.dsheirer.crypto.DecryptionEngine;
import io.github.dsheirer.dsp.gain.NonClippingGain;
import io.github.dsheirer.identifier.Form;
import io.github.dsheirer.identifier.Identifier;
import io.github.dsheirer.identifier.integer.IntegerIdentifier;
import io.github.dsheirer.message.IMessage;
import io.github.dsheirer.module.decode.p25.phase1.message.hdu.HDUMessage;
import io.github.dsheirer.module.decode.p25.phase1.message.ldu.EncryptionSyncParameters;
import io.github.dsheirer.module.decode.p25.phase1.message.ldu.LDU1Message;
import io.github.dsheirer.module.decode.p25.phase1.message.ldu.LDU2Message;
import io.github.dsheirer.module.decode.p25.phase1.message.ldu.LDUMessage;
import io.github.dsheirer.module.decode.p25.phase1.IMBEInterleave;
import io.github.dsheirer.module.decode.p25.phase1.P25P1CryptUtil;
import io.github.dsheirer.module.decode.p25.reference.Encryption;
import io.github.dsheirer.preference.UserPreferences;
import io.github.dsheirer.sample.Listener;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class P25P1AudioModule extends ImbeAudioModule
{
    private static final Logger mLog = LoggerFactory.getLogger(P25P1AudioModule.class);
    private static final int IMBE_FRAME_SIZE = 18;
    private static final int UNSET_ALGORITHM = -1;
    /**
     * Maximum number of LDU messages to cache before assuming unencrypted audio when the encrypted call state
     * has not been established from HDU or LDU2 messages (e.g. due to missed HDU and CRC failures in LDU2).
     */
    private static final int MAX_CACHED_LDU_BEFORE_UNENCRYPTED_FALLBACK = 4;

    private boolean mEncryptedCall = false;
    private boolean mEncryptedCallStateEstablished = false;

    private DecryptionEngine mDecryptionEngine;
    private String mCurrentEncryptionKID;
    private byte[] mCurrentMessageIndicator;
    private int mCurrentEncryptionAlgorithm = UNSET_ALGORITHM;
    private Map<Integer, CachedKey> mTalkgroupKeyCache = new ConcurrentHashMap<>();

    private SquelchStateListener mSquelchStateListener = new SquelchStateListener();
    private NonClippingGain mGain = new NonClippingGain(5.0f, 0.95f);
    private List<LDUMessage> mCachedLDUMessages = new ArrayList<>();

    public P25P1AudioModule(UserPreferences userPreferences, AliasList aliasList)
    {
        super(userPreferences, aliasList);
    }

    /**
     * Sets the decryption engine to use for decrypting encrypted audio frames.
     * @param engine the shared DecryptionEngine instance, or null to disable decryption
     */
    public void setDecryptionEngine(DecryptionEngine engine)
    {
        mDecryptionEngine = engine;
    }

    @Override
    protected int getTimeslot()
    {
        return 0;
    }

    @Override
    public Listener<SquelchStateEvent> getSquelchStateListener()
    {
        return mSquelchStateListener;
    }

    @Override
    public void reset()
    {
        getIdentifierCollection().clear();
        mCurrentEncryptionKID = null;
        mCurrentMessageIndicator = null;
        mCurrentEncryptionAlgorithm = UNSET_ALGORITHM;
        mTalkgroupKeyCache.clear();
    }

    @Override
    public void start()
    {
    }

    /**
     * Processes call header (HDU) and voice frame (LDU1/LDU2) messages to decode audio and to determine the
     * encrypted audio status of a call event. Only the HDU and LDU2 messages convey encrypted call status. If an
     * LDU1 message is received without a preceding HDU message, then the LDU1 message is cached until the first
     * LDU2 message is received and the encryption state can be determined. Both the LDU1 and the LDU2 message are
     * then processed for audio if the call is unencrypted.
     */
    public void receive(IMessage message)
    {
        if(hasAudioCodec())
        {
            if(mEncryptedCallStateEstablished)
            {
                if(message instanceof LDU2Message ldu2)
                {
                    // Process the LDU2 audio with the CURRENT MI (before updating)
                    processAudio(ldu2);

                    // After processing LDU2 voice, update MI for the next superframe
                    if(mEncryptedCall && ldu2.getEncryptionSyncParameters().isValid())
                    {
                        EncryptionSyncParameters esp = ldu2.getEncryptionSyncParameters();
                        mCurrentMessageIndicator = DecryptionEngine.hexToBytes(esp.getMessageIndicator());
                        mCurrentEncryptionAlgorithm = esp.getEncryptionKey().getValue().getAlgorithm();
                    }
                    else if(mEncryptedCall && mCurrentMessageIndicator != null)
                    {
                        // If LDU2 ESP is invalid, cycle the MI using the P25 LFSR
                        P25P1CryptUtil.cycleMI(mCurrentMessageIndicator);
                    }
                }
                else if(message instanceof LDUMessage ldu)
                {
                    processAudio(ldu);
                }
            }
            else
            {
                if(message instanceof HDUMessage hdu && hdu.isValid())
                {
                    mEncryptedCallStateEstablished = true;
                    mEncryptedCall = hdu.getHeaderData().isEncryptedAudio();

                    if(mEncryptedCall)
                    {
                        mCurrentEncryptionKID = String.format("%04X", hdu.getHeaderData().getEncryptionKey().getValue().getKey());
                        mCurrentMessageIndicator = DecryptionEngine.hexToBytes(hdu.getHeaderData().getMessageIndicator());
                        mCurrentEncryptionAlgorithm = hdu.getHeaderData().getEncryptionKey().getValue().getAlgorithm();
                    }
                }
                else if(message instanceof LDU1Message ldu1)
                {
                    //When we receive an LDU1 message without first receiving the HDU message, cache the LDU1 Message
                    //until we can determine the encrypted call state from the next LDU2 message
                    mCachedLDUMessages.add(ldu1);
                }
                else if(message instanceof LDU2Message ldu2)
                {
                    if(ldu2.getEncryptionSyncParameters().isValid())
                    {
                        mEncryptedCallStateEstablished = true;
                        EncryptionSyncParameters esp = ldu2.getEncryptionSyncParameters();
                        mEncryptedCall = esp.isEncryptedAudio();

                        if(mEncryptedCall)
                        {
                            mCurrentEncryptionKID = String.format("%04X", esp.getEncryptionKey().getValue().getKey());
                            mCurrentMessageIndicator = DecryptionEngine.hexToBytes(esp.getMessageIndicator());
                            mCurrentEncryptionAlgorithm = esp.getEncryptionKey().getValue().getAlgorithm();
                        }
                    }

                    if(mEncryptedCallStateEstablished)
                    {
                        for(LDUMessage cachedLdu : mCachedLDUMessages)
                        {
                            processAudio(cachedLdu);
                        }

                        mCachedLDUMessages.clear();
                        processAudio(ldu2);
                    }
                    else
                    {
                        mCachedLDUMessages.add(ldu2);

                        //Fallback: if we've accumulated too many LDU messages without establishing the encrypted
                        //call state (e.g. due to missed HDU and repeated LDU2 CRC failures), assume the call is
                        //unencrypted and process the cached audio to avoid silent calls.
                        if(mCachedLDUMessages.size() >= MAX_CACHED_LDU_BEFORE_UNENCRYPTED_FALLBACK)
                        {
                            mLog.info("Encrypted call state not established after [{}] cached LDU messages - " +
                                "falling back to unencrypted audio processing", mCachedLDUMessages.size());
                            mEncryptedCallStateEstablished = true;
                            mEncryptedCall = false;

                            for(LDUMessage cachedLdu : mCachedLDUMessages)
                            {
                                processAudio(cachedLdu);
                            }

                            mCachedLDUMessages.clear();
                        }
                    }
                }
            }
        }
    }

    /**
     * Processes an audio packet by decoding the IMBE audio frames and rebroadcasting them as PCM audio packets.
     * When the call is encrypted and a decryption engine with a matching key is available, each IMBE voice codeword
     * is decrypted individually at the correct keystream offset using the P25 Phase 1 decryption pipeline:
     * FEC decode (18-byte frame → 11-byte packed codeword), keystream XOR, FEC re-encode → JMBE codec.
     */
    private void processAudio(LDUMessage ldu)
    {
        if(!mEncryptedCall)
        {
            for(byte[] frame : ldu.getIMBEFrames())
            {
                float[] audio = getAudioCodec().getAudio(frame);
                audio = mGain.apply(audio);
                addAudio(audio);
            }
        }
        else if(mDecryptionEngine != null && mCurrentEncryptionKID != null
            && mCurrentMessageIndicator != null && mCurrentMessageIndicator.length > 0)
        {
            boolean isLDU2 = ldu instanceof LDU2Message;
            byte[] keystream = null;
            String algorithm = null;

            // Determine the P25 protocol algorithm from the over-the-air algorithm ID
            if(mCurrentEncryptionAlgorithm != UNSET_ALGORITHM)
            {
                algorithm = Encryption.toDecryptionAlgorithm(mCurrentEncryptionAlgorithm);
            }

            // Try to find a key: first from the engine by KID, then from alias
            byte[] rawKey = mDecryptionEngine.getRawKeyBytesForKID(mCurrentEncryptionKID);
            if(rawKey == null)
            {
                // Try alias-based key lookup
                byte[][] foundKey = new byte[1][];
                String[] foundAlgorithm = new String[1];
                findAliasKey(foundKey, foundAlgorithm);
                rawKey = foundKey[0];
                if(rawKey != null && algorithm == null)
                {
                    algorithm = foundAlgorithm[0];
                }
            }
            else if(algorithm == null)
            {
                algorithm = mDecryptionEngine.getAlgorithmForKID(mCurrentEncryptionKID);
            }

            // Also try null key for Motorola ADP with key ID 0
            if(rawKey == null && mCurrentEncryptionAlgorithm == Encryption.MOTOROLA_ADP.getValue()
                && "0000".equals(mCurrentEncryptionKID))
            {
                rawKey = new byte[5]; // null key
                algorithm = "RC4";
            }

            // Generate keystream using the P25 Phase 1 algorithm
            if(rawKey != null && algorithm != null)
            {
                keystream = generateP25Keystream(algorithm, rawKey, mCurrentMessageIndicator);
            }

            if(keystream != null)
            {
                List<byte[]> frames = ldu.getIMBEFrames();
                for(int i = 0; i < frames.size(); i++)
                {
                    byte[] frame = frames.get(i);

                    // FEC decode: 18-byte frame → 11-byte packed codeword
                    byte[] packed = IMBEInterleave.decode(frame);

                    // Decrypt: XOR with keystream at correct offset
                    int offset = P25P1CryptUtil.getVoiceKeystreamOffset(algorithm, isLDU2, i);
                    if(offset + P25P1CryptUtil.PACKED_CODEWORD_SIZE <= keystream.length)
                    {
                        for(int j = 0; j < P25P1CryptUtil.PACKED_CODEWORD_SIZE; j++)
                        {
                            packed[j] ^= keystream[offset + j];
                        }
                    }

                    // FEC re-encode: 11-byte packed codeword → 18-byte frame
                    byte[] decryptedFrame = IMBEInterleave.encode(packed);

                    float[] audio = getAudioCodec().getAudio(decryptedFrame);
                    audio = mGain.apply(audio);
                    addAudio(audio);
                }

                // Cache key for talkgroup if successful
                Integer talkgroupId = getCurrentTalkgroupId();
                if(talkgroupId != null)
                {
                    mTalkgroupKeyCache.put(talkgroupId, new CachedKey(rawKey, algorithm));
                }
            }
            else
            {
                Encryption encType = Encryption.fromValue(mCurrentEncryptionAlgorithm);
                String protocolAlgo = encType.toDecryptionAlgorithm();
                mLog.warn("Failed to decrypt encrypted audio for talkgroup [{}] with KID [{}] algorithm [{}] (0x{}) " +
                        "protocolAlgo [{}]", getCurrentTalkgroupId(), mCurrentEncryptionKID, encType,
                        String.format("%02X", mCurrentEncryptionAlgorithm & 0xFF),
                        protocolAlgo != null ? protocolAlgo : "UNSUPPORTED");
            }
        }
    }

    /**
     * Generates the P25 Phase 1 keystream for the given algorithm, key, and message indicator.
     */
    private byte[] generateP25Keystream(String algorithm, byte[] rawKey, byte[] mi)
    {
        switch(algorithm)
        {
            case "DES":
                return P25P1CryptUtil.generateDESOFBKeystream(rawKey, mi);
            case "AES":
                return P25P1CryptUtil.generateAES256OFBKeystream(rawKey, mi);
            case "RC4":
                return P25P1CryptUtil.generateRC4ADPKeystream(rawKey, mi);
            default:
                mLog.warn("Unsupported P25 encryption algorithm: {}", algorithm);
                return null;
        }
    }

    /**
     * Searches for an encryption key in the talkgroup alias, if one is configured.
     */
    private void findAliasKey(byte[][] foundKeyOut, String[] foundAlgorithmOut)
    {
        AliasList aliasList = getAliasList();
        if(aliasList == null)
        {
            return;
        }

        for(Identifier identifier : getIdentifierCollection().getIdentifiers(Form.TALKGROUP))
        {
            List<Alias> aliases = aliasList.getAliases(identifier);
            for(Alias alias : aliases)
            {
                for(io.github.dsheirer.alias.id.AliasID aliasID : alias.getAliasIdentifiers())
                {
                    if(aliasID instanceof EncryptionKeyID encKeyID && encKeyID.isValid())
                    {
                        byte[] rawKey = encKeyID.getRawKeyBytes();
                        if(rawKey != null)
                        {
                            foundKeyOut[0] = rawKey;
                            foundAlgorithmOut[0] = encKeyID.getAlgorithm();
                            return;
                        }
                    }
                }
            }
        }
    }

    /**
     * Returns the current talkgroup ID as an Integer, or null if not available.
     */
    private Integer getCurrentTalkgroupId()
    {
        for(Identifier identifier : getIdentifierCollection().getIdentifiers(Form.TALKGROUP))
        {
            if(identifier instanceof IntegerIdentifier intIdent)
            {
                return intIdent.getValue();
            }
        }
        return null;
    }

    /**
     * Wrapper for squelch state to process end of call actions.  At call end the encrypted call state established
     * flag is reset so that the encrypted audio state for the next call can be properly detected and we send an
     * END audio packet so that downstream processors like the audio recorder can properly close out a call sequence.
     */
    public class SquelchStateListener implements Listener<SquelchStateEvent>
    {
        @Override
        public void receive(SquelchStateEvent event)
        {
            if(event.getSquelchState() == SquelchState.SQUELCH)
            {
                closeAudioSegment();
                mEncryptedCallStateEstablished = false;
                mEncryptedCall = false;
                mCachedLDUMessages.clear();
                mCurrentEncryptionKID = null;
                mCurrentMessageIndicator = null;
                mCurrentEncryptionAlgorithm = UNSET_ALGORITHM;
            }
        }
    }

    /**
     * Holds cached decryption key data for a talkgroup, including the raw key bytes and algorithm name.
     */
    private record CachedKey(byte[] rawKey, String algorithm) {}
}
