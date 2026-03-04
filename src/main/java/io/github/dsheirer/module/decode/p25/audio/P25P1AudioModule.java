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
import io.github.dsheirer.module.decode.p25.reference.Encryption;
import io.github.dsheirer.preference.UserPreferences;
import io.github.dsheirer.sample.Listener;
import java.util.ArrayList;
import java.util.Arrays;
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
                if(message instanceof LDUMessage ldu)
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
                    }
                }
            }
        }
    }

    /**
     * Processes an audio packet by decoding the IMBE audio frames and rebroadcasting them as PCM audio packets.
     * When the call is encrypted and a decryption engine with a matching key is available, the IMBE frames are
     * decrypted before being passed to the audio codec.
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
        else if(mDecryptionEngine != null && mCurrentEncryptionKID != null)
        {
            List<byte[]> frames = ldu.getIMBEFrames();
            byte[] concatenated = new byte[frames.size() * IMBE_FRAME_SIZE];
            for(int i = 0; i < frames.size(); i++)
            {
                byte[] frame = frames.get(i);
                System.arraycopy(frame, 0, concatenated, i * IMBE_FRAME_SIZE,
                    Math.min(frame.length, IMBE_FRAME_SIZE));
            }

            byte[] decrypted = new byte[0];

            // Check talkgroup key cache first to skip the full decryption cascade when possible
            Integer talkgroupId = getCurrentTalkgroupId();
            if(talkgroupId != null && mCurrentMessageIndicator != null && mCurrentMessageIndicator.length > 0)
            {
                CachedKey cached = mTalkgroupKeyCache.get(talkgroupId);
                if(cached != null)
                {
                    if("RC4".equals(cached.algorithm()))
                    {
                        decrypted = mDecryptionEngine.decryptWithRC4Key(mCurrentMessageIndicator, cached.rawKey(), concatenated);
                    }
                    else
                    {
                        decrypted = mDecryptionEngine.decryptWithAlgorithmAndKey(cached.algorithm(), cached.rawKey(), mCurrentMessageIndicator, concatenated);
                    }
                }
            }

            if(decrypted.length == 0)
            {
                decrypted = mDecryptionEngine.decrypt(mCurrentEncryptionKID, mCurrentMessageIndicator, concatenated);

                if(decrypted.length > 0 && talkgroupId != null)
                {
                    byte[] rawKey = mDecryptionEngine.getRawKeyBytesForKID(mCurrentEncryptionKID);
                    if(rawKey != null)
                    {
                        String algo = mDecryptionEngine.getAlgorithmForKID(mCurrentEncryptionKID);
                        mTalkgroupKeyCache.put(talkgroupId, new CachedKey(rawKey, algo != null ? algo : "RC4"));
                    }
                }
            }

            //If no key is registered for this KID but the call uses Motorola ADP (40-bit RC4) with null key
            //ID 0, attempt decryption using a null (all-zero) 5-byte key. Key ID 0 is the P25 null key,
            //and some Motorola systems transmit ADP-encrypted audio using this null key.
            if(decrypted.length == 0 && mCurrentEncryptionAlgorithm == Encryption.MOTOROLA_ADP.getValue()
                && "0000".equals(mCurrentEncryptionKID) && mCurrentMessageIndicator != null
                && mCurrentMessageIndicator.length > 0)
            {
                decrypted = mDecryptionEngine.decryptWithNullKeyRC4(mCurrentMessageIndicator, 5, concatenated);

                if(decrypted.length > 0 && talkgroupId != null)
                {
                    mTalkgroupKeyCache.put(talkgroupId, new CachedKey(new byte[5], "RC4"));
                }
            }

            //If still no key found, check if the talkgroup alias provides a per-talkgroup encryption key.
            if(decrypted.length == 0 && mCurrentMessageIndicator != null && mCurrentMessageIndicator.length > 0)
            {
                byte[][] foundKey = new byte[1][];
                String[] foundAlgorithm = new String[1];
                decrypted = tryAliasKeyDecrypt(mCurrentMessageIndicator, concatenated, foundKey, foundAlgorithm);

                if(decrypted.length > 0 && talkgroupId != null && foundKey[0] != null)
                {
                    String algo = foundAlgorithm[0] != null ? foundAlgorithm[0] : "RC4";
                    mTalkgroupKeyCache.put(talkgroupId, new CachedKey(foundKey[0], algo));
                }
            }

            if(decrypted.length == 0)
            {
                mLog.warn("Failed to decrypt encrypted audio for talkgroup [{}] with KID [{}]",
                        talkgroupId, mCurrentEncryptionKID);
            }

            if(decrypted.length == concatenated.length)
            {
                for(int i = 0; i < frames.size(); i++)
                {
                    byte[] decryptedFrame = Arrays.copyOfRange(decrypted, i * IMBE_FRAME_SIZE,
                        (i + 1) * IMBE_FRAME_SIZE);
                    float[] audio = getAudioCodec().getAudio(decryptedFrame);
                    audio = mGain.apply(audio);
                    addAudio(audio);
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
     * Attempts decryption using a key found in the talkgroup alias, if one is configured.
     * This provides a per-talkgroup key fallback when no key is registered for the transmitted KID.
     *
     * @param messageIndicator per-call message indicator bytes
     * @param ciphertext encrypted IMBE frame bytes
     * @param foundKeyOut single-element array to receive the raw key bytes that succeeded (may be null on failure)
     * @param foundAlgorithmOut single-element array to receive the algorithm name that succeeded (may be null on failure)
     * @return decrypted bytes if an alias key was found and decryption succeeded, otherwise empty byte array
     */
    private byte[] tryAliasKeyDecrypt(byte[] messageIndicator, byte[] ciphertext, byte[][] foundKeyOut,
                                      String[] foundAlgorithmOut)
    {
        AliasList aliasList = getAliasList();
        if(aliasList == null)
        {
            return new byte[0];
        }

        for(Identifier identifier : getIdentifierCollection().getIdentifiers(Form.TALKGROUP))
        {
            List<Alias> aliases = aliasList.getAliases(identifier);
            int encKeyCount = 0;
            for(Alias alias : aliases)
            {
                for(io.github.dsheirer.alias.id.AliasID aliasID : alias.getAliasIdentifiers())
                {
                    if(aliasID instanceof EncryptionKeyID encKeyID && encKeyID.isValid())
                    {
                        encKeyCount++;
                    }
                }
            }
            mLog.debug("tryAliasKeyDecrypt: talkgroup [{}] aliases=[{}] encryptionKeys=[{}]",
                    identifier, aliases.size(), encKeyCount);

            for(Alias alias : aliases)
            {
                for(io.github.dsheirer.alias.id.AliasID aliasID : alias.getAliasIdentifiers())
                {
                    if(aliasID instanceof EncryptionKeyID encKeyID && encKeyID.isValid())
                    {
                        byte[] rawKey = encKeyID.getRawKeyBytes();
                        if(rawKey != null)
                        {
                            String algorithm = encKeyID.getAlgorithm();
                            byte[] result;
                            if("RC4".equals(algorithm))
                            {
                                result = mDecryptionEngine.decryptWithRC4Key(messageIndicator, rawKey, ciphertext);
                            }
                            else
                            {
                                result = mDecryptionEngine.decryptWithAlgorithmAndKey(algorithm, rawKey, messageIndicator, ciphertext);
                            }
                            if(result.length > 0)
                            {
                                if(foundKeyOut != null)
                                {
                                    foundKeyOut[0] = rawKey;
                                }
                                if(foundAlgorithmOut != null)
                                {
                                    foundAlgorithmOut[0] = algorithm;
                                }
                                return result;
                            }
                        }
                    }
                }
            }
        }

        return new byte[0];
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
