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
import io.github.dsheirer.audio.codec.mbe.AmbeAudioModule;
import io.github.dsheirer.audio.squelch.SquelchState;
import io.github.dsheirer.audio.squelch.SquelchStateEvent;
import io.github.dsheirer.bits.BinaryMessage;
import io.github.dsheirer.crypto.DecryptionEngine;
import io.github.dsheirer.identifier.Form;
import io.github.dsheirer.identifier.Identifier;
import io.github.dsheirer.identifier.IdentifierUpdateNotification;
import io.github.dsheirer.identifier.IdentifierUpdateProvider;
import io.github.dsheirer.identifier.Role;
import io.github.dsheirer.identifier.integer.IntegerIdentifier;
import io.github.dsheirer.identifier.tone.AmbeTone;
import io.github.dsheirer.identifier.tone.P25ToneIdentifier;
import io.github.dsheirer.identifier.tone.Tone;
import io.github.dsheirer.identifier.tone.ToneIdentifier;
import io.github.dsheirer.identifier.tone.ToneIdentifierMessage;
import io.github.dsheirer.identifier.tone.ToneSequence;
import io.github.dsheirer.message.IMessage;
import io.github.dsheirer.message.IMessageProvider;
import io.github.dsheirer.module.decode.p25.phase2.message.EncryptionSynchronizationSequence;
import io.github.dsheirer.module.decode.p25.phase2.message.mac.MacMessage;
import io.github.dsheirer.module.decode.p25.phase2.message.mac.structure.MacStructure;
import io.github.dsheirer.module.decode.p25.phase2.message.mac.structure.PushToTalk;
import io.github.dsheirer.module.decode.p25.phase2.timeslot.AbstractVoiceTimeslot;
import io.github.dsheirer.module.decode.p25.reference.Encryption;
import io.github.dsheirer.preference.UserPreferences;
import io.github.dsheirer.protocol.Protocol;
import io.github.dsheirer.sample.Listener;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import jmbe.iface.IAudioWithMetadata;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class P25P2AudioModule extends AmbeAudioModule implements IdentifierUpdateProvider, IMessageProvider
{
    private final static Logger mLog = LoggerFactory.getLogger(P25P2AudioModule.class);
    private static final int UNSET_ALGORITHM = -1;

    private Listener<IdentifierUpdateNotification> mIdentifierUpdateNotificationListener;
    private SquelchStateListener mSquelchStateListener = new SquelchStateListener();
    private ToneMetadataProcessor mToneMetadataProcessor = new ToneMetadataProcessor();
    private Queue<AbstractVoiceTimeslot> mQueuedAudioTimeslots = new ArrayDeque<>();
    private boolean mEncryptedCallStateEstablished = false;
    private boolean mEncryptedCall = false;
    private Listener<IMessage> mMessageListener;

    private DecryptionEngine mDecryptionEngine;
    private String mCurrentEncryptionKID;
    private byte[] mCurrentMessageIndicator;
    private int mCurrentEncryptionAlgorithm = UNSET_ALGORITHM;
    private Map<Integer, CachedKey> mTalkgroupKeyCache = new ConcurrentHashMap<>();

    public P25P2AudioModule(UserPreferences userPreferences, int timeslot, AliasList aliasList)
    {
        super(userPreferences, aliasList, timeslot);
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
    public Listener<SquelchStateEvent> getSquelchStateListener()
    {
        return mSquelchStateListener;
    }

    /**
     * Resets this audio module upon completion of an audio call to prepare for the next call.  This method is
     * controlled by the squelch state listener and squelch state is controlled by the P25P2DecoderState.
     */
    @Override
    public void reset()
    {
        //Explicitly clear FROM identifiers to ensure previous call TONE identifiers are cleared.
        mIdentifierCollection.remove(Role.FROM);

        mToneMetadataProcessor.reset();
        mQueuedAudioTimeslots.clear();

        //Reset encrypted call handling flags
        mEncryptedCallStateEstablished = false;
        mEncryptedCall = false;
        mCurrentEncryptionKID = null;
        mCurrentMessageIndicator = null;
        mCurrentEncryptionAlgorithm = UNSET_ALGORITHM;
        mTalkgroupKeyCache.clear();
    }

    @Override
    public void start()
    {
        reset();
    }

    /**
     * Primary message processing method for processing voice timeslots and Push-To-Talk MAC messages
     *
     * Audio timeslots are temporarily queued until a determination of the encrypted state of the call is determined
     * and then all queued audio is processed through to the end of the call.  Encryption state is determined either
     * by the PTT MAC message or by processing the ESS fragments from the Voice2 and Voice4 timeslots.
     *
     * @param message to process
     */
    @Override
    public void receive(IMessage message)
    {
        if(message.getTimeslot() == getTimeslot())
        {
            if(message instanceof AbstractVoiceTimeslot abstractVoiceTimeslot)
            {
                if(mEncryptedCallStateEstablished)
                {
                    if(!mEncryptedCall)
                    {
                        processAudio(abstractVoiceTimeslot.getVoiceFrames(), message.getTimestamp());
                    }
                    else if(mDecryptionEngine != null && mCurrentEncryptionKID != null)
                    {
                        processEncryptedAudio(abstractVoiceTimeslot.getVoiceFrames(), message.getTimestamp());
                    }
                }
                else
                {
                    //Queue audio timeslots until we can determine if the audio is encrypted or not
                    mQueuedAudioTimeslots.offer(abstractVoiceTimeslot);
                }
            }
            else if(message instanceof MacMessage macMessage && message.isValid())
            {
                MacStructure macStructure = macMessage.getMacStructure();

                if(macStructure instanceof PushToTalk pushToTalk)
                {
                    mEncryptedCallStateEstablished = true;
                    mEncryptedCall = pushToTalk.isEncrypted();

                    if(mEncryptedCall)
                    {
                        mCurrentEncryptionKID = String.format("%04X", pushToTalk.getEncryptionKey().getValue().getKey());
                        mCurrentMessageIndicator = DecryptionEngine.hexToBytes(pushToTalk.getMessageIndicator());
                        mCurrentEncryptionAlgorithm = pushToTalk.getEncryptionKey().getValue().getAlgorithm();
                    }

                    //There should not be any pending voice timeslots to process since the PTT message is the first in
                    //the audio call sequence.
                    clearPendingVoiceTimeslots();
                }
            }
            else if(message instanceof EncryptionSynchronizationSequence ess && message.isValid())
            {
                mEncryptedCallStateEstablished = true;
                mEncryptedCall = ess.isEncrypted();

                if(mEncryptedCall)
                {
                    mCurrentEncryptionKID = String.format("%04X", ess.getEncryptionKey().getValue().getKey());
                    mCurrentMessageIndicator = DecryptionEngine.hexToBytes(ess.getMessageIndicator());
                    mCurrentEncryptionAlgorithm = ess.getEncryptionKey().getValue().getAlgorithm();
                }

                processPendingVoiceTimeslots();
            }
        }
    }

    /**
     * Drains and processes any audio timeslots that have been queued pending determination of encrypted call status
     */
    private void processPendingVoiceTimeslots()
    {
        AbstractVoiceTimeslot timeslot = mQueuedAudioTimeslots.poll();

        while(timeslot != null)
        {
            receive(timeslot);
            timeslot = mQueuedAudioTimeslots.poll();
        }
    }

    /**
     * Clears/deletes any pending voice timeslots
     */
    private void clearPendingVoiceTimeslots()
    {
        mQueuedAudioTimeslots.clear();
    }

    /**
     * Process the audio voice frames
     * @param voiceFrames to process
     * @param timestamp of the carrier message
     */
    private void processAudio(List<BinaryMessage> voiceFrames, long timestamp)
    {
        if(hasAudioCodec())
        {
            for(BinaryMessage voiceFrame: voiceFrames)
            {
                byte[] voiceFrameBytes = voiceFrame.getBytes();

                try
                {
                    IAudioWithMetadata audioWithMetadata = getAudioCodec().getAudioWithMetadata(voiceFrameBytes);
                    addAudio(audioWithMetadata.getAudio());
                    processMetadata(audioWithMetadata, timestamp);
                }
                catch(Exception e)
                {
                    mLog.error("Error synthesizing AMBE audio - continuing [" + e.getLocalizedMessage() + "]");
                }
            }
        }
    }

    /**
     * Decrypts and processes encrypted audio voice frames using the registered DecryptionEngine.
     * All voice frames in the timeslot are concatenated, decrypted as a single block, then processed individually.
     * @param voiceFrames to decrypt and process
     * @param timestamp of the carrier message
     */
    private void processEncryptedAudio(List<BinaryMessage> voiceFrames, long timestamp)
    {
        if(!hasAudioCodec() || voiceFrames.isEmpty())
        {
            return;
        }

        int frameSize = voiceFrames.get(0).getBytes().length;
        byte[] concatenated = new byte[voiceFrames.size() * frameSize];
        for(int i = 0; i < voiceFrames.size(); i++)
        {
            byte[] frameBytes = voiceFrames.get(i).getBytes();
            System.arraycopy(frameBytes, 0, concatenated, i * frameSize, Math.min(frameBytes.length, frameSize));
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
            for(int i = 0; i < voiceFrames.size(); i++)
            {
                byte[] decryptedFrame = java.util.Arrays.copyOfRange(decrypted, i * frameSize, (i + 1) * frameSize);
                try
                {
                    IAudioWithMetadata audioWithMetadata = getAudioCodec().getAudioWithMetadata(decryptedFrame);
                    addAudio(audioWithMetadata.getAudio());
                    processMetadata(audioWithMetadata, timestamp);
                }
                catch(Exception e)
                {
                    mLog.error("Error synthesizing decrypted AMBE audio - continuing [" + e.getLocalizedMessage() + "]");
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
     * @param ciphertext encrypted AMBE frame bytes
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
     * Processes optional metadata that can be included with decoded audio (ie dtmf, tones, knox, etc.) so that the
     * tone metadata can be converted into a FROM identifier and included with any call segment.
     */
    private void processMetadata(IAudioWithMetadata audioWithMetadata, long timestamp)
    {
        if(audioWithMetadata.hasMetadata())
        {
            //JMBE only places 1 entry in the map, but for consistency we'll process the map entry set
            for(Map.Entry<String,String> entry: audioWithMetadata.getMetadata().entrySet())
            {
                //Each metadata map entry contains a tone-type (key) and tone (value)
                ToneIdentifier toneIdentifier = mToneMetadataProcessor.process(entry.getKey(), entry.getValue());

                if(toneIdentifier != null)
                {
                    broadcast(toneIdentifier, timestamp);
                }
            }
        }
        else
        {
            mToneMetadataProcessor.closeMetadata();
        }
    }

    /**
     * Broadcasts the identifier to a registered listener and creates a new AMBE tone identifier message when tones are
     * present to send to the alias action manager
     */
    private void broadcast(ToneIdentifier identifier, long timestamp)
    {
        if(mIdentifierUpdateNotificationListener != null)
        {
            mIdentifierUpdateNotificationListener.receive(new IdentifierUpdateNotification(identifier,
                IdentifierUpdateNotification.Operation.ADD, getTimeslot()));
        }

        if(mMessageListener != null)
        {
            StringBuilder sb = new StringBuilder();
            sb.append("P25.2 Timeslot ");
            sb.append(getTimeslot());
            sb.append("Audio Tone Sequence Decoded: ");
            sb.append(identifier.toString());

            mMessageListener.receive(new ToneIdentifierMessage(Protocol.APCO25_PHASE2, getTimeslot(), timestamp,
                    identifier, sb.toString()));
        }
    }

    /**
     * Registers the listener to receive identifier updates
     */
    @Override
    public void setIdentifierUpdateListener(Listener<IdentifierUpdateNotification> listener)
    {
        mIdentifierUpdateNotificationListener = listener;
    }

    /**
     * Unregisters a listener from receiving identifier updates
     */
    @Override
    public void removeIdentifierUpdateListener()
    {
        mIdentifierUpdateNotificationListener = null;
    }

    /**
     * Registers a message listener to receive AMBE tone identifier messages.
     * @param listener to register
     */
    @Override
    public void setMessageListener(Listener<IMessage> listener)
    {
        mMessageListener = listener;
    }

    /**
     * Removes the message listener
     */
    @Override
    public void removeMessageListener()
    {
        mMessageListener = null;
    }

    /**
     * Process AMBE audio frame tone metadata.  Tracks the count of sequential frames containing tone metadata to
     * provide a list of each unique tone and a time duration (milliseconds) for the tone.  Tones are concatenated into
     * a comma separated list and included as call segment metadata.
     */
    public class ToneMetadataProcessor
    {
        private List<Tone> mTones = new ArrayList<>();
        private Tone mCurrentTone;

        /**
         * Resets or clears any accumulated call tone sequences to prepare for the next call.
         */
        public void reset()
        {
            mTones.clear();
        }

        /**
         * Process the tone metadata
         * @param type of tone
         * @param value of tone
         * @return an identifier with the accumulated tone metadata set
         */
        public ToneIdentifier process(String type, String value)
        {
            if(type == null || value == null)
            {
                return null;
            }

            AmbeTone tone = AmbeTone.fromValues(type, value);

            if(tone == AmbeTone.INVALID)
            {
                return null;
            }

            if(mCurrentTone == null || mCurrentTone.getAmbeTone() != tone)
            {
                mCurrentTone = new Tone(tone);
                mTones.add(mCurrentTone);
            }

            mCurrentTone.incrementDuration();

            return P25ToneIdentifier.create(new ToneSequence(new ArrayList<>(mTones)));
        }

        /**
         * Closes current tone metadata when there is no metadata for the current audio frame.
         */
        public void closeMetadata()
        {
            mCurrentTone = null;
        }
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
            if(event.getTimeslot() == getTimeslot())
            {
                if(event.getSquelchState() == SquelchState.SQUELCH)
                {
                    closeAudioSegment();
                    reset();
                }
            }
        }
    }

    /**
     * Holds cached decryption key data for a talkgroup, including the raw key bytes and algorithm name.
     */
    private record CachedKey(byte[] rawKey, String algorithm) {}
}
