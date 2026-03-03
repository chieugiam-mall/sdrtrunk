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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import io.github.dsheirer.alias.id.AliasID;
import io.github.dsheirer.alias.id.AliasIDType;

/**
 * Alias identifier that associates an encryption key with a talkgroup alias.
 * When added to an alias, the specified key will be used to decrypt audio for
 * that talkgroup, bypassing the need to match the transmitted key ID (KID) to
 * a key registered in the global DecryptionEngine.
 *
 * This is particularly useful for Motorola ADP (40-bit RC4) systems where the
 * same key applies to all calls on a talkgroup.
 */
public class EncryptionKeyID extends AliasID
{
    private String mAlgorithm = "RC4";
    private String mKey = "";

    public EncryptionKeyID()
    {
    }

    public EncryptionKeyID(String algorithm, String key)
    {
        mAlgorithm = algorithm;
        mKey = key;
    }

    /**
     * Encryption algorithm name: RC4, DES, or AES.
     */
    @JacksonXmlProperty(isAttribute = true, localName = "algorithm")
    public String getAlgorithm()
    {
        return mAlgorithm;
    }

    public void setAlgorithm(String algorithm)
    {
        mAlgorithm = algorithm;
        updateValueProperty();
    }

    /**
     * Hex-encoded encryption key string.
     */
    @JacksonXmlProperty(isAttribute = true, localName = "key")
    public String getKey()
    {
        return mKey;
    }

    public void setKey(String key)
    {
        mKey = key;
        updateValueProperty();
    }

    /**
     * Returns the raw key bytes parsed from the hex key string, or null if the key is invalid.
     */
    @JsonIgnore
    public byte[] getRawKeyBytes()
    {
        if(mKey == null || mKey.isEmpty() || mKey.length() % 2 != 0)
        {
            return null;
        }

        try
        {
            byte[] bytes = new byte[mKey.length() / 2];
            for(int i = 0; i < mKey.length(); i += 2)
            {
                bytes[i / 2] = (byte) Integer.parseInt(mKey.substring(i, i + 2), 16);
            }
            return bytes;
        }
        catch(NumberFormatException e)
        {
            return null;
        }
    }

    @JacksonXmlProperty(isAttribute = true, localName = "type", namespace = "http://www.w3.org/2001/XMLSchema-instance")
    @Override
    public AliasIDType getType()
    {
        return AliasIDType.ENCRYPTION_KEY;
    }

    @Override
    public boolean isAudioIdentifier()
    {
        return false;
    }

    @Override
    public boolean isValid()
    {
        return mAlgorithm != null && !mAlgorithm.isEmpty() && getRawKeyBytes() != null;
    }

    @Override
    public boolean matches(AliasID id)
    {
        return false;
    }

    @Override
    public String toString()
    {
        String maskedKey = (mKey != null && mKey.length() >= 4)
            ? "\u2022\u2022\u2022\u2022" + mKey.substring(mKey.length() - 4)
            : "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022";
        return "Encryption Key: " + mAlgorithm + " [" + maskedKey + "]";
    }
}
