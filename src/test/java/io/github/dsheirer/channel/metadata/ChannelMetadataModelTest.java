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

package io.github.dsheirer.channel.metadata;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

/**
 * Tests for ChannelMetadataModel boundary conditions, particularly the off-by-one fix
 * in getValueAt() that previously used {@code <=} instead of {@code <}.
 */
public class ChannelMetadataModelTest
{
    @Test
    public void testGetValueAtEmptyModel()
    {
        ChannelMetadataModel model = new ChannelMetadataModel();

        //Row 0 in an empty model (size=0) should return null, not throw
        assertDoesNotThrow(() -> model.getValueAt(0, ChannelMetadataModel.COLUMN_DECODER_STATE),
            "getValueAt with rowIndex=0 on empty model should not throw IndexOutOfBoundsException");

        Object result = model.getValueAt(0, ChannelMetadataModel.COLUMN_DECODER_STATE);
        assertNull(result, "getValueAt for empty model should return null");
    }

    @Test
    public void testGetRowCountEmpty()
    {
        ChannelMetadataModel model = new ChannelMetadataModel();
        assertEquals(0, model.getRowCount(), "Empty model should have 0 rows");
    }

    @Test
    public void testColumnCount()
    {
        ChannelMetadataModel model = new ChannelMetadataModel();
        assertEquals(9, model.getColumnCount(), "Model should have 9 columns");
    }
}
