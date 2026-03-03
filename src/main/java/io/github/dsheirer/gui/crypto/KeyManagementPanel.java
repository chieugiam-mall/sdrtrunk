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

// Part of the crypto subsystem GUI for managing encryption keys (KIDs).
package io.github.dsheirer.gui.crypto;

import io.github.dsheirer.crypto.DecryptionEngine;
import io.github.dsheirer.crypto.EncryptionKey;
import java.awt.Font;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableModel;
import net.miginfocom.swing.MigLayout;

/**
 * Swing panel for managing encryption keys in the DecryptionEngine.
 * Allows adding and removing KID/algorithm/key combinations via a JTable.
 * Keys are never displayed in plain text; the table always shows a masked value.
 */
public class KeyManagementPanel extends JPanel
{
    private static final String[] TABLE_COLUMNS = {"KID", "Algorithm", "Key (masked)"};

    private final DecryptionEngine mDecryptionEngine;
    private final Path mConfigPath;

    private DefaultTableModel mTableModel;
    private JTable mTable;
    private JTextField mKidField;
    private JComboBox<String> mAlgorithmCombo;
    private JPasswordField mKeyField;
    private JLabel mStatusLabel;

    /**
     * Constructs a KeyManagementPanel wired to the given DecryptionEngine.
     *
     * @param engine     The shared DecryptionEngine singleton
     * @param configPath Path to the JSON file used to persist keys (may be null to disable persistence)
     */
    public KeyManagementPanel(DecryptionEngine engine, Path configPath)
    {
        mDecryptionEngine = engine;
        mConfigPath = configPath;
        initComponents();
        refreshTable();
    }

    private void initComponents()
    {
        setLayout(new MigLayout("insets 10", "[grow,fill]", "[][grow,fill][][]"));

        // Title
        JLabel titleLabel = new JLabel("Encryption Key Management");
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 14f));
        titleLabel.setHorizontalAlignment(SwingConstants.CENTER);
        add(titleLabel, "wrap");

        // Table
        mTableModel = new DefaultTableModel(TABLE_COLUMNS, 0)
        {
            @Override
            public boolean isCellEditable(int row, int column)
            {
                return false;
            }
        };

        mTable = new JTable(mTableModel);
        mTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        mTable.setFillsViewportHeight(true);

        JScrollPane scrollPane = new JScrollPane(mTable);
        add(scrollPane, "wrap, height 150:200:400");

        // Add Key section
        JPanel addPanel = new JPanel(new MigLayout("insets 5", "[][grow,fill][grow,fill][grow,fill][]", "[]"));

        addPanel.add(new JLabel("KID:"));
        mKidField = new JTextField(6);
        mKidField.setToolTipText("Key ID, e.g. 0001");
        addPanel.add(mKidField, "growx");

        addPanel.add(new JLabel("Algorithm:"));
        mAlgorithmCombo = new JComboBox<>(new String[]{"RC4", "DES", "AES"});
        addPanel.add(mAlgorithmCombo);

        addPanel.add(new JLabel("Key (hex):"));
        mKeyField = new JPasswordField(20);
        mKeyField.setEchoChar('\u2022');
        mKeyField.setToolTipText("Enter key as hex string, e.g. 0011AABB...");
        addPanel.add(mKeyField, "growx");

        JButton addButton = new JButton("Add Key");
        addButton.addActionListener(e -> onAddKey());
        addPanel.add(addButton, "wrap");

        add(addPanel, "wrap");

        // Remove button + status
        JPanel bottomPanel = new JPanel(new MigLayout("insets 0", "[]push[][]", "[]"));

        mStatusLabel = new JLabel(" ");
        bottomPanel.add(mStatusLabel, "growx");

        JButton removeButton = new JButton("Remove Selected");
        removeButton.addActionListener(e -> onRemoveSelected());
        bottomPanel.add(removeButton);

        JButton closeButton = new JButton("Close");
        closeButton.addActionListener(e -> SwingUtilities.getWindowAncestor(this).dispose());
        bottomPanel.add(closeButton);

        add(bottomPanel, "wrap");
    }

    /**
     * Handles the Add Key button action.
     */
    private void onAddKey()
    {
        String kid = mKidField.getText().trim();
        String algorithm = (String) mAlgorithmCombo.getSelectedItem();
        char[] passwordChars = mKeyField.getPassword();

        try
        {
            if(kid.isEmpty())
            {
                setStatus("KID cannot be empty.", true);
                return;
            }

            if(passwordChars.length == 0)
            {
                setStatus("Key cannot be empty.", true);
                return;
            }

            // Check for duplicate KID
            for(EncryptionKey existing : mDecryptionEngine.getKeys())
            {
                if(existing.getKid().equalsIgnoreCase(kid))
                {
                    setStatus("KID '" + kid + "' already exists. Remove it first.", true);
                    return;
                }
            }

            // Convert char[] to trimmed char[] without creating a String
            int start = 0;
            int end = passwordChars.length;
            while(start < end && passwordChars[start] == ' ') start++;
            while(end > start && passwordChars[end - 1] == ' ') end--;
            char[] hexChars = Arrays.copyOfRange(passwordChars, start, end);

            byte[] keyBytes;
            try
            {
                keyBytes = parseHex(hexChars);
            }
            catch(IllegalArgumentException ex)
            {
                setStatus("Invalid hex key: " + ex.getMessage(), true);
                return;
            }
            finally
            {
                Arrays.fill(hexChars, '\0');
            }

            mDecryptionEngine.addKey(kid, algorithm, keyBytes);
            mKeyField.setText("");
            mKidField.setText("");
            refreshTable();
            saveKeys();
            setStatus("Key added for KID '" + kid + "'.", false);
        }
        finally
        {
            Arrays.fill(passwordChars, '\0');
        }
    }

    /**
     * Handles the Remove Selected button action.
     */
    private void onRemoveSelected()
    {
        int selectedRow = mTable.getSelectedRow();

        if(selectedRow < 0)
        {
            setStatus("No key selected.", true);
            return;
        }

        String kid = (String) mTableModel.getValueAt(selectedRow, 0);
        mDecryptionEngine.removeKey(kid);
        refreshTable();
        saveKeys();
        setStatus("Key removed for KID '" + kid + "'.", false);
    }

    /**
     * Refreshes the table from the current state of the DecryptionEngine.
     */
    private void refreshTable()
    {
        mTableModel.setRowCount(0);
        List<EncryptionKey> keys = mDecryptionEngine.getKeys();

        for(EncryptionKey key : keys)
        {
            mTableModel.addRow(new Object[]{key.getKid(), key.getAlgorithm(), key.getMaskedKey()});
        }
    }

    /**
     * Updates the status label.
     *
     * @param message Message to display
     * @param isError True to indicate an error (displayed in red), false for success
     */
    private void setStatus(String message, boolean isError)
    {
        mStatusLabel.setText(message);
        mStatusLabel.setForeground(isError ? java.awt.Color.RED : new java.awt.Color(0, 128, 0));
    }

    /**
     * Saves current keys to the configured file path, if set.
     */
    private void saveKeys()
    {
        if(mConfigPath == null)
        {
            return;
        }

        try
        {
            mDecryptionEngine.save(mConfigPath);
        }
        catch(IOException e)
        {
            setStatus("Failed to save keys to [" + mConfigPath + "]: " + e.getMessage(), true);
        }
    }

    /**
     * Parses a hex char array into a byte array without creating an intermediate String.
     *
     * @param hex Hex char array (must have even length, valid hex digits)
     * @return Parsed byte array
     * @throws IllegalArgumentException if the array is not valid hex
     */
    private static byte[] parseHex(char[] hex)
    {
        if(hex.length % 2 != 0)
        {
            throw new IllegalArgumentException("Hex string must have an even number of characters");
        }

        byte[] result = new byte[hex.length / 2];

        for(int i = 0; i < hex.length; i += 2)
        {
            int high = Character.digit(hex[i], 16);
            int low = Character.digit(hex[i + 1], 16);

            if(high == -1 || low == -1)
            {
                throw new IllegalArgumentException("Invalid hex characters in key");
            }

            result[i / 2] = (byte) ((high << 4) | low);
        }

        return result;
    }
}
