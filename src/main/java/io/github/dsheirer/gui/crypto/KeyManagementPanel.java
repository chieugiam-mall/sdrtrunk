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
import java.util.HexFormat;
import java.util.List;
import javax.swing.DefaultListSelectionModel;
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

    private DefaultTableModel mTableModel;
    private JTable mTable;
    private JTextField mKidField;
    private JComboBox<String> mAlgorithmCombo;
    private JPasswordField mKeyField;
    private JLabel mStatusLabel;

    /**
     * Constructs a KeyManagementPanel wired to the given DecryptionEngine.
     *
     * @param engine The shared DecryptionEngine singleton
     */
    public KeyManagementPanel(DecryptionEngine engine)
    {
        mDecryptionEngine = engine;
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
        JPanel bottomPanel = new JPanel(new MigLayout("insets 0", "[]push[]", "[]"));

        mStatusLabel = new JLabel(" ");
        bottomPanel.add(mStatusLabel, "growx");

        JButton removeButton = new JButton("Remove Selected");
        removeButton.addActionListener(e -> onRemoveSelected());
        bottomPanel.add(removeButton);

        add(bottomPanel, "wrap");
    }

    /**
     * Handles the Add Key button action.
     */
    private void onAddKey()
    {
        String kid = mKidField.getText().trim();
        String algorithm = (String) mAlgorithmCombo.getSelectedItem();
        String hexKey = new String(mKeyField.getPassword()).trim();

        if(kid.isEmpty())
        {
            setStatus("KID cannot be empty.", true);
            return;
        }

        if(hexKey.isEmpty())
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

        byte[] keyBytes;
        try
        {
            keyBytes = parseHex(hexKey);
        }
        catch(IllegalArgumentException ex)
        {
            setStatus("Invalid hex key: " + ex.getMessage(), true);
            return;
        }

        mDecryptionEngine.addKey(kid, algorithm, keyBytes);
        mKeyField.setText("");
        mKidField.setText("");
        refreshTable();
        setStatus("Key added for KID '" + kid + "'.", false);
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
     * Parses a hex string into a byte array.
     *
     * @param hex Hex string (must have even length, valid hex digits)
     * @return Parsed byte array
     * @throws IllegalArgumentException if the string is not valid hex
     */
    private static byte[] parseHex(String hex)
    {
        String cleaned = hex.replaceAll("\\s", "");

        if(cleaned.length() % 2 != 0)
        {
            throw new IllegalArgumentException("Hex string must have an even number of characters");
        }

        try
        {
            return HexFormat.of().parseHex(cleaned);
        }
        catch(IllegalArgumentException e)
        {
            throw new IllegalArgumentException("Invalid hex characters in key");
        }
    }
}
