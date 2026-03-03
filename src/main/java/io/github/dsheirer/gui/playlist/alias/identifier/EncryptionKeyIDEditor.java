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

package io.github.dsheirer.gui.playlist.alias.identifier;

import io.github.dsheirer.alias.id.encryption.EncryptionKeyID;
import javafx.geometry.HPos;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.layout.GridPane;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Editor for encryption key alias identifiers
 */
public class EncryptionKeyIDEditor extends IdentifierEditor<EncryptionKeyID>
{
    private static final Logger mLog = LoggerFactory.getLogger(EncryptionKeyIDEditor.class);
    private ComboBox<String> mAlgorithmComboBox;
    private TextField mKeyField;

    /**
     * Constructs an instance
     */
    public EncryptionKeyIDEditor()
    {
        GridPane gridPane = new GridPane();
        gridPane.setHgap(5);
        gridPane.setVgap(3);

        Label algorithmLabel = new Label("Algorithm");
        GridPane.setHalignment(algorithmLabel, HPos.RIGHT);
        GridPane.setConstraints(algorithmLabel, 0, 0);
        gridPane.getChildren().add(algorithmLabel);

        GridPane.setConstraints(getAlgorithmComboBox(), 1, 0);
        gridPane.getChildren().add(getAlgorithmComboBox());

        Label keyLabel = new Label("Key (hex)");
        GridPane.setHalignment(keyLabel, HPos.RIGHT);
        GridPane.setConstraints(keyLabel, 2, 0);
        gridPane.getChildren().add(keyLabel);

        GridPane.setConstraints(getKeyField(), 3, 0);
        gridPane.getChildren().add(getKeyField());

        getChildren().add(gridPane);
    }

    @Override
    public void setItem(EncryptionKeyID item)
    {
        super.setItem(item);

        getAlgorithmComboBox().setDisable(item == null);
        getKeyField().setDisable(item == null);

        if(item != null)
        {
            String algorithm = item.getAlgorithm();
            if(algorithm != null && getAlgorithmComboBox().getItems().contains(algorithm))
            {
                getAlgorithmComboBox().getSelectionModel().select(algorithm);
            }
            else
            {
                getAlgorithmComboBox().getSelectionModel().select("RC4");
            }

            getKeyField().setText(item.getKey() != null ? item.getKey() : "");
        }
        else
        {
            getAlgorithmComboBox().getSelectionModel().select("RC4");
            getKeyField().setText("");
        }

        modifiedProperty().set(false);
    }

    @Override
    public void save()
    {
        if(getItem() != null)
        {
            getItem().setAlgorithm(getAlgorithmComboBox().getSelectionModel().getSelectedItem());
            getItem().setKey(getKeyField().getText());
        }
    }

    @Override
    public void dispose()
    {
        //no-op
    }

    private ComboBox<String> getAlgorithmComboBox()
    {
        if(mAlgorithmComboBox == null)
        {
            mAlgorithmComboBox = new ComboBox<>();
            mAlgorithmComboBox.getItems().addAll("RC4", "DES", "AES");
            mAlgorithmComboBox.getSelectionModel().select("RC4");
            mAlgorithmComboBox.setDisable(true);
            mAlgorithmComboBox.setOnAction(event -> {
                if(getItem() != null)
                {
                    modifiedProperty().set(true);
                }
            });
        }

        return mAlgorithmComboBox;
    }

    private TextField getKeyField()
    {
        if(mKeyField == null)
        {
            mKeyField = new TextField();
            mKeyField.setPromptText("Hex key (e.g. 0A1B2C3D4E)");
            mKeyField.setDisable(true);
            mKeyField.textProperty().addListener((observable, oldValue, newValue) -> {
                if(getItem() != null)
                {
                    modifiedProperty().set(true);
                }
            });
        }

        return mKeyField;
    }
}
