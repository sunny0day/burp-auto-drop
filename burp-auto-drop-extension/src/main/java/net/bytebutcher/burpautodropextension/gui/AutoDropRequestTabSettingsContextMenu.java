package net.bytebutcher.burpautodropextension.gui;

import burp.BurpExtender;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import net.bytebutcher.burpautodropextension.gui.util.DialogUtil;
import net.bytebutcher.burpautodropextension.models.AutoDropRequestRule;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.PrintWriter;
import java.util.List;

class AutoDropRequestTabSettingsContextMenu extends JPopupMenu {

    private BurpExtender burpExtender;
    private final JMenuItem restoreDefaults;
    private final JMenuItem loadOptions;
    private final JMenuItem saveOptions;

    private AutoDropRequestTable autoDropRequestTable;
    private AutoDropRequestTab autoDropRequestTab;

    public AutoDropRequestTabSettingsContextMenu(final BurpExtender burpExtender, final AutoDropRequestTab autoDropRequestTab) {
        this.burpExtender = burpExtender;
        this.autoDropRequestTab = autoDropRequestTab;
        this.autoDropRequestTable = autoDropRequestTab.getAutoDropRequestTable();
        restoreDefaults = new JMenuItem("Restore defaults");
        restoreDefaults.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                boolean result = DialogUtil.showConfirmationDialog(autoDropRequestTab.getParent(), "Reset \"Auto Drop\"-options",
                        "Do you really want to reset the \"Auto Drop\"-options?");
                if (result) {
                    autoDropRequestTab.resetOptions();
                }
            }
        });
        add(restoreDefaults);
        loadOptions = new JMenuItem("Load options");
        loadOptions.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setDialogTitle("Load \"Auto Drop\" options from file...");
                fileChooser.setCurrentDirectory(new File(System.getProperty("user.home")));
                int result = fileChooser.showOpenDialog(getParent());
                if (result == JFileChooser.APPROVE_OPTION) {
                    File selectedFile = fileChooser.getSelectedFile();
                    try {
                        List<AutoDropRequestRule> commandObjectList = new Gson().fromJson(new FileReader(selectedFile), new TypeToken<List<AutoDropRequestRule>>(){}.getType());
                        autoDropRequestTable.removeAll();
                        autoDropRequestTable.addDropRequestRules(commandObjectList);
                    } catch (FileNotFoundException e1) {
                        DialogUtil.showErrorDialog(
                                autoDropRequestTab.getParent(),
                                "Error while loading options!",
                                "<html><p>There was an unknown error while loading the options!</p>" +
                                        "<p>For more information check out the \"Auto Drop\" extension error log!</p></html>"
                        );
                        burpExtender.getCallbacks().printError("Error while loading options: " + e1);
                        return;
                    }
                    burpExtender.getCallbacks().printOutput("Successfully loaded options from '" + selectedFile.getAbsolutePath() + "'!");
                }
            }
        });
        add(loadOptions);
        saveOptions = new JMenuItem("Save options");
        saveOptions.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setDialogTitle("Save \"Auto Drop\" options to file...");

                int userSelection = fileChooser.showSaveDialog(getParent());
                if (userSelection == JFileChooser.APPROVE_OPTION) {
                    File fileToSave = fileChooser.getSelectedFile();
                    String json = new Gson().toJson(autoDropRequestTable.getAutoDropRequestRules());
                    try (PrintWriter out = new PrintWriter(fileToSave)) {
                        out.write(json);
                    } catch (FileNotFoundException e1) {
                        DialogUtil.showErrorDialog(
                                autoDropRequestTab.getParent(),
                                "Error while saving options!",
                                "<html><p>There was an unknown error while saving the options!</p>" +
                                        "<p>For more information check out the \"Auto Drop\" extension error log!</p></html>"
                        );
                        burpExtender.getCallbacks().printError("Error while saving options: " + e1);
                        return;
                    }
                    burpExtender.getCallbacks().printOutput("Successfully saved options in '" + fileToSave.getAbsolutePath() + "'!");
                }
            }
        });
        add(saveOptions);
    }
}
