package net.bytebutcher.burpautodropextension.gui;

import burp.BurpExtender;
import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import com.intellij.uiDesigner.core.Spacer;
import net.bytebutcher.burpautodropextension.gui.listener.AutoDropRequestTableListener;
import net.bytebutcher.burpautodropextension.gui.util.WebUtil;
import net.bytebutcher.burpautodropextension.models.AutoDropRequestRule;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.net.MalformedURLException;
import java.net.URL;

public class AutoDropRequestTab {
    private BurpExtender burpExtender;
    private JButton btnAutoDropRequestRemove;
    private JButton btnAutoDropRequestEdit;
    private JButton btnAutoDropRequestAdd;
    private JButton btnAutoDropRequestUp;
    private JButton btnAutoDropRequestDown;
    private JTable tblAutoDropRequest;

    private AutoDropRequestTable autoDropRequestTable;

    private JPanel formPanel;
    private JLabel lblSettings;
    private JLabel lblHelp;
    private JCheckBox chkLogAutoDropRequests;
    private AutoDropRequestTableListener autoDropRequestTableListener;
    private final AutoDropRequestTabSettingsContextMenu autoDropRequestTabSettingsContextMenu;


    public AutoDropRequestTab(final BurpExtender burpExtender) {
        this.burpExtender = burpExtender;
        $$$setupUI$$$();
        this.lblHelp.setIcon(this.burpExtender.createImageIcon("/panel_help.png", "", 24, 24));
        this.lblSettings.setIcon(this.burpExtender.createImageIcon("/panel_settings.png", "", 24, 24));
        this.autoDropRequestTableListener = new AutoDropRequestTableListener(this.tblAutoDropRequest, this.autoDropRequestTable, burpExtender);
        this.tblAutoDropRequest.getModel().addTableModelListener(autoDropRequestTableListener);
        btnAutoDropRequestAdd.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(final ActionEvent e) {
                new Thread(new Runnable() {
                    public void run() {
                        AutoDropRequestAddDialog addDialog = new AutoDropRequestAddDialog(getParent(), "Add \"Auto-Drop Request\" rule");
                        if (addDialog.run()) {
                            autoDropRequestTableListener.onAddButtonClick(e, addDialog.getAutoDropRequestRule());
                        }
                    }
                }).start();
            }
        });
        btnAutoDropRequestEdit.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                AutoDropRequestRule autoDropRequestRule = autoDropRequestTable.getSelectedAutoDropRequestRule();
                AutoDropRequestAddDialog editDialog = new AutoDropRequestAddDialog(getParent(), "Edit \"Auto-Drop Request\" rule", autoDropRequestRule);
                if (editDialog.run()) {
                    autoDropRequestTableListener.onEditButtonClick(e, editDialog.getAutoDropRequestRule());
                }
            }
        });
        btnAutoDropRequestRemove.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                autoDropRequestTableListener.onRemoveButtonClick(e);
            }
        });
        btnAutoDropRequestUp.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                autoDropRequestTableListener.onUpButtonClick(e);
            }
        });
        btnAutoDropRequestDown.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                autoDropRequestTableListener.onDownButtonClick(e);
            }
        });
        lblHelp.addMouseListener(new LabelIconImageHoverAdapter(lblHelp, "/panel_help.png", "/panel_help_highlighted.png"));
        lblSettings.addMouseListener(new LabelIconImageHoverAdapter(lblSettings, "/panel_settings.png", "/panel_settings_highlighted.png"));
        lblHelp.addMouseListener(new MouseAdapter() {

            @Override
            public void mouseClicked(MouseEvent e) {
                try {
                    WebUtil.openWebpage(new URL("https://github.com/PortSwigger/burp-auto-drop"));
                } catch (MalformedURLException e1) {
                    // Nothing to do here...
                }
            }
        });
        autoDropRequestTabSettingsContextMenu = new AutoDropRequestTabSettingsContextMenu(burpExtender, this);
        lblSettings.addMouseListener(new MouseAdapter() {

            @Override
            public void mouseClicked(MouseEvent e) {
                autoDropRequestTabSettingsContextMenu.show(lblSettings, lblSettings.getX() + lblSettings.getWidth(), lblSettings.getY());
            }
        });
        chkLogAutoDropRequests.setSelected(burpExtender.getConfig().isLoggingEnabled());
        chkLogAutoDropRequests.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                burpExtender.getConfig().enableLogging(chkLogAutoDropRequests.isSelected());
            }
        });
    }

    public void resetOptions() {
        autoDropRequestTable.clearTable();
    }

    /**
     * Method generated by IntelliJ IDEA GUI Designer
     * >>> IMPORTANT!! <<<
     * DO NOT edit this method OR call it in your code!
     *
     * @noinspection ALL
     */
    private void $$$setupUI$$$() {
        createUIComponents();
        formPanel = new JPanel();
        formPanel.setLayout(new GridLayoutManager(5, 1, new Insets(10, 10, 10, 10), -1, -1));
        final JPanel panel1 = new JPanel();
        panel1.setLayout(new GridLayoutManager(3, 2, new Insets(0, 0, 0, 0), -1, -1));
        formPanel.add(panel1, new GridConstraints(0, 0, 3, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        panel1.add(panel2, new GridConstraints(2, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JPanel panel3 = new JPanel();
        panel3.setLayout(new GridLayoutManager(6, 1, new Insets(0, 0, 0, 0), -1, -1));
        panel2.add(panel3, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        btnAutoDropRequestRemove = new JButton();
        btnAutoDropRequestRemove.setText("Remove");
        panel3.add(btnAutoDropRequestRemove, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        btnAutoDropRequestEdit = new JButton();
        btnAutoDropRequestEdit.setText("Edit");
        panel3.add(btnAutoDropRequestEdit, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        btnAutoDropRequestAdd = new JButton();
        btnAutoDropRequestAdd.setText("Add");
        panel3.add(btnAutoDropRequestAdd, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer1 = new Spacer();
        panel3.add(spacer1, new GridConstraints(5, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_VERTICAL, 1, GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        btnAutoDropRequestUp = new JButton();
        btnAutoDropRequestUp.setText("Up");
        btnAutoDropRequestUp.setMnemonic('U');
        btnAutoDropRequestUp.setDisplayedMnemonicIndex(0);
        panel3.add(btnAutoDropRequestUp, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        btnAutoDropRequestDown = new JButton();
        btnAutoDropRequestDown.setText("Down");
        btnAutoDropRequestDown.setMnemonic('D');
        btnAutoDropRequestDown.setDisplayedMnemonicIndex(0);
        panel3.add(btnAutoDropRequestDown, new GridConstraints(4, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JScrollPane scrollPane1 = new JScrollPane();
        panel2.add(scrollPane1, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        scrollPane1.setViewportView(tblAutoDropRequest);
        final JLabel label1 = new JLabel();
        label1.setText("<html>Use these settings to control which HTTP requests are dropped automatically.<br></html>");
        panel1.add(label1, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label2 = new JLabel();
        Font label2Font = this.$$$getFont$$$(null, Font.BOLD, 14, label2.getFont());
        if (label2Font != null) label2.setFont(label2Font);
        label2.setForeground(new Color(-1341440));
        label2.setText("Auto-Drop Requests");
        panel1.add(label2, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel4 = new JPanel();
        panel4.setLayout(new GridLayoutManager(1, 1, new Insets(2, 2, 2, 2), -1, -1));
        panel1.add(panel4, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, new Dimension(26, 26), 0, false));
        lblSettings = new JLabel();
        lblSettings.setText("");
        panel4.add(lblSettings, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel5 = new JPanel();
        panel5.setLayout(new GridLayoutManager(1, 1, new Insets(2, 2, 2, 2), -1, -1));
        panel1.add(panel5, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, new Dimension(26, 26), 0, false));
        lblHelp = new JLabel();
        lblHelp.setText("");
        panel5.add(lblHelp, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel6 = new JPanel();
        panel6.setLayout(new GridLayoutManager(3, 4, new Insets(0, 0, 0, 0), -1, -1));
        formPanel.add(panel6, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JLabel label3 = new JLabel();
        Font label3Font = this.$$$getFont$$$(null, Font.BOLD, 14, label3.getFont());
        if (label3Font != null) label3.setFont(label3Font);
        label3.setForeground(new Color(-1341440));
        label3.setText("Miscellaneous Options");
        panel6.add(label3, new GridConstraints(0, 1, 1, 3, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel7 = new JPanel();
        panel7.setLayout(new GridLayoutManager(1, 1, new Insets(2, 2, 2, 2), -1, -1));
        panel6.add(panel7, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, new Dimension(26, 26), null, new Dimension(26, 26), 0, false));
        final JLabel label4 = new JLabel();
        label4.setText("");
        panel7.add(label4, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel8 = new JPanel();
        panel8.setLayout(new GridLayoutManager(1, 1, new Insets(0, 0, 0, 0), -1, -1));
        panel6.add(panel8, new GridConstraints(2, 1, 1, 3, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final Spacer spacer2 = new Spacer();
        panel8.add(spacer2, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        chkLogAutoDropRequests = new JCheckBox();
        chkLogAutoDropRequests.setText("Log requests which are automatically dropped in Extender tab");
        panel6.add(chkLogAutoDropRequests, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer3 = new Spacer();
        formPanel.add(spacer3, new GridConstraints(4, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_VERTICAL, 1, GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
    }

    /**
     * @noinspection ALL
     */
    private Font $$$getFont$$$(String fontName, int style, int size, Font currentFont) {
        if (currentFont == null) return null;
        String resultName;
        if (fontName == null) {
            resultName = currentFont.getName();
        } else {
            Font testFont = new Font(fontName, Font.PLAIN, 10);
            if (testFont.canDisplay('a') && testFont.canDisplay('1')) {
                resultName = fontName;
            } else {
                resultName = currentFont.getName();
            }
        }
        return new Font(resultName, style >= 0 ? style : currentFont.getStyle(), size >= 0 ? size : currentFont.getSize());
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return formPanel;
    }

    class LabelIconImageHoverAdapter extends MouseAdapter {

        private String resource;
        private String resourceHovered;
        private JLabel label;

        public LabelIconImageHoverAdapter(JLabel label, String resource, String resourceHovered) {
            this.label = label;
            this.resource = resource;
            this.resourceHovered = resourceHovered;
        }

        @Override
        public void mouseEntered(MouseEvent e) {
            label.setIcon(AutoDropRequestTab.this.burpExtender.createImageIcon(resourceHovered, "", 24, 24));
        }

        @Override
        public void mouseExited(MouseEvent e) {
            label.setIcon(AutoDropRequestTab.this.burpExtender.createImageIcon(resource, "", 24, 24));
        }
    }

    public JPanel getRootPanel() {
        return formPanel;
    }

    public JFrame getParent() {
        return (JFrame) SwingUtilities.getRootPane(this.getRootPanel()).getParent();
    }

    public AutoDropRequestTable getAutoDropRequestTable() {
        return autoDropRequestTable;
    }

    /**
     * Creates Custom GUI forms
     */
    private void createUIComponents() {
        this.tblAutoDropRequest = this.autoDropRequestTable = new AutoDropRequestTable(this.burpExtender);
    }

    public AutoDropRequestTableListener getAutoDropRequestTableListener() {
        return this.autoDropRequestTableListener;
    }
}
