package net.bytebutcher.burpautodropextension.gui;

import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import com.intellij.uiDesigner.core.Spacer;
import net.bytebutcher.burpautodropextension.models.AutoDropRequestRule;
import net.bytebutcher.burpautodropextension.gui.util.DialogUtil;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;

public class AutoDropRequestAddDialog {

    private JPanel formPanel;

    private JButton btnOk;
    private JButton btnCancel;

    private JComboBox cmbBooleanOperator;
    private JComboBox cmbMatchType;
    private JComboBox cmbMatchRelationship;
    private JTextField txtMatchCondition;

    private boolean enabled = true;

    private final JDialog dialog;

    private boolean success = false;
    private AbstractAction onOkActionListener;
    private AbstractAction onCancelActionListener;

    public AutoDropRequestAddDialog(JFrame parent, String title) {
        this.dialog = initDialog(parent, title);
        initComboBoxes();
        initEventListener();
        initKeyboardShortcuts();
    }

    private void initComboBoxes() {
        for (AutoDropRequestRule.EBooleanOperator value : AutoDropRequestRule.EBooleanOperator.values()) {
            cmbBooleanOperator.addItem(value.getName());
        }
        for (AutoDropRequestRule.EMatchType value : AutoDropRequestRule.EMatchType.values()) {
            cmbMatchType.addItem(value.getName());
        }
        for (AutoDropRequestRule.EMatchRelationship value : AutoDropRequestRule.EMatchRelationship.values()) {
            cmbMatchRelationship.addItem(value.getName());
        }
    }

    public AutoDropRequestAddDialog(JFrame parent, String title, AutoDropRequestRule autoDropRequestRule) {
        this(parent, title);
        cmbBooleanOperator.setSelectedIndex(autoDropRequestRule.getBooleanOperator().getIndex());
        cmbMatchType.setSelectedIndex(autoDropRequestRule.getMatchType().getIndex());
        cmbMatchRelationship.setSelectedIndex(autoDropRequestRule.getMatchRelationship().getIndex());
        txtMatchCondition.setText(autoDropRequestRule.getMatchCondition().toString());
        enabled = autoDropRequestRule.isEnabled();
    }

    private void initKeyboardShortcuts() {
        bindKeyStrokeToAction("ESCAPE", onCancelActionListener);
        bindKeyStrokeToAction("ENTER", onOkActionListener);
    }

    private void bindKeyStrokeToAction(String keyStroke, Action action) {
        KeyStroke stroke = KeyStroke.getKeyStroke(keyStroke);
        InputMap inputMap = formPanel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW);
        inputMap.put(stroke, keyStroke);
        formPanel.getActionMap().put(keyStroke, action);
    }

    private void initEventListener() {
        onOkActionListener = new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (getMatchCondition().isEmpty()) {
                    DialogUtil.showErrorDialog(
                            dialog,
                            "Match condition should not be empty!",
                            "Match condition is empty!"
                    );
                    return;
                }
                success = true;
                dialog.dispose();
            }
        };
        btnOk.addActionListener(onOkActionListener);
        onCancelActionListener = new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                success = false;
                dialog.dispose();
            }
        };
        btnCancel.addActionListener(onCancelActionListener);
    }

    private JDialog initDialog(JFrame parent, String title) {
        JDialog dialog = new JDialog(parent, title, true);
        dialog.getContentPane().add(this.getRootPanel());
        dialog.setSize(450, 250);
        int x = DialogUtil.getX(parent, dialog);
        int y = DialogUtil.getY(parent, dialog);
        dialog.setLocation(x, y);
        dialog.pack();
        return dialog;
    }

    public boolean run() {
        this.dialog.setVisible(true);
        return this.success;
    }

    private JPanel getRootPanel() {
        return formPanel;
    }

    private AutoDropRequestRule.EBooleanOperator getBooleanOperator() {
        return AutoDropRequestRule.EBooleanOperator.byIndex(cmbBooleanOperator.getSelectedIndex()).get();
    }

    private AutoDropRequestRule.EMatchType getMatchType() {
        return AutoDropRequestRule.EMatchType.byIndex(cmbMatchType.getSelectedIndex()).get();
    }

    private AutoDropRequestRule.EMatchRelationship getMatchRelationship() {
        return AutoDropRequestRule.EMatchRelationship.byIndex(cmbMatchRelationship.getSelectedIndex()).get();
    }

    private String getMatchCondition() {
        return txtMatchCondition.getText();
    }

    private boolean isEnabled() {
        return enabled;
    }

    public AutoDropRequestRule getAutoDropRequestRule() {
        return new AutoDropRequestRule(getBooleanOperator(), getMatchType(), getMatchRelationship(), getMatchCondition(), isEnabled());
    }

    {
// GUI initializer generated by IntelliJ IDEA GUI Designer
// >>> IMPORTANT!! <<<
// DO NOT EDIT OR ADD ANY CODE HERE!
        $$$setupUI$$$();
    }

    /**
     * Method generated by IntelliJ IDEA GUI Designer
     * >>> IMPORTANT!! <<<
     * DO NOT edit this method OR call it in your code!
     *
     * @noinspection ALL
     */
    private void $$$setupUI$$$() {
        formPanel = new JPanel();
        formPanel.setLayout(new GridLayoutManager(3, 1, new Insets(10, 10, 10, 10), -1, -1));
        final JLabel label1 = new JLabel();
        label1.setText("Specify the details for the drop request rule.");
        formPanel.add(label1, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel1 = new JPanel();
        panel1.setLayout(new GridBagLayout());
        formPanel.add(panel1, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JLabel label2 = new JLabel();
        label2.setText("Match Condition:");
        label2.setDisplayedMnemonic('C');
        label2.setDisplayedMnemonicIndex(6);
        GridBagConstraints gbc;
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(2, 2, 2, 10);
        panel1.add(label2, gbc);
        final JLabel label3 = new JLabel();
        label3.setText("Match Type:");
        label3.setDisplayedMnemonic('T');
        label3.setDisplayedMnemonicIndex(6);
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(2, 2, 2, 10);
        panel1.add(label3, gbc);
        final JLabel label4 = new JLabel();
        label4.setText("Match Relationship:");
        label4.setDisplayedMnemonic('R');
        label4.setDisplayedMnemonicIndex(6);
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(2, 2, 2, 10);
        panel1.add(label4, gbc);
        final JLabel label5 = new JLabel();
        label5.setText("Boolean Operator:");
        label5.setDisplayedMnemonic('O');
        label5.setDisplayedMnemonicIndex(8);
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(2, 2, 2, 10);
        panel1.add(label5, gbc);
        txtMatchCondition = new JTextField();
        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 3;
        gbc.weightx = 1.0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(2, 2, 2, 2);
        panel1.add(txtMatchCondition, gbc);
        cmbMatchRelationship = new JComboBox();
        final DefaultComboBoxModel defaultComboBoxModel1 = new DefaultComboBoxModel();
        cmbMatchRelationship.setModel(defaultComboBoxModel1);
        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 2;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        panel1.add(cmbMatchRelationship, gbc);
        cmbMatchType = new JComboBox();
        final DefaultComboBoxModel defaultComboBoxModel2 = new DefaultComboBoxModel();
        cmbMatchType.setModel(defaultComboBoxModel2);
        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 1;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        panel1.add(cmbMatchType, gbc);
        cmbBooleanOperator = new JComboBox();
        final DefaultComboBoxModel defaultComboBoxModel3 = new DefaultComboBoxModel();
        cmbBooleanOperator.setModel(defaultComboBoxModel3);
        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        panel1.add(cmbBooleanOperator, gbc);
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new GridLayoutManager(1, 3, new Insets(0, 0, 0, 0), -1, -1));
        formPanel.add(panel2, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        btnCancel = new JButton();
        btnCancel.setText("Cancel");
        btnCancel.setMnemonic('C');
        btnCancel.setDisplayedMnemonicIndex(0);
        panel2.add(btnCancel, new GridConstraints(0, 2, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        btnOk = new JButton();
        btnOk.setText("Ok");
        btnOk.setMnemonic('O');
        btnOk.setDisplayedMnemonicIndex(0);
        panel2.add(btnOk, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer1 = new Spacer();
        panel2.add(spacer1, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return formPanel;
    }

}
