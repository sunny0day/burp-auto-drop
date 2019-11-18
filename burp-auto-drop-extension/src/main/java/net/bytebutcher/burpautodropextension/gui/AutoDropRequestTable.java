package net.bytebutcher.burpautodropextension.gui;

import burp.BurpExtender;
import net.bytebutcher.burpautodropextension.models.AutoDropRequestRule;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.util.ArrayList;
import java.util.List;

public class AutoDropRequestTable extends JTable {

    private final DefaultTableModel defaultModel;
    private BurpExtender burpExtender;

    private enum Column {
        ID(0),
        ENABLED(1),
        BOOLEAN_OPERATOR(2),
        MATCH_TYPE(3),
        MATCH_RELATIONSHIP(4),
        MATCH_CONDITION(5);

        private final int index;

        Column(int id) {
            this.index = id;
        }

        public int getIndex() {
            return index;
        }
    }

    public AutoDropRequestTable(BurpExtender burpExtender) {
        this.burpExtender = burpExtender;

        this.defaultModel = new DefaultTableModel() {
            @Override
            public boolean isCellEditable(int row, int column) {
                return (column == 1);
            }
        };
        this.defaultModel.addColumn("Id");
        this.defaultModel.addColumn("Enabled");
        this.defaultModel.addColumn("Operator");
        this.defaultModel.addColumn("Match type");
        this.defaultModel.addColumn("Relationship");
        this.defaultModel.addColumn("Condition");
        setModel(this.defaultModel);

        // Hide Id-Column.
        this.removeColumn(this.getColumnModel().getColumn(Column.ID.getIndex()));

        //this.getColumnModel().getColumn(1).setPreferredWidth(25);
    }

    @Override
    public Class getColumnClass(int column) {
        switch (column) {
            case 0: // ENABLED
                return Boolean.class;
            case 1: // BOOLEAN_OPERATOR
                return String.class;
            case 2: // MATCH_TYPE
                return String.class;
            case 3: // MATCH_RELATIONSHIP
                return String.class;
            case 4: // MATCH_CONDITION
                return String.class;
            default:
                throw new RuntimeException("Logic Error");
        }
    }

    public AutoDropRequestRule getSelectedAutoDropRequestRule() {
        int[] selectedRows = this.getSelectedRows();
        if (selectedRows.length > 0) {
            int selectedRow = selectedRows[0];
            return getAutoDropRequestRuleByRowIndex(selectedRow);
        }
        throw new IllegalStateException("No row selected!");
    }

    public DefaultTableModel getDefaultModel() {
        return defaultModel;
    }

    private AutoDropRequestRule.EBooleanOperator getBooleanOperatorByRowIndex(int rowIndex) {
        return AutoDropRequestRule.EBooleanOperator.byName(this.getModel().getValueAt(rowIndex, Column.BOOLEAN_OPERATOR.getIndex()).toString()).get();
    }

    private AutoDropRequestRule.EMatchType getMatchTypeByRowIndex(int rowIndex) {
        return AutoDropRequestRule.EMatchType.byName(this.getModel().getValueAt(rowIndex, Column.MATCH_TYPE.getIndex()).toString()).get();
    }

    private AutoDropRequestRule.EMatchRelationship getMatchRelationshipByRowIndex(int rowIndex) {
        return AutoDropRequestRule.EMatchRelationship.byName(this.getModel().getValueAt(rowIndex, Column.MATCH_RELATIONSHIP.getIndex()).toString()).get();
    }

    private String getMatchConditionByRowIndex(int rowIndex) {
        return this.getModel().getValueAt(rowIndex, Column.MATCH_CONDITION.getIndex()).toString();
    }

    private boolean getEnabledByRowIndex(int rowIndex) {
        return Boolean.parseBoolean(this.getModel().getValueAt(rowIndex, Column.ENABLED.getIndex()).toString());
    }

    public List<AutoDropRequestRule> getAutoDropRequestRules() {
        List<AutoDropRequestRule> autoDropRequestRules = new ArrayList<>();
        for (int i = 0; i < this.getDefaultModel().getRowCount(); i++) {
            autoDropRequestRules.add(getAutoDropRequestRuleByRowIndex(i));
        }
        return autoDropRequestRules;
    }

    private AutoDropRequestRule getAutoDropRequestRuleByRowIndex(int rowIndex) {
        String id = this.getModel().getValueAt(rowIndex, Column.ID.getIndex()).toString();
        AutoDropRequestRule.EBooleanOperator booleanOperator = getBooleanOperatorByRowIndex(rowIndex);
        AutoDropRequestRule.EMatchType matchType = getMatchTypeByRowIndex(rowIndex);
        AutoDropRequestRule.EMatchRelationship matchRelationship = getMatchRelationshipByRowIndex(rowIndex);
        String matchCondition = getMatchConditionByRowIndex(rowIndex);
        boolean isEnabled = isEnabled();
        return new AutoDropRequestRule(id, booleanOperator, matchType, matchRelationship, matchCondition, isEnabled);
    }

    public AutoDropRequestRule getAutoDropRequestRuleById(String commandId) {
        if (commandId == null) {
            burpExtender.getCallbacks().printError("id should not be null!");
            throw new IllegalArgumentException("id should not be null!");
        }
        for (int i = 0; i < this.getDefaultModel().getRowCount(); i++) {
            AutoDropRequestRule autoDropRequestRule = getAutoDropRequestRuleByRowIndex(i);
            if (commandId.equals(autoDropRequestRule.getId())) {
                return autoDropRequestRule;
            }
        }
        burpExtender.getCallbacks().printError("No rule found with the specified id!");
        throw new IllegalStateException("No rule found with the specified id!");
    }

    public void addDropRequestRules(List<AutoDropRequestRule> autoDropRequestRuleList) {
        for (AutoDropRequestRule autoDropRequestRule : autoDropRequestRuleList) {
            addDropRequestRule(autoDropRequestRule);
        }
    }

    public void addDropRequestRule(AutoDropRequestRule autoDropRequestRule) {
        try {
            getDefaultModel().addRow(new Object[]{
                    autoDropRequestRule.getId(),
                    autoDropRequestRule.isEnabled(),
                    autoDropRequestRule.getBooleanOperator().getName(),
                    autoDropRequestRule.getMatchType().getName(),
                    autoDropRequestRule.getMatchRelationship().getName(),
                    autoDropRequestRule.getMatchCondition().toString(),
            });
        } catch (RuntimeException e) {
            burpExtender.getCallbacks().printError("Error adding rule!");
            burpExtender.getCallbacks().printError(autoDropRequestRule.toString());
        }
    }

    public void editSelectedAutoDropRequestRule(AutoDropRequestRule autoDropRequestRule) {
        int selectedRowIndex = this.getSelectedRow();
        if (selectedRowIndex >= 0) {
            editRow(selectedRowIndex, autoDropRequestRule);
        }
    }

    private void editRow(int rowIndex, AutoDropRequestRule autoDropRequestRule) {
        try {
            DefaultTableModel model = getDefaultModel();
            model.setValueAt(autoDropRequestRule.getId(), rowIndex, Column.ID.getIndex());
            model.setValueAt(autoDropRequestRule.isEnabled(), rowIndex, Column.ENABLED.getIndex());
            model.setValueAt(autoDropRequestRule.getBooleanOperator().getName(), rowIndex, Column.BOOLEAN_OPERATOR.getIndex());
            model.setValueAt(autoDropRequestRule.getMatchType().getName(), rowIndex, Column.MATCH_TYPE.getIndex());
            model.setValueAt(autoDropRequestRule.getMatchRelationship().getName(), rowIndex, Column.MATCH_RELATIONSHIP.getIndex());
            model.setValueAt(autoDropRequestRule.getMatchCondition().toString(), rowIndex, Column.MATCH_CONDITION.getIndex());
        } catch (Exception e) {
            burpExtender.getCallbacks().printError("Error editing rule!");
            burpExtender.getCallbacks().printError(autoDropRequestRule.toString());
        }
    }

    public void editObject(AutoDropRequestRule autoDropRequestRule) {
        for (int i = 0; i < this.getDefaultModel().getRowCount(); i++) {
            AutoDropRequestRule currentAutoDropRequestRule = getAutoDropRequestRuleByRowIndex(i);
            if (currentAutoDropRequestRule.getId().equals(autoDropRequestRule.getId())) {
                editRow(i, autoDropRequestRule);
                return;
            }
        }
    }

    public void removeSelectedRow() {
        int[] rows = this.getSelectedRows();
        if (rows.length > 0) {
            getDefaultModel().removeRow(rows[0]);
        }
    }

    public void clearTable() {
        for (int row = this.getRowCount() - 1; row >= 0; row--) {
            getDefaultModel().removeRow(row);
        }
    }

    public void moveSelectedRowUp() {
        moveRowBy(-1);
    }

    public void moveSelectedRowDown() {
        moveRowBy(1);
    }

    private void moveRowBy(int index) {
        DefaultTableModel model = (DefaultTableModel) this.getModel();
        int[] rows = this.getSelectedRows();
        int destination = rows[0] + index;
        int rowCount = model.getRowCount();

        if (destination < 0 || destination >= rowCount) {
            return;
        }

        model.moveRow(rows[0], rows[rows.length - 1], destination);
        this.setRowSelectionInterval(rows[0] + index, rows[rows.length - 1] + index);
    }

    @Override
    public void removeAll() {
        DefaultTableModel model = (DefaultTableModel) this.getModel();
        for (int i = 0; i < model.getRowCount(); i++) {
            model.removeRow(i);
        }
    }

}
