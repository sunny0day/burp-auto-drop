package net.bytebutcher.burpautodropextension.gui.listener;

import burp.BurpExtender;
import com.google.common.collect.Lists;
import com.google.gson.Gson;
import net.bytebutcher.burpautodropextension.gui.AutoDropRequestTable;
import net.bytebutcher.burpautodropextension.models.AutoDropRequestRule;

import javax.swing.*;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.DefaultTableModel;
import java.awt.event.ActionEvent;
import java.util.List;

public class AutoDropRequestTableListener implements TableModelListener {

    private AutoDropRequestTable autoDropRequestTable;
    private final JTable table;
    private final DefaultTableModel model;
    private BurpExtender burpExtender;
    private List<TableListener<AutoDropRequestRule>> tableListeners = Lists.newArrayList();

    public AutoDropRequestTableListener(JTable table, AutoDropRequestTable autoDropRequestTable, BurpExtender burpExtender) {
        this.autoDropRequestTable = autoDropRequestTable;
        this.table = table;
        this.model = autoDropRequestTable.getDefaultModel();
        this.burpExtender = burpExtender;
    }

    @Override
    public void tableChanged(TableModelEvent e) {
        List<AutoDropRequestRule> autoDropRequestRules = autoDropRequestTable.getAutoDropRequestRules();
        for (TableListener<AutoDropRequestRule> tableListener : tableListeners) {
            tableListener.tableChanged(autoDropRequestRules);
        }
        this.burpExtender.getConfig().saveAutoDropRequestTableData(new Gson().toJson(autoDropRequestTable.getAutoDropRequestRules()));
    }

    public void onAddButtonClick(ActionEvent e, AutoDropRequestRule commandObject) {
        autoDropRequestTable.addDropRequestRule(commandObject);
    }

    public void onEditButtonClick(ActionEvent e, AutoDropRequestRule commandObject) {
        autoDropRequestTable.editSelectedAutoDropRequestRule(commandObject);
    }

    public void onRemoveButtonClick(ActionEvent e) {
        autoDropRequestTable.removeSelectedRow();
    }

    public void onUpButtonClick(ActionEvent e) {
        autoDropRequestTable.moveSelectedRowUp();
    }

    public void onDownButtonClick(ActionEvent e) {
        autoDropRequestTable.moveSelectedRowDown();
    }

    public void registerTableLister(TableListener<AutoDropRequestRule> tableListener) {
        tableListeners.add(tableListener);
    }
}
