package net.bytebutcher.burpautodropextension.gui;

import burp.*;
import com.google.common.collect.Lists;
import net.bytebutcher.burpautodropextension.gui.listener.AutoDropRequestTableListener;
import net.bytebutcher.burpautodropextension.models.AutoDropRequestRule;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.util.*;

public class AutoDropRequestContextMenu implements IContextMenuFactory {

    private BurpExtender burpExtender;
    private AutoDropRequestTableListener tableListener;

    public AutoDropRequestContextMenu(BurpExtender burpExtender, AutoDropRequestTableListener tableListener) {
        this.burpExtender = burpExtender;
        this.tableListener = tableListener;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        return Lists.newArrayList(new JMenuItem(new AbstractAction("Auto-Drop request...") {
            @Override
            public void actionPerformed(ActionEvent e) {
                AutoDropRequestAddDialog addDialog = new AutoDropRequestAddDialog(
                        burpExtender.getParent(),
                        "Add \"Auto-Drop Request\" rule",
                        guessAutoDropRequestRule(invocation)
                );
                if (addDialog.run()) {
                    tableListener.onAddButtonClick(e, addDialog.getAutoDropRequestRule());
                }
            }
        }));
    }

    private IRequestInfo getRequestInfo(IHttpRequestResponse req) {
        return burpExtender.getCallbacks().getHelpers().analyzeRequest(req.getHttpService(), req.getRequest());
    }

    private AutoDropRequestRule guessAutoDropRequestRule(IContextMenuInvocation invocation) {
        AutoDropRequestRule.EBooleanOperator booleanOperator = AutoDropRequestRule.EBooleanOperator.OR;
        AutoDropRequestRule.EMatchType matchType = AutoDropRequestRule.EMatchType.URL;
        AutoDropRequestRule.EMatchRelationship matchRelationship = AutoDropRequestRule.EMatchRelationship.MATCHES;
        String matchCondition = "";

        int[] selectionBounds = invocation.getSelectionBounds();
        IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
        byte iContext = invocation.getInvocationContext();
        if (selectionBounds != null) {
            IHttpRequestResponse iHttpRequestResponse = invocation.getSelectedMessages()[0];
            matchType = AutoDropRequestRule.EMatchType.REQUEST;
            if (iContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST
                    || iContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST) {
                matchCondition = new String(iHttpRequestResponse.getRequest()).substring(selectionBounds[0], selectionBounds[1]);
            } else if (iContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE
                    || iContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE) {
                matchCondition = new String(iHttpRequestResponse.getResponse()).substring(selectionBounds[0], selectionBounds[1]);
            }
        } else if (selectedMessages != null) {
            matchCondition = getRequestInfo(selectedMessages[0]).getUrl().toString();
            matchType = AutoDropRequestRule.EMatchType.URL;
        }
        return new AutoDropRequestRule(booleanOperator, matchType, matchRelationship, maskString(matchCondition), true);
    }

    private String maskString(String matchCondition) {
        return Optional.of(matchCondition).orElse("").replaceAll("[\\W]", "\\\\$0");
    }

}
