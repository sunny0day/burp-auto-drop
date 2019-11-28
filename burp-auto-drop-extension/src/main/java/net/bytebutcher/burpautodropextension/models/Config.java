package net.bytebutcher.burpautodropextension.models;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.util.ArrayList;
import java.util.List;

public class Config {

    private final IBurpExtenderCallbacks callbacks;
    private BurpExtender burpExtender;

    public Config(BurpExtender burpExtender) {
        this.burpExtender = burpExtender;
        this.callbacks = burpExtender.getCallbacks();
    }

    public void saveAutoDropRequestTableData(String jsonData) {
        this.callbacks.saveExtensionSetting("AutoDropRequestTableData", jsonData);
    }

    public List<AutoDropRequestRule> getAutoDropRequestTableData() {
        List<AutoDropRequestRule> commandObjectList = new ArrayList<>();
        try {
            String autoDropRequestTableData = this.callbacks.loadExtensionSetting("AutoDropRequestTableData");
            if (autoDropRequestTableData == null || autoDropRequestTableData.isEmpty()) {
                return commandObjectList;
            }
            return new Gson().fromJson(autoDropRequestTableData, new TypeToken<List<AutoDropRequestRule>>() {}.getType());
        } catch (Exception e) {
            return commandObjectList;
        }
    }

    public void enableLogging(boolean enable) {
        this.callbacks.saveExtensionSetting("AutoDropRequestLogging", Boolean.toString(enable));
    }

    public boolean isLoggingEnabled() {
        return Boolean.valueOf(this.callbacks.loadExtensionSetting("AutoDropRequestLogging"));
    }

    public void enableSendToProxyHistory(boolean enable) {
        this.callbacks.saveExtensionSetting("AutoDropRequestProxyHistory", Boolean.toString(enable));
    }

    public boolean isSendToProxyHistoryEnabled() {
        return Boolean.valueOf(this.callbacks.loadExtensionSetting("AutoDropRequestProxyHistory"));
    }
}
