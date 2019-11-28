package net.bytebutcher.burpautodropextension.models.types;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import net.bytebutcher.burpautodropextension.models.InterceptedProxyMessageWrapper;

import java.util.regex.Pattern;

public abstract class AbstractMatchType {

    private final IBurpExtenderCallbacks callbacks;

    public AbstractMatchType(final BurpExtender burpExtender) {
        callbacks = burpExtender.getCallbacks();
    }

    public abstract boolean match(Pattern matchCondition, InterceptedProxyMessageWrapper interceptedProxyMessageWrapper);

    protected void printError(String error) {
        this.callbacks.printError(error);
    }

}
