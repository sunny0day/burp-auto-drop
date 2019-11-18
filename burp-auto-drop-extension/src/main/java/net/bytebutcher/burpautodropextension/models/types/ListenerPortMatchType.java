package net.bytebutcher.burpautodropextension.models.types;

import burp.BurpExtender;
import net.bytebutcher.burpautodropextension.models.InterceptedProxyMessageWrapper;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ListenerPortMatchType extends AbstractMatchType {

    public ListenerPortMatchType(BurpExtender burpExtender) {
        super(burpExtender);
    }

    @Override
    public boolean match(Pattern matchCondition, InterceptedProxyMessageWrapper interceptedProxyMessageWrapper) {
        Matcher regexMatcher = matchCondition.matcher(String.valueOf(interceptedProxyMessageWrapper.getInterceptedProxyMessage().getMessageInfo().getHttpService().getPort()));
        return regexMatcher.find();
    }

}
