package net.bytebutcher.burpautodropextension.models.types;

import burp.BurpExtender;
import net.bytebutcher.burpautodropextension.models.InterceptedProxyMessageWrapper;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RequestMatchType extends AbstractMatchType {

    public RequestMatchType(BurpExtender burpExtender) {
        super(burpExtender);
    }

    @Override
    public boolean match(Pattern matchCondition, InterceptedProxyMessageWrapper interceptedProxyMessageWrapper) {
        String input = new String(interceptedProxyMessageWrapper.getInterceptedProxyMessage().getMessageInfo().getRequest());
        Matcher regexMatcher = matchCondition.matcher(input);
        return regexMatcher.find();
    }

}
