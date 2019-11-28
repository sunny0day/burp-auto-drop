package net.bytebutcher.burpautodropextension.models.types;

import burp.BurpExtender;
import net.bytebutcher.burpautodropextension.models.InterceptedProxyMessageWrapper;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DomainNameMatchType extends AbstractMatchType {

    public DomainNameMatchType(BurpExtender burpExtender) {
        super(burpExtender);
    }

    @Override
    public boolean match(Pattern matchCondition, InterceptedProxyMessageWrapper interceptedProxyMessageWrapper) {
        Matcher regexMatcher = matchCondition.matcher(interceptedProxyMessageWrapper.getInterceptedProxyMessage().getMessageInfo().getHttpService().getHost());
        return regexMatcher.find();
    }

}
