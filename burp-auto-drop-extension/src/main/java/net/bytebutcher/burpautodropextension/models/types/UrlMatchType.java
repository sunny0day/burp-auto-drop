package net.bytebutcher.burpautodropextension.models.types;

import burp.BurpExtender;
import net.bytebutcher.burpautodropextension.models.InterceptedProxyMessageWrapper;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class UrlMatchType extends AbstractMatchType {

    public UrlMatchType(BurpExtender burpExtender) {
        super(burpExtender);
    }

    @Override
    public boolean match(Pattern matchCondition, InterceptedProxyMessageWrapper interceptedProxyMessageWrapper) {
        Matcher regexMatcher = matchCondition.matcher(interceptedProxyMessageWrapper.getRequestInfo().getUrl().toString());
        return regexMatcher.find();
    }

}
