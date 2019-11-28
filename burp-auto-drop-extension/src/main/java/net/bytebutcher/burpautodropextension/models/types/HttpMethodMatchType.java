package net.bytebutcher.burpautodropextension.models.types;

import burp.BurpExtender;
import net.bytebutcher.burpautodropextension.models.InterceptedProxyMessageWrapper;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class HttpMethodMatchType extends AbstractMatchType {

    public HttpMethodMatchType(BurpExtender burpExtender) {
        super(burpExtender);
    }

    @Override
    public boolean match(Pattern matchCondition, InterceptedProxyMessageWrapper interceptedProxyMessageWrapper) {
        Matcher regexMatcher = matchCondition.matcher(interceptedProxyMessageWrapper.getRequestInfo().getMethod());
        return regexMatcher.find();
    }

}
