package net.bytebutcher.burpautodropextension.models.types;

import burp.BurpExtender;
import net.bytebutcher.burpautodropextension.models.InterceptedProxyMessageWrapper;

import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BodyMatchType extends AbstractMatchType {

    public BodyMatchType(BurpExtender burpExtender) {
        super(burpExtender);
    }

    @Override
    public boolean match(Pattern matchCondition, InterceptedProxyMessageWrapper interceptedProxyMessageWrapper) {
        String requestBody = interceptedProxyMessageWrapper.getRequestInfo().getBody();
        Matcher regexMatcher = matchCondition.matcher(requestBody);
        return regexMatcher.find();
    }

}
