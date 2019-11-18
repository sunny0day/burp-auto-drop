package net.bytebutcher.burpautodropextension.models.types;

import burp.BurpExtender;
import net.bytebutcher.burpautodropextension.models.InterceptedProxyMessageWrapper;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AnyHeaderMatchType extends AbstractMatchType {

    public AnyHeaderMatchType(BurpExtender burpExtender) {
        super(burpExtender);
    }

    @Override
    public boolean match(Pattern matchCondition, InterceptedProxyMessageWrapper interceptedProxyMessageWrapper) {
        for (String header : interceptedProxyMessageWrapper.getRequestInfo().getHeaders()) {
            Matcher regexMatcher = matchCondition.matcher(header);
            if (regexMatcher.find()) {
                return true;
            }
        }
        return false;
    }

}
