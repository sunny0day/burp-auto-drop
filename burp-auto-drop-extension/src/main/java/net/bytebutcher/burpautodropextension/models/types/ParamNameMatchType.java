package net.bytebutcher.burpautodropextension.models.types;

import burp.BurpExtender;
import burp.IParameter;
import net.bytebutcher.burpautodropextension.models.InterceptedProxyMessageWrapper;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ParamNameMatchType extends AbstractMatchType {

    public ParamNameMatchType(BurpExtender burpExtender) {
        super(burpExtender);
    }

    @Override
    public boolean match(Pattern matchCondition, InterceptedProxyMessageWrapper interceptedProxyMessageWrapper) {
        for (IParameter parameter : interceptedProxyMessageWrapper.getRequestInfo().getParameters()) {
            Matcher regexMatcher = matchCondition.matcher(parameter.getName());
            if (regexMatcher.find()) {
                return true;
            }
        }
        return false;
    }

}
