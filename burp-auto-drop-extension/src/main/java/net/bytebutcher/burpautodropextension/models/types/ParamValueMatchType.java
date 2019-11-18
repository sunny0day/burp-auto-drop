package net.bytebutcher.burpautodropextension.models.types;

import burp.BurpExtender;
import burp.IParameter;
import net.bytebutcher.burpautodropextension.models.InterceptedProxyMessageWrapper;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ParamValueMatchType extends AbstractMatchType {

    public ParamValueMatchType(BurpExtender burpExtender) {
        super(burpExtender);
    }

    @Override
    public boolean match(Pattern matchCondition, InterceptedProxyMessageWrapper interceptedProxyMessageWrapper) {
        for (IParameter parameter : interceptedProxyMessageWrapper.getRequestInfo().getParameters()) {
            Matcher regexMatcher = matchCondition.matcher(parameter.getValue());
            if (regexMatcher.find()) {
                return true;
            }
        }
        return false;
    }

}
