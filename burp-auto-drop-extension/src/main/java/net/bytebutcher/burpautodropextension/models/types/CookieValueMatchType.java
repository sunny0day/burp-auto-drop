package net.bytebutcher.burpautodropextension.models.types;

import burp.BurpExtender;
import burp.ICookie;
import net.bytebutcher.burpautodropextension.models.InterceptedProxyMessageWrapper;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CookieValueMatchType extends AbstractMatchType {

    public CookieValueMatchType(BurpExtender burpExtender) {
        super(burpExtender);
    }

    @Override
    public boolean match(Pattern matchCondition, InterceptedProxyMessageWrapper interceptedProxyMessageWrapper) {
        for (ICookie cookie : interceptedProxyMessageWrapper.getRequestInfo().getCookies()) {
            Matcher regexMatcher = matchCondition.matcher(cookie.getValue());
            if (regexMatcher.find()) {
                return true;
            }
        }
        return false;
    }

}
