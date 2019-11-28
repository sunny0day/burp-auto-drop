package net.bytebutcher.burpautodropextension.models.types;

import burp.BurpExtender;
import net.bytebutcher.burpautodropextension.models.InterceptedProxyMessageWrapper;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class FileExtensionMatchType extends AbstractMatchType {

    public FileExtensionMatchType(BurpExtender burpExtender) {
        super(burpExtender);
    }

    @Override
    public boolean match(Pattern matchCondition, InterceptedProxyMessageWrapper interceptedProxyMessageWrapper) {
        String extension = "";
        int i = interceptedProxyMessageWrapper.getRequestInfo().getUrl().getFile().lastIndexOf('.');
        if (i > 0) {
            extension = interceptedProxyMessageWrapper.getRequestInfo().getUrl().getFile().substring(i+1);
        }
        Matcher regexMatcher = matchCondition.matcher(extension);
        return regexMatcher.find();
    }

}
