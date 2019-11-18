package net.bytebutcher.burpautodropextension.models.types;

import burp.BurpExtender;
import net.bytebutcher.burpautodropextension.models.InterceptedProxyMessageWrapper;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class IpAddressMatchType extends AbstractMatchType {

    public IpAddressMatchType(BurpExtender burpExtender) {
        super(burpExtender);
    }

    @Override
    public boolean match(Pattern matchCondition, InterceptedProxyMessageWrapper interceptedProxyMessageWrapper) {
        try {
            byte[] address = interceptedProxyMessageWrapper.getInterceptedProxyMessage().getClientIpAddress().getAddress();
            Matcher regexMatcher = matchCondition.matcher(String.valueOf(InetAddress.getByAddress(address).getHostAddress()));
            return regexMatcher.find();
        } catch (UnknownHostException e) {
            printError("Error while processing IpAddressMatchType: " + e);
            return false;
        }
    }

}
