package net.bytebutcher.burpautodropextension.utils;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IInterceptedProxyMessage;
import net.bytebutcher.burpautodropextension.models.AutoDropRequestRule;
import net.bytebutcher.burpautodropextension.models.InterceptedProxyMessageWrapper;
import net.bytebutcher.burpautodropextension.models.types.*;

import java.util.List;
import java.util.stream.Collectors;

public class AutoDropRequestRuleMatcher {

    private final IBurpExtenderCallbacks callbacks;
    private BurpExtender burpExtender;

    public AutoDropRequestRuleMatcher(final BurpExtender burpExtender) {
        this.burpExtender = burpExtender;
        this.callbacks = burpExtender.getCallbacks();
    }

    private AbstractMatchType getMatchType(AutoDropRequestRule.EMatchType matchType) {
        switch (matchType) {
            case DOMAIN_NAME:
                return new DomainNameMatchType(burpExtender);
            case IP_ADDRESS:
                return new IpAddressMatchType(burpExtender);
            case PROTOCOL:
                return new ProtocolMatchType(burpExtender);
            case HTTP_METHOD:
                return new HttpMethodMatchType(burpExtender);
            case URL:
                return new UrlMatchType(burpExtender);
            case FILE_EXTENSION:
                return new FileExtensionMatchType(burpExtender);
            case REQUEST:
                return new RequestMatchType(burpExtender);
            case COOKIE_NAME:
                return new CookieNameMatchType(burpExtender);
            case COOKIE_VALUE:
                return new CookieValueMatchType(burpExtender);
            case ANY_HEADER:
                return new AnyHeaderMatchType(burpExtender);
            case BODY:
                return new BodyMatchType(burpExtender);
            case PARAM_NAME:
                return new ParamNameMatchType(burpExtender);
            case PARAM_VALUE:
                return new ParamValueMatchType(burpExtender);
            case LISTENER_PORT:
                return new ListenerPortMatchType(burpExtender);
        }
        throw new RuntimeException("Missing Match Type");
    }

    private boolean hasRules(List<AutoDropRequestRule> ruleList) {
        return ruleList.size() > 0;
    }

    public boolean match(AutoDropRequestRule rule, IInterceptedProxyMessage interceptedProxyMessage) {
        return match(rule, new InterceptedProxyMessageWrapper(this.callbacks, interceptedProxyMessage));
    }

    public boolean match(AutoDropRequestRule rule, InterceptedProxyMessageWrapper interceptedProxyMessageWrapper) {
        AbstractMatchType matchType = getMatchType(rule.getMatchType());
        try {
            boolean doesMatch = matchType.match(rule.getMatchCondition(), interceptedProxyMessageWrapper);
            return ((rule.getMatchRelationship() == AutoDropRequestRule.EMatchRelationship.MATCHES && doesMatch) ||
                    (rule.getMatchRelationship() == AutoDropRequestRule.EMatchRelationship.DOES_NOT_MATCH && !doesMatch));
        } catch (RuntimeException e) {
            this.burpExtender.getCallbacks().printError("Unexpected exception when processing " + matchType.getClass().getName() + "!");
            this.burpExtender.getCallbacks().printError(e.toString());
            return false;
        }
    }


    public boolean match(List<AutoDropRequestRule> rules, IInterceptedProxyMessage interceptedProxyMessage) {
        List<AutoDropRequestRule> enabledRules = rules.stream().filter(AutoDropRequestRule::isEnabled).collect(Collectors.toList());
        if (!hasRules(enabledRules)) {
            return false;
        }
        return match(enabledRules, new InterceptedProxyMessageWrapper(this.callbacks, interceptedProxyMessage));
    }

    boolean match(List<AutoDropRequestRule> enabledRules, InterceptedProxyMessageWrapper interceptedProxyMessageWrapper) {
        boolean lastResult = true;
        AutoDropRequestRule rule;

        for (int i = 0; i < enabledRules.size(); i++) {

            rule = enabledRules.get(i);

            boolean doesMatch = match(rule, interceptedProxyMessageWrapper);
            boolean hasNextRule = (i + 1) < enabledRules.size();

            if (doesMatch) {
                if (rule.getBooleanOperator() == AutoDropRequestRule.EBooleanOperator.AND && !lastResult) {
                    continue;
                }
                if (hasNextRule) {
                    if (enabledRules.get(i + 1).getBooleanOperator() == AutoDropRequestRule.EBooleanOperator.AND) {
                        lastResult = true;
                        continue;
                    }
                    if (enabledRules.get(i + 1).getBooleanOperator() == AutoDropRequestRule.EBooleanOperator.OR) {
                        return true;
                    }
                    throw new RuntimeException("Logic Error: Missing check");
                } else {
                    if (rule.getBooleanOperator() == AutoDropRequestRule.EBooleanOperator.AND) {
                        if (lastResult) {
                            return true;
                        } else {
                            continue;
                        }
                    }
                    if (rule.getBooleanOperator() == AutoDropRequestRule.EBooleanOperator.OR) {
                        return true;
                    }
                    throw new RuntimeException("Logic Error: Missing check");
                }
            } else {
                lastResult = false;
            }
        }
        return false;
    }
}
