package net.bytebutcher.burpautodropextension.utils;

import burp.*;
import com.google.common.collect.Lists;
import net.bytebutcher.burpautodropextension.models.AutoDropRequestRule;
import net.bytebutcher.burpautodropextension.models.InterceptedProxyMessageWrapper;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Answers;

import java.net.URL;
import java.util.List;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AutoDropRequestRuleMatcherTest {

    private AutoDropRequestRuleMatcher autoDropRequestRuleMatcher;
    private AutoDropRequestRule disabledRule;
    private AutoDropRequestRule andMatchRule;
    private AutoDropRequestRule andNoMatchRule;
    private AutoDropRequestRule orMatchRule;
    private AutoDropRequestRule orNoMatchRule;
    private InterceptedProxyMessageWrapper interceptedProxyMessageWrapper;


    @Before
    public void setUp() throws Exception {
        BurpExtender burpExtender = mock(BurpExtender.class);

        //
        // WARNING: every time a mock returns a mock a fairy dies.
        //
        // CASUALTIES SO FAR:
        //
        interceptedProxyMessageWrapper = mock(InterceptedProxyMessageWrapper.class, Answers.RETURNS_DEEP_STUBS.get());
        when(interceptedProxyMessageWrapper.getRequestInfo().getUrl()).thenReturn(new URL("http://localhost/"));

        autoDropRequestRuleMatcher = new AutoDropRequestRuleMatcher(burpExtender);

        disabledRule = new AutoDropRequestRule(null, null, null, null, false);
        andMatchRule = new AutoDropRequestRule(
                AutoDropRequestRule.EBooleanOperator.AND,
                AutoDropRequestRule.EMatchType.URL,
                AutoDropRequestRule.EMatchRelationship.MATCHES,
                ".*",
                true
        );
        andNoMatchRule = new AutoDropRequestRule(
                AutoDropRequestRule.EBooleanOperator.AND,
                AutoDropRequestRule.EMatchType.URL,
                AutoDropRequestRule.EMatchRelationship.DOES_NOT_MATCH,
                ".*",
                true
        );
        orMatchRule = new AutoDropRequestRule(
                AutoDropRequestRule.EBooleanOperator.OR,
                AutoDropRequestRule.EMatchType.URL,
                AutoDropRequestRule.EMatchRelationship.MATCHES,
                ".*",
                true
        );
        orNoMatchRule = new AutoDropRequestRule(
                AutoDropRequestRule.EBooleanOperator.OR,
                AutoDropRequestRule.EMatchType.URL,
                AutoDropRequestRule.EMatchRelationship.DOES_NOT_MATCH,
                ".*",
                true
        );
    }

    // -----------------------------------------------------------------------------------------------------------------

    @Test
    public void testNoRulesReturnsFalse() {
        List<AutoDropRequestRule> rules = Lists.newArrayList();
        assertFalse(autoDropRequestRuleMatcher.match(rules, interceptedProxyMessageWrapper));
    }

    @Test
    public void testNoEnabledRulesReturnsFalse() {
        List<AutoDropRequestRule> rules = Lists.newArrayList(disabledRule, disabledRule);
        assertFalse(autoDropRequestRuleMatcher.match(rules, mock(IInterceptedProxyMessage.class)));
    }

    @Test
    public void testNoMatchingRulesReturnsFalse() {
        List<AutoDropRequestRule> rules = Lists.newArrayList(andNoMatchRule, orNoMatchRule);
        assertFalse(autoDropRequestRuleMatcher.match(rules, interceptedProxyMessageWrapper));
    }

    // -----------------------------------------------------------------------------------------------------------------

    @Test
    public void testOrMatchRuleReturnsTrue() {
        List<AutoDropRequestRule> rules = Lists.newArrayList(orMatchRule);
        assertTrue(autoDropRequestRuleMatcher.match(rules, interceptedProxyMessageWrapper));
    }

    @Test
    public void testAndMatchRuleReturnsTrue() {
        List<AutoDropRequestRule> rules = Lists.newArrayList(andMatchRule);
        assertTrue(autoDropRequestRuleMatcher.match(rules, interceptedProxyMessageWrapper));
    }

    @Test
    public void testAndNoMatchRuleReturnsFalse() {
        List<AutoDropRequestRule> rules = Lists.newArrayList(andNoMatchRule);
        assertFalse(autoDropRequestRuleMatcher.match(rules, interceptedProxyMessageWrapper));
    }

    @Test
    public void testOrNoMatchRuleReturnsFalse() {
        List<AutoDropRequestRule> rules = Lists.newArrayList(orNoMatchRule);
        assertFalse(autoDropRequestRuleMatcher.match(rules, interceptedProxyMessageWrapper));
    }

    // -----------------------------------------------------------------------------------------------------------------

    @Test
    public void testNoMatchingRuleOrMatchingRuleReturnsTrue() {
        List<AutoDropRequestRule> rules = Lists.newArrayList(orNoMatchRule, orMatchRule);
        assertTrue(autoDropRequestRuleMatcher.match(rules, interceptedProxyMessageWrapper));
    }

    @Test
    public void testMatchingRuleOrNoMatchingRuleReturnsTrue() {
        List<AutoDropRequestRule> rules = Lists.newArrayList(orMatchRule, orNoMatchRule);
        assertTrue(autoDropRequestRuleMatcher.match(rules, interceptedProxyMessageWrapper));
    }

    @Test
    public void testNoMatchingRuleAndNoMatchingRuleReturnsFalse() {
        List<AutoDropRequestRule> rules = Lists.newArrayList(orNoMatchRule, andNoMatchRule);
        assertFalse(autoDropRequestRuleMatcher.match(rules, interceptedProxyMessageWrapper));
    }

    @Test
    public void testMatchingRuleAndMatchingRuleReturnsTrue() {
        List<AutoDropRequestRule> rules = Lists.newArrayList(orMatchRule, andMatchRule);
        assertTrue(autoDropRequestRuleMatcher.match(rules, interceptedProxyMessageWrapper));
    }

    @Test
    public void testNoMatchingRuleAndMatchingRuleReturnsFalse() {
        List<AutoDropRequestRule> rules = Lists.newArrayList(orNoMatchRule, andMatchRule);
        assertFalse(autoDropRequestRuleMatcher.match(rules, interceptedProxyMessageWrapper));
    }

    @Test
    public void testMatchingRuleAndNoMatchingRuleReturnsFalse() {
        List<AutoDropRequestRule> rules = Lists.newArrayList(orMatchRule, andNoMatchRule);
        assertFalse(autoDropRequestRuleMatcher.match(rules, interceptedProxyMessageWrapper));
    }

    // -----------------------------------------------------------------------------------------------------------------

    @Test
    public void testNoMatchingRuleOrNoMatchingRuleAndMatchingRuleReturnsFalse() {
        List<AutoDropRequestRule> rules = Lists.newArrayList(orNoMatchRule, orNoMatchRule, andMatchRule);
        assertFalse(autoDropRequestRuleMatcher.match(rules, interceptedProxyMessageWrapper));
    }
    
    @Test
    public void testNoMatchingRuleOrMatchingRuleAndMatchingRuleReturnsTrue() {
        List<AutoDropRequestRule> rules = Lists.newArrayList(orNoMatchRule, orMatchRule, andMatchRule);
        assertTrue(autoDropRequestRuleMatcher.match(rules, interceptedProxyMessageWrapper));
    }

}