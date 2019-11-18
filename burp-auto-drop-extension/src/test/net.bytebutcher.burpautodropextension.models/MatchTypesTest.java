package net.bytebutcher.burpautodropextension.models;

import burp.*;
import com.google.common.collect.Lists;
import net.bytebutcher.burpautodropextension.models.types.*;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Answers;

import java.net.*;
import java.util.Arrays;
import java.util.regex.Pattern;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class MatchTypesTest {

    private BurpExtender burpExtender;
    private InterceptedProxyMessageWrapper interceptedProxyMessageWrapper;

    @Before
    public void setUp() throws Exception {
        burpExtender = mock(BurpExtender.class);
        //
        // WARNING: every time a mock returns a mock a fairy dies.
        //
        // CASUALTIES SO FAR: X X X X X X X X X X X X X
        //
        interceptedProxyMessageWrapper = mock(InterceptedProxyMessageWrapper.class, Answers.RETURNS_DEEP_STUBS.get());
    }

    private Pattern newPattern(String condition) {
        return Pattern.compile(condition);
    }

    // -----------------------------------------------------------------------------------------------------------------

    @Test
    public void testAnyHeaderMatchTypeFail() {
        when(interceptedProxyMessageWrapper.getRequestInfo().getHeaders()).thenReturn(Arrays.asList("Foo: bar", "Bar: foo"));
        assertFalse(new AnyHeaderMatchType(burpExtender).match(newPattern("test"), interceptedProxyMessageWrapper));
    }

    @Test
    public void testAnyHeaderMatchTypeSuccess() {
        when(interceptedProxyMessageWrapper.getRequestInfo().getHeaders()).thenReturn(Arrays.asList("Foo: bar", "Bar: foo"));
        assertTrue(new AnyHeaderMatchType(burpExtender).match(newPattern("Foo:"), interceptedProxyMessageWrapper));
        assertTrue(new AnyHeaderMatchType(burpExtender).match(newPattern("Bar:"), interceptedProxyMessageWrapper));
    }

    // -----------------------------------------------------------------------------------------------------------------

    @Test
    public void testBodyMatchTypeFail() {
        when(interceptedProxyMessageWrapper.getRequestInfo().getBody()).thenReturn("foo=bar&Foo=Bar");
        assertFalse(new BodyMatchType(burpExtender).match(newPattern("POST"), interceptedProxyMessageWrapper));
        assertFalse(new BodyMatchType(burpExtender).match(newPattern("close"), interceptedProxyMessageWrapper));
        assertFalse(new BodyMatchType(burpExtender).match(newPattern("\n"), interceptedProxyMessageWrapper));
    }


    @Test
    public void testBodyMatchTypeSuccess() {
        when(interceptedProxyMessageWrapper.getRequestInfo().getBody()).thenReturn("foo=bar&Foo=Bar");
        assertTrue(new BodyMatchType(burpExtender).match(newPattern("foo=bar"), interceptedProxyMessageWrapper));
        assertTrue(new BodyMatchType(burpExtender).match(newPattern("Foo=Bar"), interceptedProxyMessageWrapper));
    }

    // -----------------------------------------------------------------------------------------------------------------

    @Test
    public void testCookieNameMatchTypeFail() {
        when(interceptedProxyMessageWrapper.getRequestInfo().getCookies()).thenReturn(Lists.newArrayList(new Cookie("FOO", "BAR")));
        assertFalse(new CookieNameMatchType(burpExtender).match(newPattern("BAR"), interceptedProxyMessageWrapper));
        assertFalse(new CookieNameMatchType(burpExtender).match(newPattern(" "), interceptedProxyMessageWrapper));
        assertFalse(new CookieNameMatchType(burpExtender).match(newPattern("="), interceptedProxyMessageWrapper));
    }

    @Test
    public void testCookieNameMatchTypeSuccess() {
        when(interceptedProxyMessageWrapper.getRequestInfo().getCookies()).thenReturn(Lists.newArrayList(new Cookie("FOO", "BAR")));
        assertTrue(new CookieNameMatchType(burpExtender).match(newPattern("FOO"), interceptedProxyMessageWrapper));
    }

    // -----------------------------------------------------------------------------------------------------------------

    @Test
    public void testDomainNameMatchTypeFail() {
        when(interceptedProxyMessageWrapper.getInterceptedProxyMessage().getMessageInfo().getHttpService().getHost()).thenReturn("FooBar");
        assertFalse(new DomainNameMatchType(burpExtender).match(newPattern("test"), interceptedProxyMessageWrapper));
    }

    @Test
    public void testDomainNameMatchTypeSuccess() {
        when(interceptedProxyMessageWrapper.getInterceptedProxyMessage().getMessageInfo().getHttpService().getHost()).thenReturn("FooBar");
        assertTrue(new DomainNameMatchType(burpExtender).match(newPattern("a"), interceptedProxyMessageWrapper));
    }

    // -----------------------------------------------------------------------------------------------------------------

    @Test
    public void testFileExtensionMatchTypeFail() throws MalformedURLException {
        when(interceptedProxyMessageWrapper.getRequestInfo().getUrl()).thenReturn(new URL("http://host/foo.bar"));
        assertFalse(new FileExtensionMatchType(burpExtender).match(newPattern("foo"), interceptedProxyMessageWrapper));
        assertFalse(new FileExtensionMatchType(burpExtender).match(newPattern("\\."), interceptedProxyMessageWrapper));
        assertFalse(new FileExtensionMatchType(burpExtender).match(newPattern("\\.bar"), interceptedProxyMessageWrapper));
    }

    @Test
    public void testFileExtensionMatchTypeSuccess() throws MalformedURLException {
        when(interceptedProxyMessageWrapper.getRequestInfo().getUrl()).thenReturn(new URL("http://host/foo.bar"));
        assertTrue(new FileExtensionMatchType(burpExtender).match(newPattern("a"), interceptedProxyMessageWrapper));
        assertTrue(new FileExtensionMatchType(burpExtender).match(newPattern("."), interceptedProxyMessageWrapper));
        assertTrue(new FileExtensionMatchType(burpExtender).match(newPattern("bar"), interceptedProxyMessageWrapper));
    }

    // -----------------------------------------------------------------------------------------------------------------

    @Test
    public void testHttpMethodMatchTypeFail() {
        when(interceptedProxyMessageWrapper.getRequestInfo().getMethod()).thenReturn("GET");
        assertFalse(new HttpMethodMatchType(burpExtender).match(newPattern("test"), interceptedProxyMessageWrapper));
    }

    @Test
    public void testHttpMethodMatchTypeSuccess() {
        when(interceptedProxyMessageWrapper.getRequestInfo().getMethod()).thenReturn("GET");
        assertTrue(new HttpMethodMatchType(burpExtender).match(newPattern("GET"), interceptedProxyMessageWrapper));
        assertTrue(new HttpMethodMatchType(burpExtender).match(newPattern("G.T"), interceptedProxyMessageWrapper));
    }

    // -----------------------------------------------------------------------------------------------------------------

    @Test
    public void testIpAddressMatchTypeFail() throws UnknownHostException {
        when(interceptedProxyMessageWrapper.getInterceptedProxyMessage().getClientIpAddress()).thenReturn(InetAddress.getByName("127.0.0.1"));
        assertFalse(new IpAddressMatchType(burpExtender).match(newPattern("test"), interceptedProxyMessageWrapper));
    }

    @Test
    public void testIpAddressMatchTypeSuccess() throws UnknownHostException {
        when(interceptedProxyMessageWrapper.getInterceptedProxyMessage().getClientIpAddress()).thenReturn(InetAddress.getByName("127.0.0.1"));
        assertTrue(new IpAddressMatchType(burpExtender).match(newPattern("127\\..*"), interceptedProxyMessageWrapper));
        assertTrue(new IpAddressMatchType(burpExtender).match(newPattern("127"), interceptedProxyMessageWrapper));
    }

    // -----------------------------------------------------------------------------------------------------------------

    @Test
    public void testListenerPortMatchTypeFail() {
        when(interceptedProxyMessageWrapper.getInterceptedProxyMessage().getMessageInfo().getHttpService().getPort()).thenReturn(443);
        assertFalse(new ListenerPortMatchType(burpExtender).match(newPattern("test"), interceptedProxyMessageWrapper));
    }

    @Test
    public void testListenerPortMatchTypeSuccess() {
        when(interceptedProxyMessageWrapper.getInterceptedProxyMessage().getMessageInfo().getHttpService().getPort()).thenReturn(443);
        assertTrue(new ListenerPortMatchType(burpExtender).match(newPattern("443"), interceptedProxyMessageWrapper));
        assertTrue(new ListenerPortMatchType(burpExtender).match(newPattern("4.*"), interceptedProxyMessageWrapper));
    }

    // -----------------------------------------------------------------------------------------------------------------

    @Test
    public void testParamNameMatchTypeFail() {
        IParameter parameter = mock(IParameter.class);
        when(parameter.getName()).thenReturn("foo");
        when(interceptedProxyMessageWrapper.getRequestInfo().getParameters()).thenReturn(Lists.newArrayList(parameter));
        assertFalse(new ParamNameMatchType(burpExtender).match(newPattern("bar"), interceptedProxyMessageWrapper));
    }

    @Test
    public void testParamNameMatchTypeSuccess() {
        IParameter parameter = mock(IParameter.class);
        when(parameter.getName()).thenReturn("foo");
        when(interceptedProxyMessageWrapper.getRequestInfo().getParameters()).thenReturn(Lists.newArrayList(parameter));
        assertTrue(new ParamNameMatchType(burpExtender).match(newPattern("foo"), interceptedProxyMessageWrapper));
        assertTrue(new ParamNameMatchType(burpExtender).match(newPattern("f.o"), interceptedProxyMessageWrapper));
    }

    // -----------------------------------------------------------------------------------------------------------------

    @Test
    public void testParamValueMatchTypeFail() {
        IParameter parameter = mock(IParameter.class);
        when(parameter.getValue()).thenReturn("foo");
        when(interceptedProxyMessageWrapper.getRequestInfo().getParameters()).thenReturn(Lists.newArrayList(parameter));
        assertFalse(new ParamValueMatchType(burpExtender).match(newPattern("bar"), interceptedProxyMessageWrapper));
    }

    @Test
    public void testParamValueMatchTypeSuccess() {
        IParameter parameter = mock(IParameter.class);
        when(parameter.getValue()).thenReturn("foo");
        when(interceptedProxyMessageWrapper.getRequestInfo().getParameters()).thenReturn(Lists.newArrayList(parameter));
        assertTrue(new ParamValueMatchType(burpExtender).match(newPattern("foo"), interceptedProxyMessageWrapper));
        assertTrue(new ParamValueMatchType(burpExtender).match(newPattern("f.o"), interceptedProxyMessageWrapper));
    }

    // -----------------------------------------------------------------------------------------------------------------

    @Test
    public void testProtocolMatchTypeFail() {
        when(interceptedProxyMessageWrapper.getInterceptedProxyMessage().getMessageInfo().getHttpService().getProtocol()).thenReturn("foo");
        assertFalse(new ProtocolMatchType(burpExtender).match(newPattern("bar"), interceptedProxyMessageWrapper));
    }

    @Test
    public void testProtocolMatchTypeSuccess() {
        when(interceptedProxyMessageWrapper.getInterceptedProxyMessage().getMessageInfo().getHttpService().getProtocol()).thenReturn("foo");
        assertTrue(new ProtocolMatchType(burpExtender).match(newPattern("foo"), interceptedProxyMessageWrapper));
        assertTrue(new ProtocolMatchType(burpExtender).match(newPattern("f.o"), interceptedProxyMessageWrapper));
    }

    // -----------------------------------------------------------------------------------------------------------------

    @Test
    public void testRequestMatchTypeFail() {
        when(interceptedProxyMessageWrapper.getInterceptedProxyMessage().getMessageInfo().getRequest()).thenReturn("Foo\nBar".getBytes());
        assertFalse(new RequestMatchType(burpExtender).match(newPattern("test"), interceptedProxyMessageWrapper));
    }

    @Test
    public void testRequestMatchTypeSuccess() {
        when(interceptedProxyMessageWrapper.getInterceptedProxyMessage().getMessageInfo().getRequest()).thenReturn("Foo\nBar".getBytes());
        assertTrue(new RequestMatchType(burpExtender).match(newPattern("a"), interceptedProxyMessageWrapper));
    }

    // -----------------------------------------------------------------------------------------------------------------

    @Test
    public void testUrlMatchTypeFail() throws MalformedURLException {
        when(interceptedProxyMessageWrapper.getRequestInfo().getUrl()).thenReturn(new URL("http://localhost/"));
        assertFalse(new UrlMatchType(burpExtender).match(newPattern("test"), interceptedProxyMessageWrapper));
    }

    @Test
    public void testUrlMatchTypeSuccess() throws MalformedURLException {
        when(interceptedProxyMessageWrapper.getRequestInfo().getUrl()).thenReturn(new URL("http://localhost/"));
        assertTrue(new UrlMatchType(burpExtender).match(newPattern("localhost"), interceptedProxyMessageWrapper));
    }

}