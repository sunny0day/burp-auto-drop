package net.bytebutcher.burpautodropextension.models;

import burp.IHttpRequestResponse;
import burp.IInterceptedProxyMessage;
import burp.IRequestInfo;
import com.google.common.collect.Lists;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Answers;

import java.util.Arrays;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class RequestInfoWrapperTest {


    private IInterceptedProxyMessage interceptedProxyMessage;
    private IRequestInfo requestInfo;

    @Before
    public void setUp() {
        //
        // WARNING: every time a mock returns a mock a fairy dies.
        //
        // CASUALTIES SO FAR: X X X /
        //
        interceptedProxyMessage = mock(IInterceptedProxyMessage.class, Answers.RETURNS_DEEP_STUBS.get());
        requestInfo = mock(IRequestInfo.class);
    }

    @Test
    public void testGetCookiesMatchCaseSensitive() {
        when(interceptedProxyMessage.getMessageInfo().getRequest()).thenReturn(("POST / HTTP/1.1\r\n" +
                "Content-Length: 27\r\n" +
                "Cookie: FOO=BAR\r\n" +
                "Connection: close\r\n" +
                "\r\n" +
                "foo=bar&Foo=Bar").getBytes());
        when(requestInfo.getHeaders()).thenReturn(Arrays.asList("Content-Length: 27", "Cookie: FOO=BAR", "Connection: close"));
        assertEquals(1, new RequestInfoWrapper(interceptedProxyMessage, requestInfo).getCookies().size());
        assertEquals(new Cookie("FOO", "BAR"), new RequestInfoWrapper(interceptedProxyMessage, requestInfo).getCookies().get(0));
        assertNotEquals(new Cookie("foo", "bar"), new RequestInfoWrapper(interceptedProxyMessage, requestInfo).getCookies().get(0));
    }

    @Test
    public void testGetCookiesWithHttpRequestCookieReturnsCookie() {
        when(interceptedProxyMessage.getMessageInfo().getRequest()).thenReturn(("POST / HTTP/1.1\r\n" +
                "Content-Length: 27\r\n" +
                "Cookie: FOO=BAR\r\n" +
                "Connection: close\r\n" +
                "\r\n" +
                "foo=bar&Foo=Bar").getBytes());
        when(requestInfo.getHeaders()).thenReturn(Arrays.asList("Content-Length: 27", "Cookie: FOO=BAR", "Connection: close"));
        assertEquals(1, new RequestInfoWrapper(interceptedProxyMessage, requestInfo).getCookies().size());
        assertEquals(new Cookie("FOO", "BAR"), new RequestInfoWrapper(interceptedProxyMessage, requestInfo).getCookies().get(0));
    }

    @Test
    public void testGetCookiesWithHttpRequestMultipleCookieHeaderReturnsCookies() {
        when(interceptedProxyMessage.getMessageInfo().getRequest()).thenReturn(("POST / HTTP/1.1\r\n" +
                "Content-Length: 27\r\n" +
                "Cookie: FOO=BAR\r\n" +
                "Cookie: foo=bar\r\n" +
                "Connection: close\r\n" +
                "\r\n" +
                "foo=bar&Foo=Bar").getBytes());
        when(requestInfo.getHeaders()).thenReturn(Arrays.asList("Content-Length: 27", "Cookie: FOO=BAR", "Cookie: foo=bar", "Connection: close"));
        assertEquals(2, new RequestInfoWrapper(interceptedProxyMessage, requestInfo).getCookies().size());
        assertEquals(new Cookie("FOO", "BAR"), new RequestInfoWrapper(interceptedProxyMessage, requestInfo).getCookies().get(0));
        assertEquals(new Cookie("foo", "bar"), new RequestInfoWrapper(interceptedProxyMessage, requestInfo).getCookies().get(1));
    }

    @Test
    public void testGetCookiesWithHttpRequestCookiesReturnsCookies() {
        when(interceptedProxyMessage.getMessageInfo().getRequest()).thenReturn(("POST / HTTP/1.1\r\n" +
                "Content-Length: 27\r\n" +
                "Cookie: FOO=BAR; foo=bar\r\n" +
                "Connection: close\r\n" +
                "\r\n" +
                "foo=bar&Foo=Bar").getBytes());
        when(requestInfo.getHeaders()).thenReturn(Arrays.asList("Content-Length: 27", "Cookie: FOO=BAR; foo=bar", "Connection: close"));
        assertEquals(2, new RequestInfoWrapper(interceptedProxyMessage, requestInfo).getCookies().size());
        assertEquals(new Cookie("FOO", "BAR"), new RequestInfoWrapper(interceptedProxyMessage, requestInfo).getCookies().get(0));
        assertEquals(new Cookie("foo", "bar"), new RequestInfoWrapper(interceptedProxyMessage, requestInfo).getCookies().get(1));
    }

    @Test
    public void testGetCookiesWithoutHttpRequestCookieReturnsEmpty() {
        when(interceptedProxyMessage.getMessageInfo().getRequest()).thenReturn(("POST / HTTP/1.1\r\n" +
                "Content-Length: 27\r\n" +
                "Connection: close\r\n" +
                "\r\n" +
                "foo=bar&Foo=Bar").getBytes());
        when(requestInfo.getHeaders()).thenReturn(Arrays.asList("Content-Length: 27", "Connection: close"));
        assertEquals(0, new RequestInfoWrapper(interceptedProxyMessage, requestInfo).getCookies().size());
    }

    @Test
    public void testGetBodyWithHttpRequestBodyReturnsBody() {
        when(requestInfo.getBodyOffset()).thenReturn(58);
        when(interceptedProxyMessage.getMessageInfo().getRequest()).thenReturn((
                "POST / HTTP/1.1\r\n" +
                        "Content-Length: 27\r\n" +
                        "Connection: close\r\n" +
                        "\r\n" +
                        "foo=bar&Foo=Bar").getBytes());

        assertEquals("foo=bar&Foo=Bar", new RequestInfoWrapper(interceptedProxyMessage, requestInfo).getBody());
    }

    @Test
    public void testGetBodyWithoutHttpRequestBodyReturnsEmpty() {
        when(requestInfo.getBodyOffset()).thenReturn(58);
        when(interceptedProxyMessage.getMessageInfo().getRequest()).thenReturn((
                "POST / HTTP/1.1\r\n" +
                        "Content-Length: 27\r\n" +
                        "Connection: close\r\n" +
                        "\r\n").getBytes());
        assertEquals("", new RequestInfoWrapper(interceptedProxyMessage, requestInfo).getBody());
    }

}