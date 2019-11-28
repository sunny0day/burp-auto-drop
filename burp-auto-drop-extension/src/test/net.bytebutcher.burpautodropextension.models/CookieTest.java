package net.bytebutcher.burpautodropextension.models;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CookieTest {

    private BurpExtender burpExtender;

    @Before
    public void setUp() {
        burpExtender = mock(BurpExtender.class);
        BurpExtender.instance = burpExtender;
        when(burpExtender.getCallbacks()).thenReturn(mock(IBurpExtenderCallbacks.class));
    }

    @Test
    public void testParseCookiesInvalidReturnsEmptyList() {
        assertTrue(Cookie.parseRequestCookies("FOO").isEmpty());
        assertTrue(Cookie.parseRequestCookies(" = ").isEmpty());
        assertTrue(Cookie.parseRequestCookies(" = ; = ").isEmpty());
    }

    @Test
    public void testParseCookiesReturnsSingle() {
        assertEquals(1, Cookie.parseRequestCookies("FOO=").size());
        assertEquals("FOO", Cookie.parseRequestCookies("FOO=").get(0).getName());
        assertEquals("", Cookie.parseRequestCookies("FOO=").get(0).getValue());
        assertEquals(1, Cookie.parseRequestCookies("FOO=").size());
        assertEquals(1, Cookie.parseRequestCookies("FOO=BAR").size());
    }

    @Test
    public void testParseCookiesReturnsNameAndValueWithoutSpaces() {
        assertEquals(1, Cookie.parseRequestCookies(" FOO = BAR ").size());
        assertEquals("FOO", Cookie.parseRequestCookies(" FOO = BAR ").get(0).getName());
        assertEquals("BAR", Cookie.parseRequestCookies(" FOO = BAR ").get(0).getValue());
    }

    @Test
    public void testParseCookiesReturnsMultiple() {
        assertEquals(2, Cookie.parseRequestCookies("FOO=BAR;foo=bar").size());
        assertEquals(2, Cookie.parseRequestCookies("FOO=BAR;foo=bar;").size());
        assertEquals(1, Cookie.parseRequestCookies(" = ; foo=bar").size());
    }

    @Test
    public void testCookiesEquals() {
        assertEquals(new Cookie("foo", "bar"), new Cookie("foo", "bar"));
    }

}