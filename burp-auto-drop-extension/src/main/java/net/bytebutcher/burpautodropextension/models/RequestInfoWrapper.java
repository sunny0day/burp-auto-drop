package net.bytebutcher.burpautodropextension.models;

import burp.ICookie;
import burp.IParameter;
import burp.IRequestInfo;
import com.google.common.collect.Lists;

import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class RequestInfoWrapper implements net.bytebutcher.burpautodropextension.models.IRequestInfo {
    private burp.IInterceptedProxyMessage interceptedProxyMessage;
    private IRequestInfo requestInfo;
    private List<ICookie> cookies;
    private String requestBody;

    public RequestInfoWrapper(burp.IInterceptedProxyMessage interceptedProxyMessage, IRequestInfo requestInfo) {
        this.interceptedProxyMessage = interceptedProxyMessage;
        this.requestInfo = requestInfo;
    }

    @Override
    public List<ICookie> getCookies() {
        if (cookies == null) {
            String cookieHeaderPrefix = "cookie: ";
            List<String> cookieHeaders = requestInfo.getHeaders().stream().filter(s -> s.toLowerCase().startsWith(cookieHeaderPrefix)).collect(Collectors.toList());
            boolean hasCookieHeader = !cookieHeaders.isEmpty();
            cookies = Lists.newArrayList();
            if (hasCookieHeader) {
                for (String cookieHeader : cookieHeaders) {
                    cookies.addAll(Cookie.parseRequestCookies(cookieHeader.substring(cookieHeaderPrefix.length() - 1)));
                }
            }
        }
        return cookies;
    }

    @Override
    public String getBody() {
        if (requestBody == null) {
            byte[] request = interceptedProxyMessage.getMessageInfo().getRequest();
            int bodyOffset = this.getBodyOffset();
            requestBody = new String(Arrays.copyOfRange(request, bodyOffset, request.length));
        }
        return requestBody;
    }

    @Override
    public String getMethod() {
        return requestInfo.getMethod();
    }

    @Override
    public URL getUrl() {
        return requestInfo.getUrl();
    }

    @Override
    public List<String> getHeaders() {
        return requestInfo.getHeaders();
    }

    @Override
    public List<IParameter> getParameters() {
        return requestInfo.getParameters();
    }

    @Override
    public int getBodyOffset() {
        return requestInfo.getBodyOffset();
    }

    @Override
    public byte getContentType() {
        return requestInfo.getContentType();
    }
}
