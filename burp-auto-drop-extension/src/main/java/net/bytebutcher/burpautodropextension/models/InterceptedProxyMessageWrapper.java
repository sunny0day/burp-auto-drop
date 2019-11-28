package net.bytebutcher.burpautodropextension.models;

import burp.*;

public class InterceptedProxyMessageWrapper {

    private final burp.IBurpExtenderCallbacks burpExtenderCallbacks;
    private final burp.IInterceptedProxyMessage interceptedProxyMessage;
    private IRequestInfo requestInfo;
    private IResponseInfo responseInfo;

    public InterceptedProxyMessageWrapper(IBurpExtenderCallbacks burpExtenderCallbacks, burp.IInterceptedProxyMessage interceptedProxyMessage) {
        this.burpExtenderCallbacks = burpExtenderCallbacks;
        this.interceptedProxyMessage = interceptedProxyMessage;
    }

    public IRequestInfo getRequestInfo() {
        if (requestInfo == null) {
            requestInfo = new RequestInfoWrapper(getInterceptedProxyMessage(), burpExtenderCallbacks.getHelpers().analyzeRequest(interceptedProxyMessage.getMessageInfo()));
        }
        return requestInfo;
    }

    public IResponseInfo getResponseInfo() {
        if (responseInfo == null) {
            responseInfo = burpExtenderCallbacks.getHelpers().analyzeResponse(interceptedProxyMessage.getMessageInfo().getResponse());
        }
        return responseInfo;
    }

    public IBurpExtenderCallbacks getBurpExtenderCallbacks() {
        return burpExtenderCallbacks;
    }

    public burp.IInterceptedProxyMessage getInterceptedProxyMessage() {
        return interceptedProxyMessage;
    }
}
