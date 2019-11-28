package net.bytebutcher.burpautodropextension.models;

import burp.ICookie;

import java.util.List;

public interface IRequestInfo extends burp.IRequestInfo {

    List<ICookie> getCookies();
    String getBody();

}
