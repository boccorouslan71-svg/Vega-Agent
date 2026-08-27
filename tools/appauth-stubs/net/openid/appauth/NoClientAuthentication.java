package net.openid.appauth;

import java.util.Map;

public final class NoClientAuthentication implements ClientAuthentication {
    public static final NoClientAuthentication INSTANCE = new NoClientAuthentication();

    private NoClientAuthentication() {}

    @Override
    public void applyToRequestHeaders(Map<String, String> requestHeaders) throws UnsupportedAuthenticationMethod {
        throw new UnsupportedAuthenticationMethod("none");
    }

    @Override
    public void applyToRequestParameters(Map<String, String> requestParameters) throws UnsupportedAuthenticationMethod {
        throw new UnsupportedAuthenticationMethod("none");
    }
}