package net.openid.appauth;

import java.util.Map;

public interface ClientAuthentication {
    class UnsupportedAuthenticationMethod extends Exception {
        public UnsupportedAuthenticationMethod(String field) {
            super("Unsupported client authentication method: " + field);
        }
    }

    @SuppressWarnings("unused")
    void applyToRequestHeaders(Map<String, String> requestHeaders) throws UnsupportedAuthenticationMethod;

    @SuppressWarnings("unused")
    void applyToRequestParameters(Map<String, String> requestParameters) throws UnsupportedAuthenticationMethod;
}