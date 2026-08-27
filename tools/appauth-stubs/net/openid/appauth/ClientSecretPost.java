package net.openid.appauth;

import java.util.Map;

public class ClientSecretPost implements ClientAuthentication {
    private final String clientSecret;

    public ClientSecretPost(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    @Override
    public void applyToRequestHeaders(Map<String, String> requestHeaders) throws UnsupportedAuthenticationMethod {
        throw new ClientAuthentication.UnsupportedAuthenticationMethod("client_secret_post");
    }

    @Override
    public void applyToRequestParameters(Map<String, String> requestParameters) throws UnsupportedAuthenticationMethod {
        requestParameters.put("client_secret", clientSecret);
    }
}