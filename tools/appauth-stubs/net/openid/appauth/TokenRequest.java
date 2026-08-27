package net.openid.appauth;
import java.util.Map;
public class TokenRequest {
    public String grantType;
    public String authorizationCode;
    public String redirectUri;
    public String refreshToken;
    public String codeVerifier;
    public String clientId;
    public Map<String, String> additionalParameters;
    public static class Builder {
        public Builder(AuthorizationServiceConfiguration configuration, String clientId) { throw new UnsupportedOperationException(); }
        public Builder setGrantType(String grantType) { return this; }
        public Builder setAuthorizationCode(String authorizationCode) { return this; }
        public Builder setRedirectUri(android.net.Uri redirectUri) { return this; }
        public Builder setRefreshToken(String refreshToken) { return this; }
        public Builder setCodeVerifier(String codeVerifier) { return this; }
        public Builder setScopes(String... scopes) { return this; }
        public Builder setAdditionalParameters(Map<String, String> additionalParameters) { return this; }
        public TokenRequest build() { throw new UnsupportedOperationException(); }
    }
}
