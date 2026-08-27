package net.openid.appauth;
public class TokenRequest {
    public static class Builder {
        public Builder(AuthorizationServiceConfiguration config, String clientId) {}
        public Builder setGrantType(String grantType) { return this; }
        public Builder setRefreshToken(String refreshToken) { return this; }
        public Builder setScopes(String... scopes) { return this; }
        public TokenRequest build() { throw new UnsupportedOperationException(); }
    }
}
