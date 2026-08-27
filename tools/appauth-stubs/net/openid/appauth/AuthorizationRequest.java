package net.openid.appauth;
import android.net.Uri;
public class AuthorizationRequest {
    public static class Builder {
        public Builder(AuthorizationServiceConfiguration config, String clientId, String responseType, Uri redirectUri) {}
        public Builder setScopes(String... scopes) { return this; }
        public AuthorizationRequest build() { throw new UnsupportedOperationException(); }
    }
}
