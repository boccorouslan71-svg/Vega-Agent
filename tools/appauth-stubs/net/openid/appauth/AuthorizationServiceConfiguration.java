package net.openid.appauth;
import android.net.Uri;
public class AuthorizationServiceConfiguration {
    public AuthorizationServiceConfiguration(Uri authorizationEndpoint, Uri tokenEndpoint) {}
    public static class Builder {
        public Builder() {}
        public Builder setAuthorizationEndpoint(Uri uri) { return this; }
        public Builder setTokenEndpoint(Uri uri) { return this; }
        public AuthorizationServiceConfiguration build() { throw new UnsupportedOperationException(); }
    }
}
