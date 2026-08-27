package net.openid.appauth;
import android.net.Uri;
import java.util.Map;
public class AuthorizationRequest {
    public final String codeVerifier;
    public final String state;
    public Map<String, String> additionalParameters;
    public AuthorizationRequest(String codeVerifier, String state, Map<String, String> additionalParameters) {
        this.codeVerifier = codeVerifier;
        this.state = state;
        this.additionalParameters = additionalParameters;
    }
    public static class Builder {
        public Builder(AuthorizationServiceConfiguration config, String clientId, String responseType, Uri redirectUri) {}
        public Builder setScopes(String... scopes) { return this; }
        public Builder setState(String state) { return this; }
        public Builder setCodeVerifier(String codeVerifier) { return this; }
        public Builder setAdditionalParameters(Map<String, String> additionalParameters) { return this; }
        public AuthorizationRequest build() { throw new UnsupportedOperationException(); }
    }
    public Uri getRedirectUri() { return null; }
    public String getState() { return null; }
}
