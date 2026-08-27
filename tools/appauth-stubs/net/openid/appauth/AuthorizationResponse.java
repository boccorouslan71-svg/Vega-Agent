package net.openid.appauth;
import android.content.Intent;
import java.util.Map;
public class AuthorizationResponse {
    public final AuthorizationRequest authRequest;
    public String authorizationCode;
    public String state;
    public String accessToken;
    public String idToken;
    public long accessTokenExpirationTime;
    public String refreshToken;
    public Map<String, String> additionalParameters;
    public static AuthorizationResponse fromIntent(Intent intent) { return null; }
    public TokenRequest createTokenExchangeRequest() { throw new UnsupportedOperationException(); }
    public static class Builder {
        public Builder(AuthorizationRequest authRequest) { throw new UnsupportedOperationException(); }
        public AuthorizationResponse build() { throw new UnsupportedOperationException(); }
    }
}
