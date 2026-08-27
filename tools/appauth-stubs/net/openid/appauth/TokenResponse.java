package net.openid.appauth;
public class TokenResponse {
    public final String accessToken;
    public final String refreshToken;
    public final String idToken;
    public final Long accessTokenExpirationTime;
    private TokenResponse() { this.accessToken = null; this.refreshToken = null; this.idToken = null; this.accessTokenExpirationTime = null; }
}
