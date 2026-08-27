package net.openid.appauth;
import android.content.Context;
import android.app.PendingIntent;
public class AuthorizationService {
    public AuthorizationService(Context context) {}
    public void performAuthorizationRequest(AuthorizationRequest request, PendingIntent completedIntent) {}
    public void performTokenRequest(TokenRequest request, TokenResponseCallback callback) {}
    public void dispose() {}
    public interface TokenResponseCallback {
        void onTokenRequestCompleted(TokenResponse response, AuthorizationException ex);
    }
}
