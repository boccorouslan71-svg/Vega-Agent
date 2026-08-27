package net.openid.appauth;
import android.content.Context;
import android.app.PendingIntent;
import androidx.browser.customtabs.CustomTabsIntent;
public class AuthorizationService {
    public AuthorizationService(Context context) {}
    public void performAuthorizationRequest(AuthorizationRequest request, PendingIntent completedIntent) {}
    public void performTokenRequest(TokenRequest request, TokenResponseCallback callback) {}
    public void performTokenRequest(TokenRequest request, ClientAuthentication clientAuthentication, TokenResponseCallback callback) {}
    public CustomTabsIntent.Builder createCustomTabsIntentBuilder() { return null; }
    public void dispose() {}
    public interface TokenResponseCallback {
        void onTokenRequestCompleted(TokenResponse response, AuthorizationException ex);
    }
}
