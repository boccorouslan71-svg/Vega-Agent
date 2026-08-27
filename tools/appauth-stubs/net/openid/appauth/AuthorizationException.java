package net.openid.appauth;
import android.content.Intent;
public class AuthorizationException extends Exception {
    public final String error;
    protected AuthorizationException(String error) { this.error = error; }
    public static AuthorizationException fromIntent(Intent intent) { throw new UnsupportedOperationException(); }
}
