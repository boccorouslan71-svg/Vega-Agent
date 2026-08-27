package com.vepro.code

import android.app.Activity
import android.content.Context
import android.content.Intent
import net.openid.appauth.AppAuthConfiguration
import net.openid.appauth.AuthorizationException
import net.openid.appauth.AuthorizationRequest
import net.openid.appauth.AuthorizationResponse
import net.openid.appauth.AuthorizationService
import net.openid.appauth.AuthorizationServiceConfiguration
import net.openid.appauth.TokenRequest
import org.json.JSONObject

/**
 * Manages OAuth 2.0 with PKCE for MCP server authentication.
 *
 * Flow:
 *   1. Discover endpoints (from server metadata or manual config)
 *   2. Build AuthorizationRequest with PKCE
 *   3. Launch Custom Tabs for user authorization
 *   4. Handle callback URI → exchange authorization code for tokens
 *   5. Store tokens encrypted via SecureStore
 *
 * Uses AppAuth-Android 0.11.1 for the full OAuth/PKCE flow.
 */
class McpOAuthManager(private val context: Context) {

    private val authService: AuthorizationService = AuthorizationService(context)

    /**
     * Callback interface for OAuth flow completion.
     */
    interface OAuthCallback {
        fun onSuccess(accessToken: String, refreshToken: String?, idToken: String?)
        fun onError(error: String)
        fun onCancel()
    }

    /**
     * Start the OAuth 2.0 authorization flow.
     *
     * @param activity The activity to launch Custom Tabs from.
     * @param server The MCP server with OAuth configuration.
     * @param callback Result callback.
     */
    fun startAuthorization(
        activity: Activity,
        server: McpServer,
        callback: OAuthCallback
    ) {
        val oauth = server.oauth

        // Build service configuration from endpoints
        val serviceConfig = AuthorizationServiceConfiguration.Builder()
            .setAuthorizationEndpoint(
                android.net.Uri.parse(oauth.authorizationEndpoint)
            )
            .setTokenEndpoint(
                android.net.Uri.parse(oauth.tokenEndpoint)
            )
            .build()

        // Build PKCE parameters
        val authRequestBuilder = AuthorizationRequest.Builder(
            serviceConfig,
            oauth.clientId,
            "code",
            android.net.Uri.parse(oauth.redirectUri)
        )
            .setScopes(*oauth.scopes.toTypedArray())

        // Store server ID for callback resolution
        val prefs = Prefs(context)
        prefs.save(MCP_OAUTH_SERVER_ID_KEY, server.id)

        val authRequest = authRequestBuilder.build()

        // Build a PendingIntent so the browser returns to our activity
        val completionIntent = android.content.Intent(context, SettingsActivity::class.java)
        completionIntent.action = android.content.Intent.ACTION_VIEW
        completionIntent.data = android.net.Uri.parse(oauth.redirectUri)
        val pendingIntent = android.app.PendingIntent.getActivity(
            context,
            PENDING_INTENT_REQUEST_CODE,
            completionIntent,
            android.app.PendingIntent.FLAG_ONE_SHOT or android.app.PendingIntent.FLAG_IMMUTABLE
        )

        // Launch authorization via Custom Tabs
        authService.performAuthorizationRequest(authRequest, pendingIntent)
    }

    /**
     * Handle the OAuth callback URI. Call this from the activity's
     * onNewIntent or onActivityResult.
     *
     * @param intent The intent containing the OAuth callback.
     * @param server The MCP server being authenticated.
     * @param callback Result callback.
     */
    fun handleAuthorizationResponse(
        intent: Intent,
        server: McpServer,
        callback: OAuthCallback
    ) {
        val authResponse = AuthorizationResponse.fromIntent(intent)
        val authException = AuthorizationException.fromIntent(intent)

        if (authResponse == null || authException != null) {
            callback.onError(
                authException?.error ?: "Authorization failed"
            )
            return
        }

        // Exchange authorization code for tokens
        val tokenRequest = authResponse.createTokenExchangeRequest()

        authService.performTokenRequest(
            tokenRequest,
            AuthorizationService.TokenResponseCallback { response, ex ->
                if (response != null) {
                    // Store tokens encrypted
                    val accessToken = response.accessToken ?: ""
                    val refreshToken = response.refreshToken ?: ""
                    val idToken = response.idToken ?: ""

                    val encryptedAccess = if (accessToken.isNotEmpty()) {
                        SecureStore.encrypt(accessToken)
                    } else ""

                    val encryptedRefresh = if (refreshToken.isNotEmpty()) {
                        SecureStore.encrypt(refreshToken)
                    } else ""

                    // Update server config
                    server.oauth.encryptedAccessToken = encryptedAccess
                    server.oauth.encryptedRefreshToken = encryptedRefresh
                    server.oauth.tokenExpiry = response.accessTokenExpirationTime ?: 0L

                    callback.onSuccess(accessToken, refreshToken, idToken)
                } else {
                    callback.onError(
                        ex?.localizedMessage ?: "Token exchange failed"
                    )
                }
            }
        )
    }

    /**
     * Refresh an expired access token using the stored refresh token.
     */
    fun refreshToken(
        server: McpServer,
        callback: OAuthCallback
    ) {
        val oauth = server.oauth
        if (oauth.encryptedRefreshToken.isEmpty()) {
            callback.onError("No refresh token available")
            return
        }

        val refreshToken = try {
            SecureStore.decrypt(oauth.encryptedRefreshToken)
        } catch (_: Exception) {
            callback.onError("Failed to decrypt refresh token")
            return
        }

        if (refreshToken.isEmpty()) {
            callback.onError("Refresh token is empty")
            return
        }

        val serviceConfig = AuthorizationServiceConfiguration.Builder()
            .setTokenEndpoint(
                android.net.Uri.parse(oauth.tokenEndpoint)
            )
            .build()

        val tokenRequest = TokenRequest.Builder(
            serviceConfig,
            oauth.clientId
        )
            .setGrantType("refresh_token")
            .setRefreshToken(refreshToken)
            .setScopes(*oauth.scopes.toTypedArray())
            .build()

        authService.performTokenRequest(
            tokenRequest,
            AuthorizationService.TokenResponseCallback { response, ex ->
                if (response != null) {
                    val newAccessToken = response.accessToken ?: ""
                    val newRefreshToken = response.refreshToken ?: refreshToken

                    val encryptedAccess = if (newAccessToken.isNotEmpty()) {
                        SecureStore.encrypt(newAccessToken)
                    } else ""

                    val encryptedRefresh = if (newRefreshToken.isNotEmpty()) {
                        SecureStore.encrypt(newRefreshToken)
                    } else ""

                    server.oauth.encryptedAccessToken = encryptedAccess
                    server.oauth.encryptedRefreshToken = encryptedRefresh
                    server.oauth.tokenExpiry = response.accessTokenExpirationTime ?: 0L

                    callback.onSuccess(
                        newAccessToken,
                        newRefreshToken,
                        response.idToken
                    )
                } else {
                    callback.onError(
                        ex?.localizedMessage ?: "Token refresh failed"
                    )
                }
            }
        )
    }

    /**
     * Get the current access token for a server, decrypting it from storage.
     * Returns null if no token exists or decryption fails.
     */
    fun getAccessToken(server: McpServer): String? {
        val oauth = server.oauth
        if (oauth.encryptedAccessToken.isEmpty()) return null

        return try {
            val token = SecureStore.decrypt(oauth.encryptedAccessToken)
            if (token.isEmpty()) null else token
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Clear all stored tokens for a server.
     */
    fun clearTokens(server: McpServer) {
        server.oauth.encryptedAccessToken = ""
        server.oauth.encryptedRefreshToken = ""
        server.oauth.tokenExpiry = 0L
    }

    /**
     * Dispose of the authorization service.
     */
    fun dispose() {
        authService.dispose()
    }

    companion object {
        const val PENDING_INTENT_REQUEST_CODE = 10001
        const val MCP_OAUTH_SERVER_ID_KEY = "mcp_oauth_server_id"
    }
}
