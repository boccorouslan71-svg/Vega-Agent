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
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

/**
 * Manages OAuth 2.0 with PKCE for MCP server authentication.
 *
 * Supports automatic discovery per MCP Authorization spec (RFC 8414 + RFC 9728):
 *   1. GET {endpoint}/.well-known/oauth-protected-resource → authorization server
 *   2. GET {authServer}/.well-known/oauth-authorization-server → endpoints
 *   3. POST {registrationEndpoint} → dynamic client registration (RFC 7591)
 *   4. Launch AppAuth PKCE flow with discovered endpoints + client_id
 *
 * Falls back to manual OAuth fields when discovery fails.
 */
class McpOAuthManager(private val context: Context) {

    private val authService: AuthorizationService = AuthorizationService(context)

    interface OAuthCallback {
        fun onSuccess(accessToken: String, refreshToken: String?, idToken: String?)
        fun onError(error: String)
        fun onCancel()
    }

    // =====================================================================
    // OAuth Discovery (RFC 8414 + RFC 9728)
    // =====================================================================

    data class DiscoveryResult(
        val authorizationEndpoint: String,
        val tokenEndpoint: String,
        val registrationEndpoint: String = "",
        val scopesSupported: List<String> = emptyList()
    )

    /**
     * Step 1: Discover the authorization server from the MCP endpoint.
     * GET {endpoint}/.well-known/oauth-protected-resource (RFC 9728)
     * Returns the authorization_server URL.
     */
    fun discoverProtectedResource(endpointUrl: String): String? {
        val wellKnownUrl = endpointUrl.trimEnd('/') + "/.well-known/oauth-protected-resource"
        val json = httpGet(wellKnownUrl) ?: return null
        return try {
            val obj = JSONObject(json)
            obj.optString("authorization_server", null)
                ?: obj.optString("authorizationServer", null)
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Step 2: Discover authorization endpoints from the authorization server.
     * GET {authServer}/.well-known/oauth-authorization-server (RFC 8414)
     * Falls back to /.well-known/openid-configuration if not found.
     */
    fun discoverAuthorizationServer(authServerUrl: String): DiscoveryResult? {
        val base = authServerUrl.trimEnd('/')
        // Try RFC 8414 first
        val json = httpGet("$base/.well-known/oauth-authorization-server")
            ?: httpGet("$base/.well-known/openid-configuration")
            ?: return null
        return try {
            val obj = JSONObject(json)
            val authEp = obj.optString("authorization_endpoint", "")
            val tokenEp = obj.optString("token_endpoint", "")
            if (authEp.isEmpty() || tokenEp.isEmpty()) return null
            val regEp = obj.optString("registration_endpoint", "")
            val scopes = mutableListOf<String>()
            val scopesArr = obj.optJSONArray("scopes_supported")
            if (scopesArr != null) {
                for (i in 0 until scopesArr.length()) {
                    val s = scopesArr.optString(i, "")
                    if (s.isNotEmpty()) scopes.add(s)
                }
            }
            DiscoveryResult(authEp, tokenEp, regEp, scopes)
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Step 3: Dynamic Client Registration (RFC 7591).
     * POST to registration_endpoint with redirect_uri, gets back client_id.
     */
    fun registerClient(registrationEndpoint: String, redirectUri: String): String? {
        val body = JSONObject()
        body.put("redirect_uris", org.json.JSONArray().put(redirectUri))
        body.put("client_name", "Vega MCP")
        body.put("token_endpoint_auth_method", "none") // public client (PKCE)
        body.put("grant_types", org.json.JSONArray().apply {
            put("authorization_code")
            put("refresh_token")
        })
        body.put("response_types", org.json.JSONArray().apply {
            put("code")
        })
        val json = httpPost(registrationEndpoint, body.toString()) ?: return null
        return try {
            val obj = JSONObject(json)
            obj.optString("client_id", null)
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Full auto-discovery + registration flow.
     * Call this off the main thread. Returns DiscoveryResult with clientId set,
     * or null if discovery fails.
     */
    fun autoDiscover(server: McpServer): DiscoveryResult? {
        // Step 1: Find the authorization server
        val authServerUrl = discoverProtectedResource(server.url) ?: return null

        // Step 2: Discover endpoints
        val discovery = discoverAuthorizationServer(authServerUrl) ?: return null

        // Step 3: Dynamic client registration if needed
        var clientId = server.oauth.clientId
        if (clientId.isEmpty() && discovery.registrationEndpoint.isNotEmpty()) {
            clientId = registerClient(discovery.registrationEndpoint, server.oauth.redirectUri) ?: ""
        }

        if (clientId.isEmpty() && discovery.registrationEndpoint.isEmpty()) {
            // No registration endpoint and no manual client_id → cannot proceed
            return null
        }

        return discovery.copy(
            authorizationEndpoint = discovery.authorizationEndpoint,
            tokenEndpoint = discovery.tokenEndpoint,
            registrationEndpoint = discovery.registrationEndpoint,
            scopesSupported = discovery.scopesSupported.ifEmpty {
                listOf("openid", "profile")
            }
        ).let {
            // Store clientId back into oauth config
            server.oauth.clientId = clientId
            server.oauth.authorizationEndpoint = it.authorizationEndpoint
            server.oauth.tokenEndpoint = it.tokenEndpoint
            if (it.scopesSupported.isNotEmpty()) {
                server.oauth.scopes = it.scopesSupported
            }
            it
        }
    }

    // =====================================================================
    // OAuth Flow
    // =====================================================================

    /**
     * Start the OAuth 2.0 authorization flow.
     * If endpoints are not yet discovered, does auto-discovery first.
     */
    fun startAuthorization(
        activity: Activity,
        server: McpServer,
        callback: OAuthCallback
    ) {
        val oauth = server.oauth

        // If endpoints are empty, run auto-discovery first
        if (oauth.authorizationEndpoint.isEmpty() || oauth.tokenEndpoint.isEmpty()) {
            Thread {
                val discovery = autoDiscover(server)
                if (discovery == null) {
                    activity.runOnUiThread {
                        callback.onError("OAuth discovery failed. Use Advanced fields to configure manually.")
                    }
                    return@Thread
                }
                activity.runOnUiThread {
                    doStartAuthorization(activity, server, callback)
                }
            }.start()
            return
        }

        doStartAuthorization(activity, server, callback)
    }

    private fun doStartAuthorization(
        activity: Activity,
        server: McpServer,
        callback: OAuthCallback
    ) {
        val oauth = server.oauth

        val serviceConfig = AuthorizationServiceConfiguration(
            android.net.Uri.parse(oauth.authorizationEndpoint),
            android.net.Uri.parse(oauth.tokenEndpoint)
        )

        val authRequestBuilder = AuthorizationRequest.Builder(
            serviceConfig,
            oauth.clientId,
            "code",
            android.net.Uri.parse(oauth.redirectUri)
        )
            .setScopes(*oauth.scopes.toTypedArray())

        val prefs = Prefs(context)
        prefs.save(MCP_OAUTH_SERVER_ID_KEY, server.id)

        val authRequest = authRequestBuilder.build()

        val completionIntent = android.content.Intent(context, SettingsActivity::class.java)
        completionIntent.action = android.content.Intent.ACTION_VIEW
        completionIntent.data = android.net.Uri.parse(oauth.redirectUri)
        val pendingIntent = android.app.PendingIntent.getActivity(
            context,
            PENDING_INTENT_REQUEST_CODE,
            completionIntent,
            android.app.PendingIntent.FLAG_ONE_SHOT or android.app.PendingIntent.FLAG_IMMUTABLE
        )

        authService.performAuthorizationRequest(authRequest, pendingIntent)
    }

    fun handleAuthorizationResponse(
        intent: Intent,
        server: McpServer,
        callback: OAuthCallback
    ) {
        val authResponse = AuthorizationResponse.fromIntent(intent)
        val authException = AuthorizationException.fromIntent(intent)

        if (authResponse == null || authException != null) {
            callback.onError(authException?.error ?: "Authorization failed")
            return
        }

        val tokenRequest = authResponse.createTokenExchangeRequest()

        authService.performTokenRequest(
            tokenRequest,
            AuthorizationService.TokenResponseCallback { response, ex ->
                if (response != null) {
                    val accessToken = response.accessToken ?: ""
                    val refreshToken = response.refreshToken ?: ""
                    val idToken = response.idToken ?: ""

                    val encryptedAccess = if (accessToken.isNotEmpty()) {
                        SecureStore.encrypt(accessToken)
                    } else ""
                    val encryptedRefresh = if (refreshToken.isNotEmpty()) {
                        SecureStore.encrypt(refreshToken)
                    } else ""

                    server.oauth.encryptedAccessToken = encryptedAccess
                    server.oauth.encryptedRefreshToken = encryptedRefresh
                    server.oauth.tokenExpiry = response.accessTokenExpirationTime ?: 0L

                    callback.onSuccess(accessToken, refreshToken, idToken)
                } else {
                    callback.onError(ex?.localizedMessage ?: "Token exchange failed")
                }
            }
        )
    }

    fun refreshToken(server: McpServer, callback: OAuthCallback) {
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
        val serviceConfig = AuthorizationServiceConfiguration(
            android.net.Uri.parse(oauth.authorizationEndpoint),
            android.net.Uri.parse(oauth.tokenEndpoint)
        )
        val tokenRequest = TokenRequest.Builder(serviceConfig, oauth.clientId)
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
                    callback.onSuccess(newAccessToken, newRefreshToken, response.idToken)
                } else {
                    callback.onError(ex?.localizedMessage ?: "Token refresh failed")
                }
            }
        )
    }

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

    fun clearTokens(server: McpServer) {
        server.oauth.encryptedAccessToken = ""
        server.oauth.encryptedRefreshToken = ""
        server.oauth.tokenExpiry = 0L
    }

    fun dispose() {
        authService.dispose()
    }

    // =====================================================================
    // HTTP helpers
    // =====================================================================

    private fun httpGet(urlStr: String): String? {
        return try {
            val url = URL(urlStr)
            val conn = url.openConnection() as HttpURLConnection
            conn.requestMethod = "GET"
            conn.connectTimeout = 8000
            conn.readTimeout = 8000
            conn.setRequestProperty("Accept", "application/json")
            if (conn.responseCode != 200) return null
            val reader = BufferedReader(InputStreamReader(conn.inputStream))
            val sb = StringBuilder()
            var line: String?
            while (reader.readLine().also { line = it } != null) {
                sb.append(line)
            }
            reader.close()
            conn.disconnect()
            sb.toString()
        } catch (_: Exception) {
            null
        }
    }

    private fun httpPost(urlStr: String, body: String): String? {
        return try {
            val url = URL(urlStr)
            val conn = url.openConnection() as HttpURLConnection
            conn.requestMethod = "POST"
            conn.doOutput = true
            conn.connectTimeout = 8000
            conn.readTimeout = 8000
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("Accept", "application/json")
            val writer = OutputStreamWriter(conn.outputStream)
            writer.write(body)
            writer.flush()
            writer.close()
            if (conn.responseCode !in 200..299) return null
            val reader = BufferedReader(InputStreamReader(conn.inputStream))
            val sb = StringBuilder()
            var line: String?
            while (reader.readLine().also { line = it } != null) {
                sb.append(line)
            }
            reader.close()
            conn.disconnect()
            sb.toString()
        } catch (_: Exception) {
            null
        }
    }

    companion object {
        const val PENDING_INTENT_REQUEST_CODE = 10001
        const val MCP_OAUTH_SERVER_ID_KEY = "mcp_oauth_server_id"
    }
}
