package com.vepro.code

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.util.Log
import net.openid.appauth.AuthorizationException
import net.openid.appauth.AuthorizationRequest
import net.openid.appauth.AuthorizationResponse
import net.openid.appauth.AuthorizationService
import net.openid.appauth.AuthorizationServiceConfiguration
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.security.SecureRandom
import java.util.Base64

/**
 * Manages OAuth 2.0 with PKCE for MCP server authentication.
 *
 * Generic auto-discovery per the MCP Authorization spec (RFC 9728 + RFC 8414
 * + RFC 7591). For the authorization flow, uses the loopback approach from
 * the MCP spec: a local TCP server on 127.0.0.1:2083 receives the callback,
 * while the browser is opened directly (not via AppAuth's performAuthorizationRequest
 * which expects a deep-link return).
 */
class McpOAuthManager(private val context: Context) {

    private val authService: AuthorizationService = AuthorizationService(context)
    private var loopbackServer: McpLoopbackCallbackServer? = null
    private var pendingLoopbackCallback: OAuthCallback? = null
    private var pendingLoopbackActivity: Activity? = null

    interface OAuthCallback {
        fun onSuccess(accessToken: String, refreshToken: String?, idToken: String?)
        fun onError(error: String)
        fun onCancel()
    }

    // =====================================================================
    // OAuth Discovery (RFC 9728 + RFC 8414 + RFC 7591)
    // =====================================================================

    data class DiscoveryResult(
        val authorizationEndpoint: String,
        val tokenEndpoint: String,
        val registrationEndpoint: String = "",
        val issuer: String = "",
        val scopesSupported: List<String> = emptyList(),
        val tokenEndpointAuthMethodsSupported: List<String> = emptyList()
    )

    data class RegisteredClient(
        val clientId: String,
        val clientSecret: String = "",
        val tokenEndpointAuthMethod: String = "none"
    )

    /**
     * Step 1: find the authorization server for an MCP endpoint via RFC 9728.
     */
    fun discoverProtectedResource(endpointUrl: String): String? {
        if (endpointUrl.isBlankJava()) return null
        val metadataUrl = probeChallenge(endpointUrl)
        if (metadataUrl != null) {
            Log.d(TAG, "resource_metadata from WWW-Authenticate: $metadataUrl")
            return metadataUrl
        }
        return protectedResourceViaWellKnown(endpointUrl).firstOrNull()
    }

    /**
     * Step 2: discover the authorization endpoints from the authorization server URL.
     */
    fun discoverAuthorizationServer(authServerUrl: String): DiscoveryResult? {
        for (candidate in authorizationServerMetadataCandidates(authServerUrl)) {
            val res = httpRequest("GET", candidate) ?: continue
            if (res.status !in 200..299) continue
            val meta = parseServerMetadata(res.body) ?: continue
            return enrichScopes(authServerUrl, meta)
        }
        return null
    }

    /**
     * Step 3: dynamic client registration (RFC 7591).
     */
    fun registerClient(registrationEndpoint: String, redirectUri: String, resource: String? = null): RegisteredClient? {
        val body = JSONObject().apply {
            put("redirect_uris", org.json.JSONArray().put(redirectUri))
            put("client_name", "Vega MCP")
            put("token_endpoint_auth_method", "none")
            put("grant_types", org.json.JSONArray().apply { put("authorization_code"); put("refresh_token") })
            put("response_types", org.json.JSONArray().apply { put("code") })
            if (!resource.isNullOrBlankJava()) put("resource", resource)
        }
        val res = httpRequest("POST", registrationEndpoint, body = body.toString()) ?: return null
        if (res.status == 429) {
            val retryAfter = res.headers["retry-after"]?.firstOrNull()?.toLongOrNull() ?: 30L
            throw McpOAuthRateLimitException(retryAfter)
        }
        if (res.status !in 200..299) return null
        return try {
            val obj = JSONObject(res.body)
            val clientId = obj.optString("client_id", "")
            if (clientId.isEmpty()) return null
            val authMethod = obj.optString("token_endpoint_auth_method", "none")
            RegisteredClient(
                clientId = clientId,
                clientSecret = obj.optString("client_secret", ""),
                tokenEndpointAuthMethod = if (authMethod.isEmpty()) "none" else authMethod
            )
        } catch (_: Exception) { null }
    }

    /**
     * Full auto-discovery: authorization server → endpoints → client registration.
     */
    fun autoDiscover(server: McpServer): DiscoveryResult? {
        val oauth = server.oauth
        val resource = oauth.resourceUrl

        val authServerUrl = discoverProtectedResource(server.url) ?: return null
        Log.d(TAG, "authorization server: $authServerUrl")

        val discovery = discoverAuthorizationServer(authServerUrl) ?: return null
        Log.d(TAG, "discovered endpoints: ${discovery.authorizationEndpoint} / ${discovery.tokenEndpoint}")

        if (oauth.clientId.isEmpty() && discovery.registrationEndpoint.isNotEmpty()) {
            val registered = runCatching {
                registerClient(discovery.registrationEndpoint, oauth.redirectUri, resource)
            }.getOrNull()
            if (registered != null) {
                oauth.clientId = registered.clientId
                Log.d(TAG, "registered client ${registered.clientId}")
                if (registered.clientSecret.isNotEmpty()) {
                    oauth.encryptedClientSecret = SecureStore.encrypt(registered.clientSecret)
                    oauth.tokenEndpointAuthMethod = registered.tokenEndpointAuthMethod
                }
            }
        }

        if (oauth.clientId.isEmpty()) return null

        oauth.authorizationEndpoint = discovery.authorizationEndpoint
        oauth.tokenEndpoint = discovery.tokenEndpoint

        val sup = discovery.scopesSupported
        val mcpScopes = sup.filter { it.startsWith("mcp:") }
        val scopes = when {
            mcpScopes.isNotEmpty() -> mcpScopes
            sup.isNotEmpty() -> sup
            else -> emptyList()
        }
        if (scopes.isNotEmpty()) oauth.scopes = scopes

        if (oauth.tokenEndpointAuthMethod.isEmpty()) {
            oauth.tokenEndpointAuthMethod = preferClientAuth(discovery.tokenEndpointAuthMethodsSupported)
        }

        persistDiscovery(server)
        return discovery
    }

    // =====================================================================
    // OAuth Flow
    // =====================================================================

    /**
     * Start the OAuth 2.0 authorization flow.
     * Uses loopback if redirect is http://127.0.0.1:*, otherwise deep link.
     */
    fun startAuthorization(
        activity: Activity,
        server: McpServer,
        callback: OAuthCallback
    ) {
        val oauth = server.oauth

        if (oauth.authorizationEndpoint.isEmpty() || oauth.tokenEndpoint.isEmpty()) {
            Thread {
                val discovery = autoDiscover(server)
                if (discovery == null) {
                    activity.runOnUiThread { callback.onError(Fa.MCP_OAUTH_DISCOVERY_FAILED) }
                    return@Thread
                }
                activity.runOnUiThread { doStartAuthorization(activity, server, callback) }
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

        // Validate origin if override is set
        if (oauth.allowedOrigin.isNotEmpty()) {
            val actualOrigin = originOf(oauth.authorizationEndpoint)
            if (actualOrigin != oauth.allowedOrigin) {
                callback.onError("AS origin mismatch: expected ${oauth.allowedOrigin}, got $actualOrigin")
                return
            }
        }

        // Generate PKCE
        val codeVerifier = generateCodeVerifier()
        val state = generateState()
        val serviceConfig = AuthorizationServiceConfiguration(
            Uri.parse(oauth.authorizationEndpoint),
            Uri.parse(oauth.tokenEndpoint)
        )

        val builder = AuthorizationRequest.Builder(
            serviceConfig,
            oauth.clientId,
            "code",
            Uri.parse(oauth.redirectUri)
        ).setScopes(*oauth.scopes.toTypedArray())
            .setState(state)
            .setCodeVerifier(codeVerifier)

        if (oauth.resourceUrl.isNotEmpty()) {
            builder.setAdditionalParameters(mapOf("resource" to oauth.resourceUrl))
        }

        val authRequest = builder.build()

        val prefs = Prefs(context)
        prefs.save(MCP_OAUTH_SERVER_ID_KEY, server.id)
        prefs.save(MCP_OAUTH_STATE_KEY, state)
        prefs.save(MCP_OAUTH_CODE_VERIFIER_KEY, codeVerifier)

        if (oauth.redirectUri.startsWith("http://127.0.0.1:")) {
            startLoopbackFlow(
                activity, server, callback,
                buildAuthorizationUrl(oauth, codeVerifier, state),
                codeVerifier
            )
        } else {
            startDeepLinkFlow(activity, server, callback, authRequest)
        }
    }

    /**
     * Loopback flow — mirrors mobile-agent's approach exactly:
     * 1. Start TCP server on 127.0.0.1:2083 in background
     * 2. Open the authorize URL directly in a Custom Tab (NOT via
     *    performAuthorizationRequest, because that would expect a deep-link return)
     * 3. Wait for the callback on the loopback server
     * 4. Exchange the received code for tokens
     */
    private fun startLoopbackFlow(
        activity: Activity,
        server: McpServer,
        callback: OAuthCallback,
        authorizationUrl: String,
        codeVerifier: String
    ) {
        activity.runOnUiThread { callback.onError(Fa.MCP_OAUTH_LOOPBACK_START) }

        pendingLoopbackCallback = callback
        pendingLoopbackActivity = activity
        loopbackServer = McpLoopbackCallbackServer(
            expectedState = Prefs(context).str(MCP_OAUTH_STATE_KEY, ""),
            onResult = { code, state, error ->
                val actualRedirectUri = loopbackServer?.getRedirectUri()
                    ?: McpLoopbackCallbackServer.LOOPBACK_URL
                pendingLoopbackCallback = null
                pendingLoopbackActivity = null
                loopbackServer = null
                if (error != null) {
                    activity.runOnUiThread {
                        if (error.contains("Canceled", ignoreCase = true) ||
                            error.contains("cancelled", ignoreCase = true)) {
                            callback.onCancel()
                        } else {
                            callback.onError(error)
                        }
                    }
                    return@McpLoopbackCallbackServer
                }
                if (code != null) {
                    exchangeCodeForToken(activity, server, callback, code, codeVerifier, actualRedirectUri)
                }
            }
        )
        val started = loopbackServer?.start() ?: false
        if (!started) {
            activity.runOnUiThread { callback.onError("Could not start loopback server") }
            return
        }

        // Open browser directly — do NOT use performAuthorizationRequest.
        // That method launches AppAuth's management activity which waits for
        // a deep-link return that never arrives with a loopback redirect.
        val customTabsIntent = authService.createCustomTabsIntentBuilder().build()
        customTabsIntent.intent.data = android.net.Uri.parse(authorizationUrl)
        activity.startActivity(customTabsIntent.intent)
    }

    private fun startDeepLinkFlow(
        activity: Activity,
        server: McpServer,
        callback: OAuthCallback,
        authRequest: AuthorizationRequest
    ) {
        val completionIntent = Intent(context, SettingsActivity::class.java)
        completionIntent.action = Intent.ACTION_VIEW
        completionIntent.data = Uri.parse(authRequest.redirectUri.toString())
        val pendingIntent = android.app.PendingIntent.getActivity(
            context, PENDING_INTENT_REQUEST_CODE, completionIntent,
            android.app.PendingIntent.FLAG_ONE_SHOT or android.app.PendingIntent.FLAG_IMMUTABLE
        )
        authService.performAuthorizationRequest(authRequest, pendingIntent)
    }

    /**
     * Exchange the authorization code for tokens with a direct form-encoded
     * POST to the token endpoint — the same procedure mobile-agent performs
     * with `exchangeCodeAsync` (expo-auth-session). This avoids AppAuth's
     * performTokenRequest entirely, which behaves differently on some devices.
     */
    private fun exchangeCodeForToken(
        activity: Activity,
        server: McpServer,
        callback: OAuthCallback,
        code: String,
        codeVerifier: String,
        redirectUri: String
    ) {
        val oauth = server.oauth
        val params = linkedMapOf(
            "grant_type" to "authorization_code",
            "code" to code,
            "redirect_uri" to redirectUri,
            "client_id" to oauth.clientId,
            "code_verifier" to codeVerifier
        )
        val basicAuth = applyExtraTokenParams(params, oauth)
        val result = postTokenForm(oauth.tokenEndpoint, params, basicAuth)
        if (result == null) {
            activity.runOnUiThread { callback.onError(Fa.MCP_OAUTH_NETWORK_ERROR) }
            return
        }
        if (result.status !in 200..299) {
            activity.runOnUiThread { callback.onError(tokenErrorText(result)) }
            return
        }
        val token = parseTokenResponse(result.body)
        if (token == null) {
            activity.runOnUiThread { callback.onError("Token exchange failed: invalid response") }
            return
        }
        val accessToken = token.accessToken ?: ""
        val refreshToken = token.refreshToken ?: ""
        server.oauth.encryptedAccessToken = if (accessToken.isNotEmpty()) SecureStore.encrypt(accessToken) else ""
        server.oauth.encryptedRefreshToken = if (refreshToken.isNotEmpty()) SecureStore.encrypt(refreshToken) else ""
        server.oauth.tokenExpiry = token.expiresAt ?: 0L
        // Persist tokens immediately to prefs so connectAll() sees them
        persistOAuthTokens(server)
        activity.runOnUiThread { callback.onSuccess(accessToken, refreshToken, token.idToken) }
    }

    fun handleAuthorizationResponse(
        intent: Intent,
        server: McpServer,
        callback: OAuthCallback
    ) {
        val authResponse = AuthorizationResponse.fromIntent(intent)
        val authException = AuthorizationException.fromIntent(intent)
        if (authResponse == null || authException != null) {
            callback.onError(authException?.error ?: Fa.MCP_AUTH_FAILED)
            return
        }
        val tokenRequest = authResponse.createTokenExchangeRequest()
        authService.performTokenRequest(tokenRequest,
            AuthorizationService.TokenResponseCallback { response, ex ->
                if (response != null) {
                    val accessToken = response.accessToken ?: ""
                    val refreshToken = response.refreshToken ?: ""
                    val encryptedAccess = if (accessToken.isNotEmpty()) SecureStore.encrypt(accessToken) else ""
                    val encryptedRefresh = if (refreshToken.isNotEmpty()) SecureStore.encrypt(refreshToken) else ""
                    server.oauth.encryptedAccessToken = encryptedAccess
                    server.oauth.encryptedRefreshToken = encryptedRefresh
                    server.oauth.tokenExpiry = response.accessTokenExpirationTime ?: 0L
                    callback.onSuccess(accessToken, refreshToken, response.idToken)
                } else {
                    callback.onError(ex?.message ?: "Token exchange failed")
                }
            })
    }

    fun refreshToken(server: McpServer, callback: OAuthCallback) {
        val oauth = server.oauth
        if (oauth.encryptedRefreshToken.isEmpty()) {
            callback.onError("No refresh token available")
            return
        }
        val refreshToken = try { SecureStore.decrypt(oauth.encryptedRefreshToken) } catch (_: Exception) {
            callback.onError("Failed to decrypt refresh token"); return
        }
        if (refreshToken.isEmpty()) {
            callback.onError("Refresh token is empty")
            return
        }
        val params = linkedMapOf(
            "grant_type" to "refresh_token",
            "refresh_token" to refreshToken,
            "client_id" to oauth.clientId
        )
        val basicAuth = applyExtraTokenParams(params, oauth)
        val result = postTokenForm(oauth.tokenEndpoint, params, basicAuth)
        if (result == null) {
            callback.onError(Fa.MCP_OAUTH_NETWORK_ERROR)
            return
        }
        if (result.status !in 200..299) {
            callback.onError(tokenErrorText(result))
            return
        }
        val token = parseTokenResponse(result.body)
        if (token == null) {
            callback.onError("Token refresh failed: invalid response")
            return
        }
        val newAccess = token.accessToken ?: ""
        val newRefresh = token.refreshToken ?: refreshToken
        server.oauth.encryptedAccessToken = if (newAccess.isNotEmpty()) SecureStore.encrypt(newAccess) else ""
        server.oauth.encryptedRefreshToken = if (newRefresh.isNotEmpty()) SecureStore.encrypt(newRefresh) else ""
        server.oauth.tokenExpiry = token.expiresAt ?: 0L
        persistOAuthTokens(server)
        callback.onSuccess(newAccess, newRefresh, token.idToken)
    }

    fun getAccessToken(server: McpServer): String? {
        val oauth = server.oauth
        if (oauth.encryptedAccessToken.isEmpty()) return null
        return try {
            val token = SecureStore.decrypt(oauth.encryptedAccessToken)
            if (token.isEmpty()) null else token
        } catch (_: Exception) { null }
    }

    fun clearTokens(server: McpServer) {
        server.oauth.encryptedAccessToken = ""
        server.oauth.encryptedRefreshToken = ""
        server.oauth.tokenExpiry = 0L
    }

    /** Abort any pending loopback callback without notifying (called from dispose). */
    fun abortPendingLoopback() {
        pendingLoopbackCallback = null
        pendingLoopbackActivity = null
        loopbackServer?.stop()
        loopbackServer = null
    }

    /**
     * Cancel a pending loopback flow and report cancellation. Mirrors
     * mobile-agent's AppState handling: if the user's browser returns to the
     * app without the callback having been received, treat the flow as
     * canceled (called from SettingsActivity.onResume).
     */
    fun cancelPendingLoopback() {
        val cb = pendingLoopbackCallback
        val act = pendingLoopbackActivity
        pendingLoopbackCallback = null
        pendingLoopbackActivity = null
        loopbackServer?.stop()
        loopbackServer = null
        cb?.let {
            act?.runOnUiThread { it.onCancel() }
        }
    }

    fun dispose() {
        abortPendingLoopback()
        authService.dispose()
    }

    // =====================================================================
    // Discovery internals
    // =====================================================================

    private fun probeChallenge(endpointUrl: String): String? {
        val probes = listOf(
            """{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"${McpClient.MCP_PROTOCOL_VERSION}","capabilities":{},"clientInfo":{"name":"Vega Agent","version":"1.0"}}}""",
            """{"jsonrpc":"2.0","id":1,"method":"tools/list"}"""
        )
        for (payload in probes) {
            val res = httpRequest("POST", endpointUrl, body = payload) ?: continue
            val challenges = res.headers["www-authenticate"].orEmpty().joinToString(", ")
            extractResourceMetadata(challenges)?.let { return it }
        }
        return null
    }

    private fun extractResourceMetadata(challenges: String): String? {
        if (challenges.isBlankJava()) return null
        val quoted = Regex("resource_metadata\\s*=\\s*\"([^\"]+)\"")
        val match = quoted.find(challenges)
        if (match != null) return match.groupValues[1]
        val bare = Regex("resource_metadata\\s*=\\s*([^\",\\s]+)")
        return bare.find(challenges)?.groupValues?.getOrNull(1)
    }

    private fun protectedResourceViaWellKnown(endpointUrl: String): List<String> {
        val origin = originOf(endpointUrl)
        val base = endpointUrl.trimEnd('/')
        val candidates = mutableListOf<String>()
        if (origin != null) candidates.add("$origin/.well-known/oauth-protected-resource")
        candidates.add("$base/.well-known/oauth-protected-resource")
        for (candidate in candidates.distinct()) {
            val res = httpRequest("GET", candidate) ?: continue
            if (res.status !in 200..299) continue
            if (parseAuthorizationServers(res.body).isNotEmpty()) return candidates
        }
        return emptyList()
    }

    private fun parseAuthorizationServers(jsonStr: String): List<String> {
        val out = mutableListOf<String>()
        try {
            val obj = JSONObject(jsonStr)
            val arr = obj.optJSONArray("authorization_servers")
            if (arr != null) {
                for (i in 0 until arr.length()) {
                    val s = arr.optString(i, "")
                    if (s.isNotEmpty()) out.add(s)
                }
            } else {
                val single = obj.optString("authorization_server", "")
                val aliased = obj.optString("authorizationServer", "")
                val chosen = if (single.isNotEmpty()) single else aliased
                if (chosen.isNotEmpty()) out.add(chosen)
            }
        } catch (_: Exception) {}
        return out
    }

    private fun authorizationServerMetadataCandidates(authServerUrl: String): List<String> {
        val origin = originOf(authServerUrl)
        val base = authServerUrl.trimEnd('/')
        val path = try { URL(authServerUrl).path.trim('/') } catch (_: Exception) { "" }
        val candidates = mutableListOf<String>()
        if (origin != null) {
            if (path.isNotEmpty()) candidates.add("$origin/.well-known/oauth-authorization-server/$path")
            candidates.add("$origin/.well-known/oauth-authorization-server")
            candidates.add("$origin/.well-known/openid-configuration")
        }
        candidates.add("$base/.well-known/oauth-authorization-server")
        candidates.add("$base/.well-known/openid-configuration")
        return candidates.distinct()
    }

    private fun enrichScopes(authServerUrl: String, meta: DiscoveryResult): DiscoveryResult {
        if (meta.scopesSupported.isNotEmpty()) return meta
        val origin = originOf(authServerUrl)
        val base = authServerUrl.trimEnd('/')
        val candidates = mutableListOf<String>()
        if (origin != null) candidates.add("$origin/.well-known/openid-configuration")
        candidates.add("$base/.well-known/openid-configuration")
        for (candidate in candidates.distinct()) {
            val res = httpRequest("GET", candidate) ?: continue
            if (res.status !in 200..299) continue
            val oidc = parseServerMetadata(res.body) ?: continue
            if (oidc.scopesSupported.isNotEmpty()) {
                return meta.copy(scopesSupported = oidc.scopesSupported)
            }
        }
        return meta
    }

    private fun parseServerMetadata(jsonStr: String): DiscoveryResult? {
        return try {
            val obj = JSONObject(jsonStr)
            val authEp = obj.optString("authorization_endpoint", "")
            val tokenEp = obj.optString("token_endpoint", "")
            if (authEp.isEmpty() || tokenEp.isEmpty()) return null
            DiscoveryResult(
                authorizationEndpoint = authEp,
                tokenEndpoint = tokenEp,
                registrationEndpoint = obj.optString("registration_endpoint", ""),
                issuer = obj.optString("issuer", ""),
                scopesSupported = stringArray(obj, "scopes_supported"),
                tokenEndpointAuthMethodsSupported = stringArray(obj, "token_endpoint_auth_methods_supported")
            )
        } catch (_: Exception) { null }
    }

    private fun stringArray(obj: JSONObject, key: String): List<String> {
        val out = mutableListOf<String>()
        val arr = obj.optJSONArray(key)
        if (arr == null) return out
        for (i in 0 until arr.length()) {
            val s = arr.optString(i, "")
            if (s.isNotEmpty()) out.add(s)
        }
        return out
    }

    private fun preferClientAuth(methods: List<String>): String = when {
        methods.any { it == "client_secret_post" } -> "client_secret_post"
        methods.any { it == "client_secret_basic" } -> "client_secret_basic"
        else -> "none"
    }

    private fun persistDiscovery(server: McpServer) {
        try {
            val manager = McpManager(context)
            manager.loadServers()
            val stored = manager.getServer(server.id) ?: return
            val from = server.oauth
            val to = stored.oauth
            to.clientId = from.clientId
            to.authorizationEndpoint = from.authorizationEndpoint
            to.tokenEndpoint = from.tokenEndpoint
            to.tokenEndpointAuthMethod = from.tokenEndpointAuthMethod
            to.encryptedClientSecret = from.encryptedClientSecret
            to.resourceUrl = from.resourceUrl
            if (from.scopes.isNotEmpty()) to.scopes = from.scopes
            manager.saveServers()
        } catch (_: Exception) {}
    }

    /**
     * Persist OAuth tokens to prefs. Called after token exchange succeeds.
     */
    private fun persistOAuthTokens(server: McpServer) {
        try {
            val manager = McpManager(context)
            manager.loadServers()
            val stored = manager.getServer(server.id) ?: return
            stored.oauth.encryptedAccessToken = server.oauth.encryptedAccessToken
            stored.oauth.encryptedRefreshToken = server.oauth.encryptedRefreshToken
            stored.oauth.tokenExpiry = server.oauth.tokenExpiry
            stored.oauth.resourceUrl = server.oauth.resourceUrl
            manager.saveServers()
        } catch (_: Exception) {}
    }

    // =====================================================================
    // PKCE helpers
    // =====================================================================

    private fun generateCodeVerifier(): String {
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }

    private fun codeChallengeFor(verifier: String): String {
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray(Charsets.UTF_8))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
    }

    private fun generateState(): String {
        val bytes = ByteArray(16)
        SecureRandom().nextBytes(bytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }

    /**
     * Build the OAuth 2.0 authorization URL manually (same as AppAuth does
     * internally) so we can open it directly in a Custom Tab without going
     * through performAuthorizationRequest — required for loopback callbacks.
     */
    private fun buildAuthorizationUrl(oauth: OAuthConfig, codeVerifier: String, state: String): String {
        val challenge = codeChallengeFor(codeVerifier)
        val scope = oauth.scopes.joinToString(" ")
        val base = oauth.authorizationEndpoint
        val query = StringBuilder()
            .append("response_type=code")
            .append("&client_id=").append(oauth.clientId)
            .append("&redirect_uri=").append(oauth.redirectUri)
            .append("&scope=").append(scope)
            .append("&code_challenge=").append(challenge)
            .append("&code_challenge_method=S256")
            .append("&state=").append(state)
        if (!oauth.resourceUrl.isNullOrBlankJava()) {
            query.append("&resource=").append(oauth.resourceUrl)
        }
        return if (base.contains('?')) "$base&$query" else "$base?$query"
    }

    // =====================================================================
    // HTTP helpers
    // =====================================================================

    private class HttpResult(
        val status: Int,
        val headers: Map<String, List<String>>,
        val body: String
    )

    private fun httpRequest(
        method: String,
        urlStr: String,
        body: String? = null,
        accept: String = "application/json",
        contentType: String? = "application/json"
    ): HttpResult? {
        return try {
            val conn = (URL(urlStr).openConnection() as HttpURLConnection).apply {
                requestMethod = method
                connectTimeout = 10000
                readTimeout = 10000
                instanceFollowRedirects = false
                setRequestProperty("Accept", accept)
                if (contentType != null) setRequestProperty("Content-Type", contentType)
                if (body != null) {
                    doOutput = true
                    OutputStreamWriter(outputStream).use { it.write(body) }
                }
            }
            val status = conn.responseCode
            val headers = LinkedHashMap<String, MutableList<String>>()
            for ((key, values) in conn.headerFields) {
                if (key == null) continue
                val k = key.lowercase()
                val list = headers.getOrPut(k) { mutableListOf() }
                if (values != null) list.addAll(values)
            }
            val text = readAll(if (status >= 400) conn.errorStream else conn.inputStream)
            conn.disconnect()
            Log.d(TAG, "[$method $urlStr] -> $status")
            HttpResult(status, headers, text)
        } catch (e: Exception) {
            Log.d(TAG, "[$method $urlStr] failed: ${e.message}")
            null
        }
    }

    private fun readAll(stream: java.io.InputStream?): String {
        if (stream == null) return ""
        return try {
            BufferedReader(InputStreamReader(stream)).use { reader ->
                val sb = StringBuilder()
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    sb.append(line)
                }
                sb.toString()
            }
        } catch (_: Exception) { "" }
    }

    // =====================================================================
    // Direct token-endpoint POST (mobile-agent / exchangeCodeAsync style).
    // =====================================================================

    private class TokenHttpResult(
        val status: Int,
        val body: String
    )

    /**
     * Form-encoded POST to the token endpoint, exactly like the plain fetch
     * mobile-agent's `exchangeCodeAsync` performs. Returns null when the
     * connection itself fails (DNS, refused, cleartext/TLS, timeout — i.e.
     * what AppAuth reports as NETWORK_ERROR). HTTP status + body are returned
     * so the caller can surface the server's error_description.
     */
    private fun postTokenForm(
        urlStr: String,
        params: Map<String, String>,
        basicClientAuth: String? = null
    ): TokenHttpResult? {
        return try {
            val body = params.entries.joinToString("&") { (k, v) ->
                "${URLEncoder.encode(k, "UTF-8")}=${URLEncoder.encode(v, "UTF-8")}"
            }
            val bodyBytes = body.toByteArray(Charsets.UTF_8)
            val conn = (URL(urlStr).openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = 20000
                readTimeout = 30000
                doOutput = true
                setFixedLengthStreamingMode(bodyBytes.size)
                setRequestProperty("Accept", "application/json")
                setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
                if (basicClientAuth != null) {
                    val cred = Base64.getEncoder().encodeToString(basicClientAuth.toByteArray(Charsets.UTF_8))
                    setRequestProperty("Authorization", "Basic $cred")
                }
            }
            conn.outputStream.use { it.write(bodyBytes) }
            val status = conn.responseCode
            val text = readAll(if (status >= 400) conn.errorStream else conn.inputStream)
            conn.disconnect()
            Log.d(TAG, "POST $urlStr -> $status")
            TokenHttpResult(status, text)
        } catch (e: Exception) {
            Log.d(TAG, "POST $urlStr failed: ${e.message}")
            null
        }
    }

    private fun applyExtraTokenParams(params: MutableMap<String, String>, oauth: OAuthConfig): String? {
        if (oauth.resourceUrl.isNotEmpty()) {
            params["resource"] = oauth.resourceUrl
        }
        val secret = runCatching { SecureStore.decrypt(oauth.encryptedClientSecret) }.getOrNull() ?: ""
        if (secret.isEmpty()) return null
        return if (oauth.tokenEndpointAuthMethod == "client_secret_basic") {
            "${oauth.clientId}:$secret"
        } else {
            params["client_secret"] = secret
            null
        }
    }

    private class TokenResponse(
        val accessToken: String?,
        val refreshToken: String?,
        val idToken: String?,
        val expiresAt: Long?
    )

    private fun parseTokenResponse(body: String): TokenResponse? {
        return try {
            val obj = JSONObject(body)
            val access = obj.optString("access_token", "")
            if (access.isEmpty()) return null
            val expiresIn = obj.optLong("expires_in", 0L)
            val expiresAt = if (expiresIn > 0L) System.currentTimeMillis() + expiresIn * 1000L else 0L
            TokenResponse(
                accessToken = access,
                refreshToken = obj.optString("refresh_token", "").ifEmpty { null },
                idToken = obj.optString("id_token", "").ifEmpty { null },
                expiresAt = expiresAt
            )
        } catch (_: Exception) { null }
    }

    private fun tokenErrorText(result: TokenHttpResult): String {
        if (result.status == 429) return Fa.MCP_OAUTH_429_MESSAGE.format("30")
        val oauthErr = try {
            val obj = JSONObject(result.body)
            val err = obj.optString("error", "")
            val desc = obj.optString("error_description", "")
            when {
                err.isEmpty() && desc.isEmpty() -> null
                desc.isEmpty() -> err
                err.isEmpty() -> desc
                else -> "$err: $desc"
            }
        } catch (_: Exception) { null }
        if (oauthErr != null) return oauthErr
        val trimmed = result.body.trimJava()
        return when {
            trimmed.isEmpty() -> "Token endpoint error (HTTP ${result.status})"
            trimmed.length <= 120 -> trimmed
            else -> trimmed.take(120) + "…"
        }
    }

    private fun originOf(urlStr: String): String? {
        return try {
            val u = URL(urlStr)
            val port = u.port
            val defaultPort = if (u.protocol.equals("https", true)) 443
                else if (u.protocol.equals("http", true)) 80 else -1
            val suffix = if (port != -1 && port != defaultPort) ":$port" else ""
            "${u.protocol.lowercase()}://${u.host}$suffix"
        } catch (_: Exception) { null }
    }

    class McpOAuthRateLimitException(val retryAfterSeconds: Long) : Exception(
        "Rate limited: retry after ${retryAfterSeconds}s"
    )

    companion object {
        const val PENDING_INTENT_REQUEST_CODE = 10001
        const val MCP_OAUTH_SERVER_ID_KEY = "mcp_oauth_server_id"
        const val MCP_OAUTH_STATE_KEY = "mcp_oauth_state"
        const val MCP_OAUTH_CODE_VERIFIER_KEY = "mcp_oauth_code_verifier"
        private const val TAG = "McpOAuth"
    }
}
