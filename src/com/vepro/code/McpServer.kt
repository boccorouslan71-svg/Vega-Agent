package com.vepro.code

import org.json.JSONObject

/**
 * Configuration for a single MCP (Model Context Protocol) server.
 *
 * Transport: HTTP POST for JSON-RPC 2.0, with optional SSE for server-initiated
 * messages. All communication happens over a single /mcp endpoint.
 *
 * Auth types:
 *  - NONE: no authentication (local servers, public APIs)
 *  - API_KEY: bearer token passed in the Authorization header
 *  - OAUTH2: full OAuth 2.0 with PKCE flow (tokens stored encrypted via SecureStore)
 */
class McpServer(
    /** Unique id (UUID-ish), survives across sessions. */
    val id: String,

    /** User-chosen display label. */
    var label: String,

    /** Base URL of the MCP endpoint (e.g. "https://mcp.example.com/mcp"). */
    var url: String,

    /** Transport protocol. */
    var transport: String = TRANSPORT_HTTP,

    /** Auth type. */
    var authType: String = AUTH_NONE,

    /** API key (only when authType == AUTH_API_KEY). Encrypted at rest via SecureStore. */
    var encryptedApiKey: String = "",

    /** Whether this server is enabled (can be toggled without deleting). */
    var enabled: Boolean = true,

    /** OAuth 2.0 configuration (only when authType == AUTH_OAUTH2). */
    var oauth: OAuthConfig = OAuthConfig(),

    /** Cached tool list from the last tools/list call. Empty until connected. */
    var cachedTools: List<McpTool> = emptyList(),

    /** Last connection error message, if any. */
    var lastError: String = ""
) {

    /** Whether this server has at least one cached tool. */
    val hasTools: Boolean get() = cachedTools.isNotEmpty()

    /** Human-readable status line. */
    val statusText: String
        get() = when {
            !enabled -> Fa.MCP_STATUS_DISABLED
            lastError.isNotEmpty() -> lastError
            hasTools -> Fa.MCP_STATUS_CONNECTED.format(cachedTools.size.toString())
            else -> Fa.MCP_STATUS_NOT_CONNECTED
        }

    /** Tool prefix for the agent: "label:" (e.g. "make:"). */
    val toolPrefix: String
        get() {
            val base = label.trimJava().lowercase()
                .replace(Regex("[^a-z0-9]+"), "_")
                .trim('_')
            return if (base.isNotEmpty()) "$base:" else ""
        }

    fun toJsonObject(): JSONObject {
        val obj = JSONObject()
        obj.put("id", id)
        obj.put("label", label)
        obj.put("url", url)
        obj.put("transport", transport)
        obj.put("authType", authType)
        obj.put("encryptedApiKey", encryptedApiKey)
        obj.put("enabled", enabled)
        obj.put("oauth", oauth.toJsonObject())
        return obj
    }

    companion object {
        const val TRANSPORT_HTTP = "http"
        const val TRANSPORT_SSE = "sse"

        const val AUTH_NONE = "none"
        const val AUTH_API_KEY = "api_key"
        const val AUTH_OAUTH2 = "oauth2"

        fun fromJsonObject(obj: JSONObject): McpServer {
            val server = McpServer(
                id = obj.optString("id", java.util.UUID.randomUUID().toString()),
                label = obj.optString("label", ""),
                url = obj.optString("url", ""),
                transport = obj.optString("transport", TRANSPORT_HTTP),
                authType = obj.optString("authType", AUTH_NONE),
                encryptedApiKey = obj.optString("encryptedApiKey", ""),
                enabled = obj.optBoolean("enabled", true)
            )
            val oauthObj = obj.optJSONObject("oauth")
            if (oauthObj != null) {
                server.oauth = OAuthConfig.fromJsonObject(oauthObj)
            }
            return server
        }

        fun generateId(): String = java.util.UUID.randomUUID().toString()
    }
}

/**
 * OAuth 2.0 configuration for an MCP server.
 */
class OAuthConfig(
    var clientId: String = "",
    var authorizationEndpoint: String = "",
    var tokenEndpoint: String = "",
    /** Loopback redirect_uri by default per MCP spec; deep-link fallback available. */
    var redirectUri: String = LOOPBACK_REDIRECT_URI,
    var scopes: List<String> = listOf("openid", "profile"),
    /** Token endpoint auth method (none / client_secret_post / client_secret_basic). */
    var tokenEndpointAuthMethod: String = "none",
    /** Encrypted client secret, stored via SecureStore (public-client flows keep it empty). */
    var encryptedClientSecret: String = "",
    /** Encrypted refresh token, stored via SecureStore. */
    var encryptedRefreshToken: String = "",
    /** Encrypted access token, stored via SecureStore. */
    var encryptedAccessToken: String = "",
    /** Token expiry timestamp (millis since epoch). 0 = unknown/expired. */
    var tokenExpiry: Long = 0L,
    /** The resource URL this client was registered for, persisted after registration. */
    var resourceUrl: String = "",
    /** Optional strict origin validation override (e.g. "https://www.make.com"). Empty = no override. */
    var allowedOrigin: String = ""
) {
    val hasTokens: Boolean
        get() = encryptedAccessToken.isNotEmpty() || encryptedRefreshToken.isNotEmpty()

    val isExpired: Boolean
        get() = tokenExpiry > 0 && System.currentTimeMillis() >= tokenExpiry - 60_000

    fun toJsonObject(): JSONObject {
        val obj = JSONObject()
        obj.put("clientId", clientId)
        obj.put("authorizationEndpoint", authorizationEndpoint)
        obj.put("tokenEndpoint", tokenEndpoint)
        obj.put("redirectUri", redirectUri)
        val arr = org.json.JSONArray()
        for (s in scopes) {
            arr.put(s)
        }
        obj.put("scopes", arr)
        obj.put("tokenEndpointAuthMethod", tokenEndpointAuthMethod)
        obj.put("encryptedClientSecret", encryptedClientSecret)
        obj.put("encryptedRefreshToken", encryptedRefreshToken)
        obj.put("encryptedAccessToken", encryptedAccessToken)
        obj.put("tokenExpiry", tokenExpiry)
        obj.put("resourceUrl", resourceUrl)
        obj.put("allowedOrigin", allowedOrigin)
        return obj
    }

    companion object {
        /** Loopback redirect_uri per the MCP Authorization spec (RFC draft). */
        const val LOOPBACK_REDIRECT_URI = "http://127.0.0.1:2083/mcp/oauth/callback"
        /** Deep-link fallback for devices that cannot bind loopback. */
        const val DEEPLINK_REDIRECT_URI = "vegaagent://oauth2callback"

        fun fromJsonObject(obj: JSONObject): OAuthConfig {
            val config = OAuthConfig(
                clientId = obj.optString("clientId", ""),
                authorizationEndpoint = obj.optString("authorizationEndpoint", ""),
                tokenEndpoint = obj.optString("tokenEndpoint", ""),
                redirectUri = obj.optString("redirectUri", LOOPBACK_REDIRECT_URI),
                tokenEndpointAuthMethod = obj.optString("tokenEndpointAuthMethod", "none"),
                encryptedClientSecret = obj.optString("encryptedClientSecret", ""),
                encryptedRefreshToken = obj.optString("encryptedRefreshToken", ""),
                encryptedAccessToken = obj.optString("encryptedAccessToken", ""),
                tokenExpiry = obj.optLong("tokenExpiry", 0L),
                resourceUrl = obj.optString("resourceUrl", ""),
                allowedOrigin = obj.optString("allowedOrigin", "")
            )
            val scopesArr = obj.optJSONArray("scopes")
            if (scopesArr != null) {
                val list = mutableListOf<String>()
                for (i in 0 until scopesArr.length()) {
                    val s = scopesArr.optString(i, "")
                    if (s.isNotEmpty()) list.add(s)
                }
                config.scopes = list
            }
            return config
        }
    }
}

/**
 * A tool exposed by an MCP server.
 */
data class McpTool(
    /** Local name: "prefix:toolName" (e.g. "make:create_scenario"). */
    val fullName: String,

    /** Original name from the server (without prefix). */
    val name: String,

    /** Description from the server. */
    val description: String,

    /** JSON Schema for input parameters, as a raw string. */
    val inputSchema: String,

    /** Server id that owns this tool. */
    val serverId: String
)
