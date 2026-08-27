package com.vepro.code

import android.content.Context
import android.os.Handler
import android.os.Looper
import org.json.JSONObject
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors

/**
 * Manages multiple MCP server connections and aggregates their tools.
 *
 * Responsibilities:
 *  - Store/retrieve server configurations via Prefs
 *  - Connect to servers, discover tools, cache results
 *  - Route tool calls to the correct server
 *  - Handle OAuth token refresh before calls
 *  - Thread-safe: all network ops run on a dedicated ExecutorService
 *
 * Usage:
 *   val manager = McpManager(context)
 *   manager.connectAll()                          // connect all enabled servers
 *   val tools = manager.allTools()                // aggregated tool list
 *   val result = manager.callTool("make:create_scenario", args)  // dispatch
 *   manager.disconnectAll()                       // cleanup
 */
class McpManager(private val context: Context) {

    private val prefs = Prefs(context)
    private val mainHandler = Handler(Looper.getMainLooper())
    private val executor = Executors.newFixedThreadPool(2)

    /** Active client per server id. */
    private val clients = ConcurrentHashMap<String, McpClient>()

    /** Cached server configs. */
    private val servers = mutableListOf<McpServer>()

    /** Cached aggregated tools. */
    private var toolsCache = mutableListOf<McpTool>()

    /** Status listener for UI updates. */
    var onStatusChanged: (() -> Unit)? = null

    // ── Server persistence ────────────────────────────────────────────

    /**
     * Load all MCP servers from preferences.
     */
    fun loadServers(): List<McpServer> {
        servers.clear()
        val json = prefs.str("mcp_servers", "")
        if (json.isNotEmpty()) {
            try {
                val arr = org.json.JSONArray(json)
                for (i in 0 until arr.length()) {
                    val obj = arr.getJSONObject(i)
                    servers.add(McpServer.fromJsonObject(obj))
                }
            } catch (_: Exception) {
                // Corrupted data, start fresh
            }
        }
        return servers.toList()
    }

    /**
     * Save all MCP servers to preferences.
     */
    fun saveServers() {
        val arr = org.json.JSONArray()
        for (server in servers) {
            arr.put(server.toJsonObject())
        }
        prefs.save("mcp_servers", arr.toString())
    }

    /**
     * Add a new server and save.
     */
    fun addServer(server: McpServer) {
        servers.add(server)
        saveServers()
    }

    /**
     * Remove a server by id, disconnect it, and save.
     */
    fun removeServer(serverId: String) {
        val server = servers.find { it.id == serverId } ?: return
        disconnectServer(server)
        servers.removeAll { it.id == serverId }
        saveServers()
        rebuildToolsCache()
        notifyStatusChanged()
    }

    /**
     * Get a server by id.
     */
    fun getServer(serverId: String): McpServer? = servers.find { it.id == serverId }

    /**
     * Get all servers.
     */
    fun getAllServers(): List<McpServer> = servers.toList()

    // ── Connection management ──────────────────────────────────────────

    /**
     * Connect to all enabled servers in parallel.
     * Runs on background thread; updates UI on main thread.
     */
    fun connectAll(onDone: (() -> Unit)? = null) {
        executor.execute {
            val enabled = servers.filter { it.enabled }
            for (server in enabled) {
                try {
                    connectServer(server)
                } catch (e: Exception) {
                    server.lastError = e.message?.take(100) ?: "Connection failed"
                    if (false) {
                        android.util.Log.e("McpManager", "Connect failed: ${server.label}", e)
                    }
                }
            }
            rebuildToolsCache()
            mainHandler.post {
                notifyStatusChanged()
                onDone?.invoke()
            }
        }
    }

    /**
     * Connect a single server. Blocking — must be called from background thread.
     */
    private fun connectServer(server: McpServer) {
        // OAuth servers without tokens need authorization first — skip silently;
        // the UI will offer an "Authorize" button.
        if (server.authType == McpServer.AUTH_OAUTH2 && !server.oauth.hasTokens) {
            server.lastError = "OAuth authorization required"
            return
        }

        // Refresh OAuth token if expired before connecting
        if (server.authType == McpServer.AUTH_OAUTH2 && server.oauth.isExpired) {
            refreshOAuthToken(server)
        }

        // Resolve bearer token
        val bearerToken = resolveBearerToken(server)

        // Create client
        val client = McpClient(
            serverUrl = server.url,
            bearerToken = bearerToken,
            timeoutMs = 30_000
        )

        // Initialize
        client.initialize()
        if (false) {
            android.util.Log.d("McpManager", "Initialized: ${server.label}")
        }

        // Discover tools
        val tools = client.toolsList()
        val prefix = server.toolPrefix
        val namedTools = tools.map { tool ->
            tool.copy(
                fullName = "${prefix}${tool.name}",
                serverId = server.id
            )
        }

        server.cachedTools = namedTools
        server.lastError = ""
        clients[server.id] = client

        if (false) {
            android.util.Log.d(
                "McpManager",
                "Tools for ${server.label}: ${namedTools.joinToString { it.name }}"
            )
        }
    }

    /**
     * Disconnect a single server.
     */
    fun disconnectServer(server: McpServer) {
        val client = clients.remove(server.id)
        client?.disconnect()
        server.cachedTools = emptyList()
    }

    /**
     * Disconnect all servers.
     */
    fun disconnectAll() {
        for ((id, client) in clients) {
            client.disconnect()
        }
        clients.clear()
        for (server in servers) {
            server.cachedTools = emptyList()
        }
    }

    // ── Tool dispatch ──────────────────────────────────────────────────

    /**
     * Get all tools from all connected servers, with prefixed names.
     */
    fun allTools(): List<McpTool> = toolsCache.toList()

    /**
     * Rebuild the aggregated tools cache from all connected servers.
     */
    private fun rebuildToolsCache() {
        toolsCache.clear()
        for (server in servers.filter { it.enabled && it.lastError.isEmpty() }) {
            toolsCache.addAll(server.cachedTools)
        }
    }

    /**
     * Check if a tool name belongs to an MCP server.
     */
    fun isMcpTool(toolName: String): Boolean {
        return toolsCache.any { it.fullName == toolName }
    }

    /**
     * Find the server that owns a given tool.
     */
    private fun findServerForTool(toolName: String): McpServer? {
        val tool = toolsCache.find { it.fullName == toolName } ?: return null
        return servers.find { it.id == tool.serverId }
    }

    /**
     * Call an MCP tool. Blocking — must be called from background thread.
     *
     * @param toolName Full prefixed tool name (e.g. "make:create_scenario").
     * @param arguments Tool arguments as a JSON object.
     * @return Tool result as a JSON object.
     * @throws McpException if the call fails.
     */
    fun callTool(toolName: String, arguments: JSONObject): JSONObject {
        val server = findServerForTool(toolName)
            ?: throw McpException("No MCP server found for tool: $toolName")

        val client = clients[server.id]
            ?: throw McpException("Server not connected: ${server.label}")

        // Extract original tool name (without prefix)
        val originalName = toolName.removePrefix(server.toolPrefix)

        // Refresh OAuth token if needed and available
        if (server.authType == McpServer.AUTH_OAUTH2 && server.oauth.isExpired) {
            refreshOAuthToken(server)
        }

        return client.toolsCall(originalName, arguments)
    }

    /**
     * Call an MCP tool asynchronously, posting result to main thread.
     */
    fun callToolAsync(
        toolName: String,
        arguments: JSONObject,
        onResult: (JSONObject) -> Unit,
        onError: (String) -> Unit
    ) {
        executor.execute {
            try {
                val result = callTool(toolName, arguments)
                mainHandler.post { onResult(result) }
            } catch (e: Exception) {
                val msg = e.message ?: "Tool call failed"
                mainHandler.post { onError(msg) }
            }
        }
    }

    // ── OAuth helpers ──────────────────────────────────────────────────

    /**
     * Resolve the bearer token for a server's auth configuration.
     */
    private fun resolveBearerToken(server: McpServer): String? {
        return when (server.authType) {
            McpServer.AUTH_NONE -> null
            McpServer.AUTH_API_KEY -> {
                if (server.encryptedApiKey.isEmpty()) null
                else try {
                    SecureStore.decrypt(server.encryptedApiKey)
                } catch (_: Exception) {
                    null
                }
            }
            McpServer.AUTH_OAUTH2 -> {
                val oauthManager = McpOAuthManager(context)
                oauthManager.getAccessToken(server)
            }
            else -> null
        }
    }

    /**
     * Refresh the OAuth token for a server. Blocking.
     */
    private fun refreshOAuthToken(server: McpServer) {
        val oauthManager = McpOAuthManager(context)
        val latch = java.util.concurrent.CountDownLatch(1)
        var refreshError: String? = null

        oauthManager.refreshToken(server, object : McpOAuthManager.OAuthCallback {
            override fun onSuccess(accessToken: String, refreshToken: String?, idToken: String?) {
                latch.countDown()
            }
            override fun onError(error: String) {
                refreshError = error
                server.lastError = "Token refresh failed: $error"
                latch.countDown()
            }
            override fun onCancel() {
                refreshError = "Token refresh cancelled"
                latch.countDown()
            }
        })

        latch.await(30, java.util.concurrent.TimeUnit.SECONDS)
        oauthManager.dispose()

        if (refreshError != null) {
            throw McpException(refreshError ?: "OAuth token refresh failed")
        }
    }

    /**
     * Store an API key for a server, encrypted.
     */
    fun storeApiKey(server: McpServer, apiKey: String) {
        server.encryptedApiKey = SecureStore.encrypt(apiKey)
        saveServers()
    }

    /**
     * Get the decrypted API key for a server.
     */
    fun getApiKey(server: McpServer): String {
        if (server.encryptedApiKey.isEmpty()) return ""
        return try {
            SecureStore.decrypt(server.encryptedApiKey)
        } catch (_: Exception) {
            ""
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────

    private fun notifyStatusChanged() {
        mainHandler.post { onStatusChanged?.invoke() }
    }

    /**
     * Build MCP tool JSON definitions for the agent's tool list.
     * Returns an array of tool definition JSONObjects.
     */
    fun buildToolDefinitions(): List<JSONObject> {
        val defs = mutableListOf<JSONObject>()
        for (tool in toolsCache) {
            val params = try {
                JSONObject(tool.inputSchema)
            } catch (_: Exception) {
                JSONObject()
            }
            defs.add(Tools.toolJsonDef(tool.fullName, tool.description, params.toString()))
        }
        return defs
    }

    /**
     * Format an MCP tool call result for the agent's tool output.
     * The agent expects a JSONObject with an "output" string field.
     */
    fun formatToolResult(result: JSONObject): JSONObject {
        val output = JSONObject()

        // Extract text content from MCP response
        val content = result.optJSONArray("content")
        if (content != null && content.length() > 0) {
            val texts = mutableListOf<String>()
            for (i in 0 until content.length()) {
                val block = content.getJSONObject(i)
                if (block.optString("type") == "text") {
                    texts.add(block.optString("text", ""))
                }
            }
            output.put("output", texts.joinToString("\n\n"))
        } else {
            output.put("output", result.toString())
        }

        return output
    }
}
