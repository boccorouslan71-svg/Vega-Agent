package com.vepro.code

import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

/**
 * Minimal JSON-RPC 2.0 client for the MCP protocol.
 *
 * Transport: HTTP POST to the server's endpoint. Request and response
 * are JSON-RPC 2.0 payloads. The server may also use Server-Sent Events
 * (SSE) for server-initiated notifications, but for the agent loop we
 * only need request/response.
 *
 * Flow:
 *   1. initialize  → get server capabilities + protocol version
 *   2. tools/list  → discover available tools
 *   3. tools/call  → invoke a tool
 *
 * Threading: all network calls are blocking. The caller must run them
 * off the main thread (via launch(Dispatchers.IO) { ... }).
 */
class McpClient(
    /** The MCP server endpoint URL. */
    private val serverUrl: String,
    /** Bearer token for API-key auth, or null. */
    private val bearerToken: String? = null,
    /** Timeout for connect and read, in milliseconds. */
    private val timeoutMs: Int = 30_000
) {
    private var sessionId: String? = null
    private var requestId: Int = 0

    // ── JSON-RPC 2.0 helpers ─────────────────────────────────────────

    private fun nextId(): Int = ++requestId

    private fun jsonRpcRequest(method: String, params: JSONObject? = null): JSONObject {
        val obj = JSONObject()
        obj.put("jsonrpc", "2.0")
        obj.put("id", nextId())
        obj.put("method", method)
        if (params != null) obj.put("params", params)
        return obj
    }

    /**
     * Send a JSON-RPC 2.0 request to the MCP endpoint and return the
     * result field from the response. Throws on error or transport failure.
     */
    private fun sendRequest(
        method: String,
        params: JSONObject? = null,
        includeSessionId: Boolean = true
    ): JSONObject {
        val url = URL(serverUrl)
        val conn = url.openConnection() as HttpURLConnection
        try {
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("Accept", "application/json, text/event-stream")
            conn.connectTimeout = timeoutMs
            conn.readTimeout = timeoutMs

            // API-key auth
            if (!bearerToken.isNullOrEmpty()) {
                conn.setRequestProperty("Authorization", "Bearer $bearerToken")
            }

            // Session ID from previous response
            if (includeSessionId && !sessionId.isNullOrEmpty()) {
                conn.setRequestProperty("Mcp-Session-Id", sessionId)
            }

            val body = jsonRpcRequest(method, params)
            if (BuildConfig.DEBUG) {
                android.util.Log.d("McpClient", ">>> $method ${body.toString(2)}")
            }

            conn.doOutput = true
            val writer = OutputStreamWriter(conn.outputStream, Charsets.UTF_8)
            writer.write(body.toString())
            writer.flush()
            writer.close()

            // Read response
            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val reader = BufferedReader(InputStreamReader(stream, Charsets.UTF_8))
            val rawResponse = reader.readText()
            reader.close()

            // Capture session ID from response headers
            val newSessionId = conn.getHeaderField("Mcp-Session-Id")
            if (!newSessionId.isNullOrEmpty()) {
                sessionId = newSessionId
            }

            if (BuildConfig.DEBUG) {
                android.util.Log.d("McpClient", "<<< $code $rawResponse")
            }

            if (code !in 200..299) {
                throw McpException("HTTP $code: ${rawResponse.take(200)}")
            }

            // The response may be SSE-framed; extract the JSON payload
            val jsonStr = extractJsonFromResponse(rawResponse)
            val respObj = JSONObject(jsonStr)

            // Check for JSON-RPC error
            if (respObj.has("error")) {
                val err = respObj.getJSONObject("error")
                val msg = err.optString("message", "Unknown MCP error")
                val data = err.opt("data")
                throw McpException("JSON-RPC error: $msg ${if (data != null) "($data)" else ""}")
            }

            return respObj.optJSONObject("result") ?: respObj
        } finally {
            conn.disconnect()
        }
    }

    /**
     * If the server responds with SSE framing (data: {...}), extract the
     * last JSON object. If it's plain JSON, return as-is.
     */
    private fun extractJsonFromResponse(raw: String): String {
        val trimmed = raw.trim()
        // Plain JSON response
        if (trimmed.startsWith("{")) return trimmed

        // SSE response: find the last "data: {...}" line
        var lastData: String? = null
        for (line in trimmed.lines()) {
            val l = line.trim()
            if (l.startsWith("data: ")) {
                lastData = l.removePrefix("data: ").trim()
            }
        }
        return lastData ?: throw McpException("No JSON payload in response")
    }

    // ── MCP protocol methods ──────────────────────────────────────────

    /**
     * Step 1: Initialize the connection. Returns server capabilities.
     */
    fun initialize(): JSONObject {
        val params = JSONObject()
        params.put("protocolVersion", MCP_PROTOCOL_VERSION)

        val clientInfo = JSONObject()
        clientInfo.put("name", "Vega-Agent")
        clientInfo.put("version", "1.0.0")
        params.put("clientInfo", clientInfo)

        // Capabilities: we support basic features
        val capabilities = JSONObject()
        params.put("capabilities", capabilities)

        val result = sendRequest("initialize", params, includeSessionId = false)

        // After initialize, send notifications/initialized
        sendInitialized()

        return result
    }

    /**
     * Send the initialized notification (no id, no response expected).
     */
    private fun sendInitialized() {
        val url = URL(serverUrl)
        val conn = url.openConnection() as HttpURLConnection
        try {
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("Accept", "application/json")
            conn.connectTimeout = timeoutMs
            conn.readTimeout = timeoutMs

            if (!bearerToken.isNullOrEmpty()) {
                conn.setRequestProperty("Authorization", "Bearer $bearerToken")
            }
            if (!sessionId.isNullOrEmpty()) {
                conn.setRequestProperty("Mcp-Session-Id", sessionId)
            }

            // Notification: no "id" field
            val notif = JSONObject()
            notif.put("jsonrpc", "2.0")
            notif.put("method", "notifications/initialized")

            conn.doOutput = true
            val writer = OutputStreamWriter(conn.outputStream, Charsets.UTF_8)
            writer.write(notif.toString())
            writer.flush()
            writer.close()

            // Consume response (may be empty or 202)
            conn.responseCode
        } catch (_: Exception) {
            // Notifications are fire-and-forget
        } finally {
            conn.disconnect()
        }
    }

    /**
     * Step 2: List available tools from the server.
     */
    fun toolsList(): List<McpTool> {
        val result = sendRequest("tools/list")
        val toolsArray = result.optJSONArray("tools") ?: return emptyList()

        val tools = mutableListOf<McpTool>()
        for (i in 0 until toolsArray.length()) {
            val toolObj = toolsArray.getJSONObject(i)
            val name = toolObj.getString("name")
            val description = toolObj.optString("description", "")
            val inputSchema = toolObj.optJSONObject("inputSchema")

            tools.add(
                McpTool(
                    fullName = name, // prefix added by McpManager
                    name = name,
                    description = description,
                    inputSchema = inputSchema?.toString() ?: "{}",
                    serverId = "" // set by McpManager
                )
            )
        }
        return tools
    }

    /**
     * Step 3: Call a tool on the server.
     *
     * @param toolName The server's original tool name (without prefix).
     * @param arguments Tool arguments as a JSON object.
     * @return The tool result as a JSONObject with "content" array.
     */
    fun toolsCall(toolName: String, arguments: JSONObject): JSONObject {
        val params = JSONObject()
        params.put("name", toolName)
        params.put("arguments", arguments)

        val result = sendRequest("tools/call", params)
        return result
    }

    // ── Cleanup ───────────────────────────────────────────────────────

    fun disconnect() {
        // Send shutdown notification if possible
        try {
            val url = URL(serverUrl)
            val conn = url.openConnection() as HttpURLConnection
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/json")
            if (!sessionId.isNullOrEmpty()) {
                conn.setRequestProperty("Mcp-Session-Id", sessionId)
            }
            conn.doOutput = true
            val notif = JSONObject()
            notif.put("jsonrpc", "2.0")
            notif.put("method", "notifications/cancelled")
            val writer = OutputStreamWriter(conn.outputStream, Charsets.UTF_8)
            writer.write(notif.toString())
            writer.flush()
            writer.close()
            conn.responseCode
            conn.disconnect()
        } catch (_: Exception) {
            // Best-effort shutdown
        }
        sessionId = null
    }

    companion object {
        /** Current MCP protocol version supported by this client. */
        const val MCP_PROTOCOL_VERSION = "2025-03-26"
    }
}

/**
 * Exception thrown on MCP client errors.
 */
class McpException(message: String) : Exception(message)
