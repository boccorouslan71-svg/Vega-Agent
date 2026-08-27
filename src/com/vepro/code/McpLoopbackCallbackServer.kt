package com.vepro.code

import android.util.Log
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStream
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URL
import java.net.URLDecoder
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Minimal HTTP loopback callback server for MCP OAuth 2.0 PKCE flows.
 *
 * Binds to 127.0.0.1:2083, handles GET /mcp/oauth/callback, returns HTML
 * page with auto-close script. Implements the approach from the MCP
 * Authorization spec draft.
 */
class McpLoopbackCallbackServer(
    private val timeoutMs: Long = 5 * 60_000L,
    private val expectedState: String? = null,
    private val onResult: (code: String?, state: String?, error: String?) -> Unit
) {
    private var serverSocket: ServerSocket? = null
    private val aborted = AtomicBoolean(false)
    private val latch = CountDownLatch(1)

    companion object {
        const val LOOPBACK_PORT = 2083
        const val CALLBACK_PATH = "/mcp/oauth/callback"
        const val LOOPBACK_URL = "http://127.0.0.1:$LOOPBACK_PORT$CALLBACK_PATH"
        private const val TAG = "McpLoopback"
    }

    /** Start listening on localhost. Must call [stop] when done. */
    fun start() {
        Thread({
            try {
                serverSocket = ServerSocket(LOOPBACK_PORT, 1, InetAddress.getByName("127.0.0.1"))
                Log.d(TAG, "Loopback listening on $LOOPBACK_URL")
                val conn = serverSocket?.accept() ?: return@Thread
                try {
                    if (aborted.get()) return@Thread
                    conn.inputStream.use { inp ->
                        BufferedReader(InputStreamReader(inp)).use { reader ->
                            val requestLine = reader.readLine() ?: return@use
                            Log.d(TAG, "Request: $requestLine")
                            val parts = requestLine.split(" ")
                            val fullPath = if (parts.size >= 2) parts[1] else ""
                            val qPos = fullPath.indexOf('?')
                            val path = if (qPos >= 0) fullPath.substring(0, qPos) else fullPath
                            val query = if (qPos >= 0) fullPath.substring(qPos + 1) else ""
                            if (path != CALLBACK_PATH) {
                                sendHtml(conn, 400, "Bad path")
                                onResult(null, null, "Unknown callback path")
                                return@use
                            }
                            val params = parseQuery(query)
                            val code = params["code"]
                            val state = params["state"]
                            val error = params["error"]
                            if (expectedState != null && state != expectedState) {
                                sendHtml(conn, 400, "State mismatch")
                                onResult(null, null, "State mismatch")
                                return@use
                            }
                            if (error != null) {
                                val desc = params["error_description"] ?: ""
                                sendHtml(conn, 400, "Auth error")
                                onResult(null, null, "$error: $desc")
                                return@use
                            }
                            if (code.isNullOrEmpty()) {
                                sendHtml(conn, 400, "No code")
                                onResult(null, null, "No authorization code")
                                return@use
                            }
                            Log.d(TAG, "Got code, sending success page")
                            sendHtml(conn, 200, buildConnectedPage())
                            onResult(code, state, null)
                        }
                    }
                } finally {
                    try { conn.close() } catch (_: Exception) {}
                }
            } catch (e: Exception) {
                Log.e(TAG, "Loopback error: ${e.message}")
                onResult(null, null, "Server error: ${e.message}")
            } finally {
                latch.countDown()
                stop()
            }
        }, "mcp-loopback").apply { isDaemon = true; start() }
    }

    fun await(): Boolean {
        try { return latch.await(timeoutMs, TimeUnit.MILLISECONDS) }
        catch (_: InterruptedException) { Thread.currentThread().interrupt(); return false }
    }

    fun stop() {
        aborted.set(true)
        latch.countDown()
        try { serverSocket?.close() } catch (_: Exception) {}
        serverSocket = null
    }

    private fun sendHtml(conn: Socket, status: Int, bodyText: String) {
        try {
            val statusText = when (status) {
                200 -> "OK"
                400 -> "Bad Request"
                499 -> "Canceled"
                else -> "Error"
            }
            val bodyBytes = bodyText.toByteArray(Charsets.UTF_8)
            val sb = StringBuilder()
            sb.append("HTTP/1.1 $status $statusText\r\n")
            sb.append("Content-Type: text/html; charset=utf-8\r\n")
            sb.append("Content-Length: ${bodyBytes.size}\r\n")
            sb.append("Connection: close\r\n")
            sb.append("\r\n")
            val out: OutputStream = conn.outputStream
            out.write(sb.toString().toByteArray(Charsets.US_ASCII))
            out.write(bodyBytes)
            out.flush()
        } catch (_: Exception) {}
    }

    private fun parseQuery(query: String): Map<String, String> {
        val map = mutableMapOf<String, String>()
        if (query.isEmpty()) return map
        for (pair in query.split("&")) {
            val eq = pair.indexOf('=')
            val key = URLDecoder.decode(if (eq >= 0) pair.substring(0, eq) else pair)
            val value = if (eq >= 0) URLDecoder.decode(pair.substring(eq + 1)) else ""
            map[key] = value
        }
        return map
    }

    private fun buildConnectedPage(): String {
        return """<!doctype html><html><head><meta name="viewport" content="width=device-width"><title>${Fa.MCP_OAUTH_LOOPBACK_CONNECTED}</title></head>
<body style="font-family:system-ui;padding:32px"><h1>${Fa.MCP_OAUTH_LOOPBACK_CONNECTED}</h1>
<p>You can close this page and return to Vega.</p>
<script>window.setTimeout(function(){window.close();}, 1000);</script>
</body></html>"""
    }
}
