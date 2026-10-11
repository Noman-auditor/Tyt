package com.nora.tunnel.core

import android.net.Uri
import android.util.Base64
import com.nora.tunnel.data.Profile
import org.json.JSONObject

object LinkParser {

    fun parse(link: String): Profile? = try {
        val l = link.trim()
        when {
            l.startsWith("vless://") -> parseUriStyle(l, "vless")
            l.startsWith("trojan://") -> parseUriStyle(l, "trojan")
            l.startsWith("vmess://") -> parseVmess(l)
            l.startsWith("ss://") -> parseSs(l)
            else -> null
        }
    } catch (e: Exception) {
        null
    }

    /** Parses plain text or base64 subscription content into profiles. */
    fun parseSubscription(body: String): List<Profile> {
        val text = if (body.contains("://")) body else decodeB64(body.trim())
        return text.lines().mapNotNull { parse(it) }
    }

    private fun parseUriStyle(link: String, proto: String): Profile? {
        val u = Uri.parse(link)
        val host = u.host ?: return null
        val port = if (u.port > 0) u.port else 443
        val extra = JSONObject()
        for (k in listOf("path", "host", "sni", "flow", "pbk", "sid", "fp", "alpn", "serviceName", "headerType")) {
            u.getQueryParameter(k)?.let { extra.put(k, it) }
        }
        val name = u.fragment?.takeIf { it.isNotBlank() } ?: "$host:$port"
        return Profile(
            name = name, protocol = proto, address = host, port = port,
            secret = u.userInfo ?: "",
            transport = u.getQueryParameter("type") ?: "tcp",
            security = u.getQueryParameter("security") ?: if (proto == "trojan") "tls" else "none",
            extra = extra.toString(), country = CountryUtil.fromName(name), rawLink = link,
        )
    }

    private fun parseVmess(link: String): Profile? {
        val j = JSONObject(decodeB64(link.removePrefix("vmess://")))
        val extra = JSONObject()
        for (k in listOf("path", "host", "sni", "alpn", "fp", "type")) {
            j.optString(k).takeIf { it.isNotBlank() }?.let { extra.put(k, it) }
        }
        val name = j.optString("ps").ifBlank { j.optString("add") }
        return Profile(
            name = name, protocol = "vmess", address = j.getString("add"),
            port = j.get("port").toString().toInt(), secret = j.getString("id"),
            transport = j.optString("net", "tcp"),
            security = j.optString("tls").ifBlank { "none" },
            extra = extra.toString(), country = CountryUtil.fromName(name), rawLink = link,
        )
    }

    private fun parseSs(link: String): Profile? {
        val body = link.removePrefix("ss://")
        val name = body.substringAfter('#', "").let { Uri.decode(it) }
        val main = body.substringBefore('#').substringBefore('?')
        val (userInfo, hostPort) = if (main.contains('@')) {
            val ui = main.substringBeforeLast('@')
            val decoded = if (ui.contains(':')) ui else decodeB64(ui)
            decoded to main.substringAfterLast('@')
        } else {
            val d = decodeB64(main)
            d.substringBeforeLast('@') to d.substringAfterLast('@')
        }
        val method = userInfo.substringBefore(':')
        val password = userInfo.substringAfter(':')
        val host = hostPort.substringBeforeLast(':')
        val port = hostPort.substringAfterLast(':').toInt()
        val extra = JSONObject().put("method", method.ifBlank { "aes-256-gcm" })
        val n = name.ifBlank { "$host:$port" }
        return Profile(
            name = n, protocol = "ss", address = host, port = port, secret = password,
            extra = extra.toString(), country = CountryUtil.fromName(n), rawLink = link,
        )
    }

    private fun decodeB64(s: String): String {
        var t = s.replace('-', '+').replace('_', '/').trim()
        while (t.length % 4 != 0) t += "="
        return String(Base64.decode(t, Base64.DEFAULT), Charsets.UTF_8)
    }
}

object CountryUtil {
    private val codes = mapOf(
        "united states" to "US", "usa" to "US", "germany" to "DE", "singapore" to "SG",
        "japan" to "JP", "united kingdom" to "GB", "uk" to "GB", "canada" to "CA",
        "france" to "FR", "netherlands" to "NL", "india" to "IN", "bangladesh" to "BD",
    )

    /** Returns ISO country code guessed from a server name, or "". */
    fun fromName(name: String): String {
        val n = name.lowercase()
        codes.forEach { (k, v) -> if (n.contains(k)) return v }
        Regex("\\b([A-Z]{2})\\b").find(name)?.value?.let { return it }
        // Flag emoji: two regional indicator symbols
        val cps = name.codePoints().toArray()
        for (i in 0 until cps.size - 1) {
            if (cps[i] in 0x1F1E6..0x1F1FF && cps[i + 1] in 0x1F1E6..0x1F1FF) {
                return "" + ('A' + (cps[i] - 0x1F1E6)) + ('A' + (cps[i + 1] - 0x1F1E6))
            }
        }
        return ""
    }

    fun flag(code: String): String {
        if (code.length != 2) return "\uD83C\uDF10"
        return code.uppercase().map { String(Character.toChars(0x1F1E6 + (it - 'A'))) }.joinToString("")
    }
}
