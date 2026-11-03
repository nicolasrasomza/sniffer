package com.undercode.sniffer

import android.content.Context
import java.io.File
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL

/** Descarga las listas públicas de amenazas (abuse.ch) y las guarda localmente. */
object IocUpdater {
    private val ipUrls = listOf("https://feodotracker.abuse.ch/downloads/ipblocklist.txt")
    private val domainUrls = listOf(
        "https://urlhaus.abuse.ch/downloads/text_online/",
        "https://urlhaus.abuse.ch/downloads/hostfile/"
    )
    private val domRe = Regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")

    private fun download(url: String): List<String> {
        val c = URL(url).openConnection() as HttpURLConnection
        c.connectTimeout = 20000
        c.readTimeout = 40000
        c.setRequestProperty("User-Agent", "UndercodeSniffer/1.0")
        try {
            if (c.responseCode != 200) throw RuntimeException("HTTP ${c.responseCode}")
            return c.inputStream.bufferedReader().readLines()
        } finally {
            c.disconnect()
        }
    }

    private fun hostOf(line: String): String? {
        val s = line.trim()
        if (s.isEmpty() || s.startsWith("#") || s.startsWith(";") || s.startsWith("$") || s.startsWith("@")) return null
        if (s.contains("://")) {
            return try { URI(s).host?.lowercase() } catch (_: Exception) { null }
        }
        val t = s.split(Regex("\\s+"))
        val h = if ((t[0] == "127.0.0.1" || t[0] == "0.0.0.0") && t.size > 1) t[1] else t[0]
        return h.lowercase().trimEnd('.')
    }

    fun update(ctx: Context): String {
        val report = StringBuilder()
        val domains = LinkedHashSet<String>()
        val ips = LinkedHashSet<String>()

        for (u in ipUrls) {
            try {
                var n = 0
                for (line in download(u)) {
                    val h = hostOf(line) ?: continue
                    if (Analyzer.isIp(h)) { ips.add(h); n++ }
                }
                report.append("✔ ${u.substringAfter("//").substringBefore('/')}: $n IPs\n")
            } catch (e: Exception) {
                report.append("✘ $u → ${e.message}\n")
            }
        }
        var domOk = false
        for (u in domainUrls) {
            if (domOk) break
            try {
                var nd = 0
                var ni = 0
                for (line in download(u)) {
                    val h = hostOf(line) ?: continue
                    if (Analyzer.isIp(h)) {
                        ips.add(h); ni++
                    } else if (domRe.matches(h) && Analyzer.registered(h) !in Analyzer.safeHosting) {
                        domains.add(h); nd++
                    }
                }
                report.append("✔ ${u.substringAfter("//").substringBefore('/')}: $nd dominios, $ni IPs\n")
                domOk = nd + ni > 0
            } catch (e: Exception) {
                report.append("✘ $u → ${e.message}\n")
            }
        }

        if (domains.isEmpty() && ips.isEmpty()) {
            report.append("\nNo se pudo descargar nada. ¿Hay conexión a internet?")
            return report.toString()
        }
        try {
            if (domains.isNotEmpty()) File(ctx.filesDir, "ioc_domains.txt").writeText(domains.joinToString("\n"))
            if (ips.isNotEmpty()) File(ctx.filesDir, "ioc_ips.txt").writeText(ips.joinToString("\n"))
            Prefs.setLong("ioc_updated", System.currentTimeMillis())
        } catch (e: Exception) {
            report.append("\nError guardando: ${e.message}")
        }
        Analyzer.load(ctx)
        report.append("\nTotal cargado: ${Analyzer.iocDomainCount} dominios · ${Analyzer.iocIpCount} IPs")
        return report.toString()
    }
}
