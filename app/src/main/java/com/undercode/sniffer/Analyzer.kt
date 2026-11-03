package com.undercode.sniffer

import android.content.Context
import java.io.File

/** Motor de reglas: combina IoC conocidos con heurísticas de comportamiento. */
object Analyzer {
    @Volatile private var iocDomains: Set<String> = emptySet()
    @Volatile private var iocIps: Set<String> = emptySet()
    val iocDomainCount: Int get() = iocDomains.size
    val iocIpCount: Int get() = iocIps.size

    // Dominios de alojamiento legítimo que nunca se tratan como IoC por nombre (haría falta analizar la URL completa)
    val safeHosting = setOf(
        "google.com", "googleusercontent.com", "googleapis.com", "gstatic.com", "github.com", "githubusercontent.com",
        "gitlab.com", "bitbucket.org", "sourceforge.net", "discord.com", "discordapp.com", "discordapp.net",
        "dropbox.com", "dropboxusercontent.com", "mediafire.com", "mega.nz", "telegram.org", "t.me",
        "amazonaws.com", "cloudfront.net", "azureedge.net", "windows.net", "azurewebsites.net", "microsoft.com",
        "live.com", "sharepoint.com", "1drv.ms", "bit.ly", "cutt.ly", "tinyurl.com", "pastebin.com",
        "ngrok.io", "ngrok-free.app", "workers.dev", "pages.dev", "herokuapp.com", "vercel.app", "netlify.app",
        "firebaseapp.com", "web.app", "blogspot.com", "wixsite.com", "weebly.com", "apple.com", "icloud.com",
        "facebook.com", "fbcdn.net", "cloudflare.com", "fastly.net", "akamaihd.net", "akamaized.net"
    )

    private val trackerDomains = setOf(
        "doubleclick.net", "googlesyndication.com", "googleadservices.com", "google-analytics.com",
        "googletagmanager.com", "app-measurement.com", "adservice.google.com", "connect.facebook.net",
        "appsflyer.com", "adjust.com", "adjust.io", "branch.io", "mixpanel.com", "amplitude.com", "flurry.com",
        "unityads.unity3d.com", "applovin.com", "applvn.com", "ironsrc.com", "supersonicads.com", "vungle.com",
        "chartboost.com", "inmobi.com", "mopub.com", "startapp.com", "onesignal.com", "segment.io", "segment.com",
        "mc.yandex.ru", "adcolony.com", "kochava.com", "tapjoy.com", "fyber.com", "moatads.com",
        "scorecardresearch.com", "criteo.com", "criteo.net", "taboola.com", "outbrain.com", "adnxs.com",
        "rubiconproject.com", "pubmatic.com", "openx.net", "casalemedia.com", "amazon-adsystem.com", "hotjar.com",
        "pangleglobal.com", "byteoversea.com", "mintegral.com", "mbridge.com", "smaato.net", "bidswitch.net",
        "liftoff.io", "digitalturbine.com", "ads.tiktok.com", "analytics.tiktok.com"
    )

    private val dohHosts = setOf(
        "dns.google", "cloudflare-dns.com", "dns.quad9.net", "dns.nextdns.io", "doh.opendns.com",
        "mozilla.cloudflare-dns.com", "dns.adguard.com", "dns.adguard-dns.com"
    )

    private val suspTlds = setOf(
        "tk", "ml", "ga", "cf", "gq", "top", "xyz", "click", "work", "loan", "icu", "cyou", "buzz", "rest",
        "monster", "zip", "mov", "cam", "country", "kim", "men", "stream", "download", "racing", "party",
        "review", "science", "trade", "webcam", "win", "bid", "date", "faith", "accountant"
    )

    private val badPorts = mapOf(
        4444 to "Metasploit / backdoor", 5555 to "ADB / backdoor", 6667 to "IRC (botnets)", 6697 to "IRC (botnets)",
        1337 to "puerto típico de backdoors", 31337 to "puerto 'elite' de backdoors", 12345 to "NetBus / backdoor",
        9001 to "Tor (ORPort)", 9030 to "Tor (DirPort)", 9050 to "Tor (SOCKS)", 9051 to "Tor (control)",
        23 to "Telnet", 2323 to "Telnet alternativo (Mirai)", 3389 to "RDP", 1080 to "proxy SOCKS", 5900 to "VNC"
    )

    private val ipRe = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")
    fun isIp(s: String) = ipRe.matches(s)

    fun load(ctx: Context) {
        val d = HashSet<String>()
        val ip = HashSet<String>()
        readLines(File(ctx.filesDir, "ioc_domains.txt")) { d.add(it) }
        readLines(File(ctx.filesDir, "ioc_ips.txt")) { ip.add(it) }
        for (c in Prefs.set("custom_ioc")) {
            val s = c.trim().lowercase()
            if (s.isEmpty()) continue
            if (isIp(s)) ip.add(s) else d.add(s)
        }
        iocDomains = d
        iocIps = ip
    }

    private fun readLines(f: File, add: (String) -> Unit) {
        try {
            if (f.exists()) f.forEachLine { val s = it.trim(); if (s.isNotEmpty()) add(s) }
        } catch (_: Exception) {
        }
    }

    fun registered(d: String): String {
        val p = d.split('.')
        if (p.size <= 2) return d
        val sld = setOf("co", "com", "org", "net", "gov", "edu", "ac", "or", "ne", "go")
        val n = if (p[p.size - 1].length == 2 && p[p.size - 2] in sld) 3 else 2
        return p.takeLast(n).joinToString(".")
    }

    /** Devuelve la entrada de IoC coincidente (nombre o dominio padre) o null. */
    fun matchIoc(name: String): String? {
        val set = iocDomains
        if (set.isEmpty()) return null
        var s = name.lowercase()
        while (true) {
            if (set.contains(s)) return s
            val i = s.indexOf('.')
            if (i < 0 || s.indexOf('.', i + 1) < 0) return null
            s = s.substring(i + 1)
        }
    }

    private fun suffixIn(set: Set<String>, name: String): Boolean {
        var s = name.lowercase()
        while (true) {
            if (set.contains(s)) return true
            val i = s.indexOf('.')
            if (i < 0) return false
            s = s.substring(i + 1)
        }
    }

    fun isTracker(name: String) = suffixIn(trackerDomains, name)

    private fun entropy(s: String): Double {
        if (s.isEmpty()) return 0.0
        val cnt = HashMap<Char, Int>()
        for (c in s) cnt[c] = (cnt[c] ?: 0) + 1
        var e = 0.0
        for (v in cnt.values) {
            val p = v.toDouble() / s.length
            e -= p * (Math.log(p) / Math.log(2.0))
        }
        return e
    }

    private fun dgaLike(name: String): Boolean {
        if (isIp(name)) return false
        val sld = registered(name).substringBefore('.')
        if (sld.length < 10) return false
        if (isTracker(name)) return false
        val digits = sld.count { it.isDigit() }
        val vowels = sld.count { it in "aeiou" }
        val ent = entropy(sld)
        val lowVowels = vowels.toDouble() / sld.length < 0.28
        return (sld.length >= 12 && ent >= 3.5 && lowVowels) || (digits.toDouble() / sld.length >= 0.35)
    }

    fun isPrivate(ip: String): Boolean {
        val p = ip.split('.').mapNotNull { it.toIntOrNull() }
        if (p.size != 4) return false
        return p[0] == 10 || p[0] == 127 || p[0] >= 224 ||
            (p[0] == 192 && p[1] == 168) || (p[0] == 172 && p[1] in 16..31) || (p[0] == 169 && p[1] == 254)
    }

    private fun beacon(starts: List<Long>): String? {
        if (starts.size < 6) return null
        val iv = ArrayList<Double>()
        for (i in 1 until starts.size) iv.add((starts[i] - starts[i - 1]).toDouble())
        val mean = iv.average()
        if (mean < 5000 || mean > 3_600_000) return null
        val sd = Math.sqrt(iv.map { (it - mean) * (it - mean) }.average())
        return if (sd / mean < 0.15) "cada ~${(mean / 1000).toInt()} s" else null
    }

    fun ruleOn(r: Rule): Boolean = Prefs.bool("rule_" + r.id, r.defaultOn)

    fun evaluate(r: ConnRecord) {
        if (r.trusted) {
            r.level = Level.GREEN
            r.score = 0
            r.ioc = false
            r.reasonText = listOf("Marcada como confiable por el usuario")
            return
        }
        var score = 0
        var ioc = false
        val reasons = ArrayList<String>()
        fun hit(rule: Rule, text: String) {
            if (ruleOn(rule)) {
                score += rule.points
                reasons.add(text)
            }
        }

        val names = r.names()

        // ---- Indicadores de compromiso (IoC) ----
        if (ruleOn(Rule.IOC_DOMAIN)) {
            for (n in names) {
                val m = matchIoc(n)
                if (m != null) {
                    ioc = true
                    reasons.add("IoC: el dominio $n coincide con las listas de amenazas ($m)")
                    break
                }
            }
        }
        if (ruleOn(Rule.IOC_IP) && iocIps.contains(r.ip)) {
            ioc = true
            reasons.add("IoC: la IP ${r.ip} figura como servidor de control / malware")
        }

        // ---- Heurísticas ----
        if (names.isEmpty() && !r.isDns && !isPrivate(r.ip) && r.port != 53) {
            hit(Rule.DIRECT_IP, "Conexión a IP directa, sin DNS ni SNI previos")
        }
        val bp = badPorts[r.port]
        if (bp != null && !r.isDns) hit(Rule.BAD_PORT, "Puerto ${r.port}: $bp")

        for (n in names) {
            if (isIp(n)) continue
            val tld = n.substringAfterLast('.')
            if (tld in suspTlds) {
                hit(Rule.SUSP_TLD, "TLD de alto abuso (.$tld) en $n")
                break
            }
        }
        for (n in names) {
            if (dgaLike(n)) {
                hit(Rule.DGA, "Nombre de aspecto aleatorio: $n")
                break
            }
        }
        for (n in names) {
            if (isTracker(n)) {
                hit(Rule.TRACKER, "Dominio de rastreo / publicidad: $n")
                break
            }
        }

        if (r.cleartext) hit(Rule.CLEARTEXT, "Tráfico HTTP sin cifrar")
        val sens = r.sensitiveList()
        if (sens.isNotEmpty()) hit(Rule.SENSITIVE, "Datos sensibles en texto plano: ${sens.joinToString(", ")}")
        if (r.oldTls) hit(Rule.OLD_TLS, "Versión de TLS obsoleta (${r.tlsVersion})")

        val bc = beacon(r.startsSnapshot())
        if (bc != null) hit(Rule.BEACON, "Conexiones muy regulares ($bc)")

        if (r.screenOffUp.get() >= 50_000) {
            hit(Rule.SCREEN_OFF, "Subió ${humanBytes(r.screenOffUp.get())} con la pantalla apagada")
        }
        val up = r.bytesUp.get()
        val down = r.bytesDown.get()
        if (up >= 2_000_000 && up > 4 * down) {
            hit(Rule.BIG_UPLOAD, "Subida masiva: ${humanBytes(up)} enviados vs ${humanBytes(down)} recibidos")
        }

        if (r.port == 53 && r.ip != "1.1.1.1" && !isPrivate(r.ip) ) {
            hit(Rule.DNS_BYPASS, "DNS directo a ${r.ip} (evita el resolver del sistema)")
        } else if (r.port == 853 && r.ip != "1.1.1.1") {
            hit(Rule.DNS_BYPASS, "DNS sobre TLS (puerto 853) a ${r.ip}")
        } else {
            for (n in names) {
                if (n in dohHosts) {
                    hit(Rule.DNS_BYPASS, "DNS sobre HTTPS propio ($n)")
                    break
                }
            }
        }

        if (Engine.scanIps.contains(r.ip)) {
            hit(Rule.PORT_SCAN, "Muchos puertos distintos probados en ${r.ip} en poco tiempo")
        }

        r.ioc = ioc
        r.score = if (ioc) maxOf(score, 100) else score
        r.level = when {
            ioc || score >= 40 -> Level.RED
            score >= 10 -> Level.AMBER
            else -> Level.GREEN
        }
        r.reasonText = reasons
    }
}

/** Firewall por dominio / IP. Las conexiones bloqueadas no se reenvían. */
object Firewall {
    @Volatile var entries: Set<String> = emptySet()

    fun load() {
        entries = Prefs.set("blocked")
    }

    fun block(x: String) {
        val s = HashSet(entries)
        s.add(x.lowercase())
        entries = s
        Prefs.setSet("blocked", s)
    }

    fun unblock(x: String) {
        val s = HashSet(entries)
        s.remove(x.lowercase())
        entries = s
        Prefs.setSet("blocked", s)
    }

    fun isDomainBlocked(name: String): Boolean {
        val e = entries
        if (e.isEmpty()) return false
        var s = name.lowercase()
        while (true) {
            if (e.contains(s)) return true
            val i = s.indexOf('.')
            if (i < 0) return false
            s = s.substring(i + 1)
        }
    }

    fun isIpBlocked(ip: String): Boolean = entries.contains(ip)

    fun blocks(r: ConnRecord): Boolean {
        if (isIpBlocked(r.ip)) return true
        for (n in r.names()) if (isDomainBlocked(n)) return true
        return Prefs.bool("autoblock_ioc", false) && r.ioc && !r.trusted
    }
}
