package com.undercode.sniffer

import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

enum class Level { GREEN, AMBER, RED }

/** Reglas de detección. Cada una puede activarse o desactivarse desde la app. */
enum class Rule(val id: String, val title: String, val points: Int, val defaultOn: Boolean = true) {
    IOC_DOMAIN("ioc_domain", "IoC · dominio en listas de amenazas", 100),
    IOC_IP("ioc_ip", "IoC · IP en listas de amenazas", 100),
    DIRECT_IP("direct_ip", "Conexión a IP directa sin DNS ni SNI", 10),
    BAD_PORT("bad_port", "Puertos típicos de backdoors / C2", 25),
    SUSP_TLD("susp_tld", "Dominios con TLD de alto abuso", 15),
    DGA("dga", "Dominios de aspecto aleatorio (DGA)", 20),
    CLEARTEXT("cleartext", "Tráfico HTTP sin cifrar", 10),
    SENSITIVE("sensitive", "Datos sensibles en texto plano", 35),
    OLD_TLS("old_tls", "TLS obsoleto (1.0 / 1.1)", 15),
    BEACON("beacon", "Conexiones periódicas (beaconing)", 20),
    SCREEN_OFF("screen_off", "Subida de datos con la pantalla apagada", 15),
    BIG_UPLOAD("big_upload", "Subida masiva hacia un solo destino", 25),
    DNS_BYPASS("dns_bypass", "DNS / DoT / DoH fuera del resolver del sistema", 15),
    TRACKER("tracker", "Dominios de rastreo y publicidad", 10),
    PORT_SCAN("port_scan", "Escaneo de puertos", 40)
}

/** Un destino (ip:puerto o consulta DNS) agregado por app y protocolo. */
class ConnRecord(
    val key: String,
    val pkg: String,
    val appLabel: String,
    val proto: String,
    val ip: String,
    val port: Int,
    val isDns: Boolean = false
) {
    private val nameSet = LinkedHashSet<String>()
    @Volatile var domain: String? = null

    fun addName(n: String) {
        val s = n.lowercase().trim().trimEnd('.')
        if (s.isEmpty()) return
        synchronized(nameSet) { if (nameSet.size < 20) nameSet.add(s) }
        domain = s
    }

    fun names(): List<String> = synchronized(nameSet) { ArrayList(nameSet) }

    val bytesUp = AtomicLong(0)
    val bytesDown = AtomicLong(0)
    val screenOffUp = AtomicLong(0)
    val flows = AtomicInteger(0)
    val blockedCount = AtomicInteger(0)
    val firstSeen: Long = System.currentTimeMillis()
    @Volatile var lastSeen: Long = firstSeen

    @Volatile var cleartext = false
    @Volatile var oldTls = false
    @Volatile var tlsVersion: String? = null
    private val sensitiveSet = LinkedHashSet<String>()
    fun addSensitive(items: Set<String>) { synchronized(sensitiveSet) { sensitiveSet.addAll(items) } }
    fun sensitiveList(): List<String> = synchronized(sensitiveSet) { ArrayList(sensitiveSet) }

    private val starts = ArrayList<Long>()
    fun noteStart() {
        val now = System.currentTimeMillis()
        synchronized(starts) {
            starts.add(now)
            if (starts.size > 20) starts.removeAt(0)
        }
    }
    fun startsSnapshot(): List<Long> = synchronized(starts) { ArrayList(starts) }

    @Volatile var level: Level = Level.GREEN
    @Volatile var score: Int = 0
    @Volatile var reasonText: List<String> = emptyList()
    @Volatile var ioc = false
    @Volatile var trusted = false
    @Volatile var alerted = false

    fun title(): String {
        val d = domain
        return if (isDns) "DNS · ${d ?: ip}" else "${d ?: ip}:$port"
    }
}

class Event(
    val time: Long,
    val rec: ConnRecord,
    val text: String,
    val screenOn: Boolean
)

fun humanBytes(b: Long): String = when {
    b < 1024 -> "$b B"
    b < 1024 * 1024 -> "%.1f KB".format(b / 1024.0)
    else -> "%.1f MB".format(b / (1024.0 * 1024.0))
}
