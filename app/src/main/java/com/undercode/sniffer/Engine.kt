package com.undercode.sniffer

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Handler
import android.os.Looper
import androidx.core.app.NotificationCompat
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/** Estado compartido entre el servicio VPN y la interfaz. */
object Engine {
    lateinit var app: Context
    private var loaded = false

    @Volatile var running = false
    @Volatile var screenOn = true
    @Volatile var sessionStart = 0L
    @Volatile var sessionEnd = 0L
    @Volatile var sessionPkg: String? = null
    @Volatile var sessionLabel = "Todas las apps"
    @Volatile var lastScan: ScanResult? = null
    @Volatile var pcap: PcapWriter? = null
    @Volatile var androidId: String = ""
    @Volatile var logListener: ((String) -> Unit)? = null

    val packets = AtomicLong(0)
    val bytes = AtomicLong(0)
    val quicBlocked = AtomicLong(0)
    val records = ConcurrentHashMap<String, ConnRecord>()
    val dnsMap = ConcurrentHashMap<String, String>()
    val scanIps: MutableSet<String> = ConcurrentHashMap.newKeySet()
    @Volatile var trusted: Set<String> = emptySet()

    private val events = ArrayList<Event>()
    private val connectLog = HashMap<String, ArrayList<LongArray>>()
    private val main = Handler(Looper.getMainLooper())
    private val fmt = SimpleDateFormat("HH:mm:ss", Locale.US)
    private val alertId = AtomicInteger(100)
    private val alertsSent = AtomicInteger(0)

    fun init(ctx: Context) {
        if (!::app.isInitialized) app = ctx.applicationContext
        Prefs.init(app)
        if (!loaded) {
            loaded = true
            Analyzer.load(app)
            Firewall.load()
            trusted = Prefs.set("trusted")
            androidId = try {
                android.provider.Settings.Secure.getString(
                    app.contentResolver, android.provider.Settings.Secure.ANDROID_ID
                )?.lowercase() ?: ""
            } catch (_: Exception) {
                ""
            }
        }
    }

    fun log(msg: String) {
        val line = synchronized(fmt) { "${fmt.format(Date())} $msg" }
        main.post { logListener?.invoke(line) }
    }

    fun clearData() {
        records.clear()
        synchronized(events) { events.clear() }
        dnsMap.clear()
        scanIps.clear()
        synchronized(connectLog) { connectLog.clear() }
        packets.set(0)
        bytes.set(0)
        quicBlocked.set(0)
        alertsSent.set(0)
    }

    fun record(pkg: String, label: String, proto: String, ip: String, port: Int): ConnRecord {
        val key = "$pkg|$proto|$ip:$port"
        val r = records.computeIfAbsent(key) {
            val c = ConnRecord(key, pkg, label, proto, ip, port)
            c.trusted = trusted.contains(key)
            c
        }
        r.lastSeen = System.currentTimeMillis()
        return r
    }

    /** Consulta DNS: solo se crea registro si el nombre ya resulta sospechoso. */
    fun noteDns(pkg: String, label: String, name: String, resolver: String) {
        val key = "$pkg|DNS|$name"
        val existing = records[key]
        if (existing != null) {
            existing.lastSeen = System.currentTimeMillis()
            existing.flows.incrementAndGet()
            existing.noteStart()
            evaluate(existing)
            return
        }
        val tmp = ConnRecord(key, pkg, label, "DNS", resolver, 53, true)
        tmp.addName(name)
        tmp.trusted = trusted.contains(key)
        Analyzer.evaluate(tmp)
        if (tmp.level != Level.GREEN) {
            val r = records.computeIfAbsent(key) { tmp }
            r.flows.incrementAndGet()
            r.noteStart()
            addEvent(r, "Consulta DNS: $name")
            evaluate(r)
        }
    }

    fun noteConnect(ip: String, port: Int) {
        val now = System.currentTimeMillis()
        synchronized(connectLog) {
            val l = connectLog.getOrPut(ip) { ArrayList() }
            l.add(longArrayOf(now, port.toLong()))
            l.removeAll { now - it[0] > 60_000 }
            if (l.map { it[1] }.toSet().size >= 15) scanIps.add(ip)
        }
    }

    fun addEvent(r: ConnRecord, text: String) {
        val e = Event(System.currentTimeMillis(), r, text, screenOn)
        synchronized(events) {
            events.add(e)
            if (events.size > 3000) events.subList(0, 500).clear()
        }
    }

    fun eventsSnapshot(): List<Event> = synchronized(events) { ArrayList(events) }

    fun evaluate(r: ConnRecord) {
        Analyzer.evaluate(r)
        if (r.level == Level.RED && !r.alerted && !r.trusted) {
            r.alerted = true
            notifyAlert(r)
        }
    }

    fun evaluateAll() {
        for (r in records.values) evaluate(r)
    }

    private fun notifyAlert(r: ConnRecord) {
        val why = r.reasonText.firstOrNull() ?: "comportamiento sospechoso"
        addEvent(r, "ALERTA ROJA: $why")
        log("[!] ${r.appLabel} → ${r.title()} · $why")
        if (alertsSent.incrementAndGet() > 25) return
        try {
            val nm = app.getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(
                NotificationChannel("alerts", "Alertas de conexión", NotificationManager.IMPORTANCE_HIGH)
            )
            val text = "${r.title()} — $why"
            val n = NotificationCompat.Builder(app, "alerts")
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentTitle("Conexión sospechosa · ${r.appLabel}")
                .setContentText(text)
                .setStyle(NotificationCompat.BigTextStyle().bigText(text))
                .setAutoCancel(true)
                .build()
            nm.notify(alertId.incrementAndGet(), n)
        } catch (_: Exception) {
        }
    }

    fun setTrusted(key: String, value: Boolean) {
        val s = HashSet(trusted)
        if (value) s.add(key) else s.remove(key)
        trusted = s
        Prefs.setSet("trusted", s)
        records[key]?.let {
            it.trusted = value
            evaluate(it)
        }
    }
}
