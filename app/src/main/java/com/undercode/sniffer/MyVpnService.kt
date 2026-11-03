package com.undercode.sniffer

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import java.io.FileInputStream
import java.io.IOException
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.atomic.AtomicLong

/** Puente simple entre el servicio y la UI. */
object CaptureBus {
    @Volatile var running = false
    val packets = AtomicLong(0)
    val bytes = AtomicLong(0)
    @Volatile var listener: ((String) -> Unit)? = null
    private val main = Handler(Looper.getMainLooper())
    private val fmt = SimpleDateFormat("HH:mm:ss", Locale.US)

    fun log(msg: String) {
        val line = "${fmt.format(Date())} $msg"
        main.post { listener?.invoke(line) }
    }
}

class MyVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.undercode.sniffer.START"
        const val ACTION_STOP = "com.undercode.sniffer.STOP"
        private const val CHANNEL_ID = "sniffer"
        private const val NOTIF_ID = 1
    }

    private var tun: ParcelFileDescriptor? = null
    private var worker: Thread? = null
    @Volatile private var active = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopCapture()
                stopSelf()
                return START_NOT_STICKY
            }
            else -> startCapture()
        }
        return START_STICKY
    }

    private fun startCapture() {
        if (active) return
        startForeground(NOTIF_ID, buildNotification())

        val builder = Builder()
            .setSession("undercode-sniffer")
            .setMtu(1500)
            .addAddress("10.8.0.2", 32)
            .addRoute("0.0.0.0", 0)          // todo el IPv4 pasa por el túnel
            .addDnsServer("1.1.1.1")         // las consultas DNS también pasan por el túnel
            .setBlocking(true)

        try {
            builder.addDisallowedApplication(packageName)   // excluye esta app
        } catch (_: Exception) {
        }

        tun = try {
            builder.establish()
        } catch (e: Exception) {
            null
        }

        if (tun == null) {
            CaptureBus.log("[!] no se pudo establecer la interfaz TUN (¿permiso revocado?)")
            stopSelf()
            return
        }

        active = true
        CaptureBus.running = true
        CaptureBus.packets.set(0)
        CaptureBus.bytes.set(0)
        CaptureBus.log("[+] tun0 arriba · 10.8.0.2/32 · mtu 1500")

        worker = Thread({ readLoop() }, "sniffer-tun-reader").also { it.start() }
    }

    private fun readLoop() {
        val fd = tun ?: return
        val input = FileInputStream(fd.fileDescriptor)
        val buf = ByteArray(32767)
        try {
            while (active) {
                val n = input.read(buf)          // bloqueante: bytes crudos de un paquete IP
                if (n <= 0) continue
                CaptureBus.packets.incrementAndGet()
                CaptureBus.bytes.addAndGet(n.toLong())
                PacketParser.describe(buf, n)?.let { CaptureBus.log(it) }
            }
        } catch (e: IOException) {
            if (active) CaptureBus.log("[!] error de lectura: ${e.message}")
        } finally {
            CaptureBus.log("[-] hilo de captura finalizado")
        }
    }

    private fun stopCapture() {
        active = false
        CaptureBus.running = false
        try { tun?.close() } catch (_: IOException) {}   // desbloquea el read()
        tun = null
        worker?.interrupt()
        worker = null
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    override fun onRevoke() {
        // El usuario o el sistema revocó la VPN
        stopCapture()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopCapture()
        super.onDestroy()
    }

    private fun buildNotification(): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "Sniffer", NotificationManager.IMPORTANCE_LOW)
            )
        }
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_menu_view)
            .setContentTitle("Undercode Sniffer")
            .setContentText("Capturando tráfico de este dispositivo")
            .setOngoing(true)
            .build()
    }
}

/** Parser mínimo de cabeceras IPv4/IPv6, TCP, UDP, ICMP y nombre DNS. */
object PacketParser {

    private fun u8(b: ByteArray, i: Int) = b[i].toInt() and 0xFF
    private fun u16(b: ByteArray, i: Int) = (u8(b, i) shl 8) or u8(b, i + 1)
    private fun ip4(b: ByteArray, i: Int) =
        "${u8(b, i)}.${u8(b, i + 1)}.${u8(b, i + 2)}.${u8(b, i + 3)}"

    private fun ip6(b: ByteArray, i: Int): String =
        (0 until 8).joinToString(":") { "%x".format(u16(b, i + it * 2)) }

    fun describe(p: ByteArray, len: Int): String? {
        if (len < 20) return null
        return when (u8(p, 0) shr 4) {
            4 -> describeV4(p, len)
            6 -> describeV6(p, len)
            else -> null
        }
    }

    private fun describeV4(p: ByteArray, len: Int): String? {
        val ihl = (u8(p, 0) and 0x0F) * 4
        if (ihl < 20 || len < ihl) return null
        val proto = u8(p, 9)
        val src = ip4(p, 12)
        val dst = ip4(p, 16)
        return "IPv4 " + l4(proto, p, ihl, len, src, dst)
    }

    private fun describeV6(p: ByteArray, len: Int): String? {
        if (len < 40) return null
        val next = u8(p, 6)
        return "IPv6 " + l4(next, p, 40, len, ip6(p, 8), ip6(p, 24))
    }

    private fun l4(proto: Int, p: ByteArray, off: Int, len: Int, src: String, dst: String): String {
        return when (proto) {
            6 -> { // TCP
                if (len < off + 14) return "TCP $src -> $dst"
                val sp = u16(p, off)
                val dp = u16(p, off + 2)
                val f = u8(p, off + 13)
                val flags = buildString {
                    if (f and 0x02 != 0) append("SYN ")
                    if (f and 0x10 != 0) append("ACK ")
                    if (f and 0x01 != 0) append("FIN ")
                    if (f and 0x04 != 0) append("RST ")
                    if (f and 0x08 != 0) append("PSH ")
                }.trim()
                "TCP $src:$sp -> $dst:$dp [$flags] len=$len"
            }
            17 -> { // UDP
                if (len < off + 8) return "UDP $src -> $dst"
                val sp = u16(p, off)
                val dp = u16(p, off + 2)
                val base = "UDP $src:$sp -> $dst:$dp len=$len"
                if (dp == 53) {
                    dnsName(p, off + 8, len)?.let { return "$base DNS? $it" }
                }
                base
            }
            1, 58 -> "ICMP $src -> $dst len=$len"
            else -> "PROTO($proto) $src -> $dst len=$len"
        }
    }

    /** Extrae el QNAME de una consulta DNS (sin compresión). */
    private fun dnsName(p: ByteArray, dnsOff: Int, len: Int): String? {
        var i = dnsOff + 12
        if (i >= len) return null
        val sb = StringBuilder()
        while (i < len) {
            val l = u8(p, i)
            if (l == 0) break
            if (l and 0xC0 != 0) return null
            i++
            if (i + l > len) return null
            sb.append(String(p, i, l, Charsets.US_ASCII)).append('.')
            i += l
        }
        return sb.toString().trimEnd('.').ifEmpty { null }
    }
}
