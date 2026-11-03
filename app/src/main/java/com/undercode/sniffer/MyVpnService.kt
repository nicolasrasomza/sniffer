package com.undercode.sniffer

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit

class MyVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.undercode.sniffer.START"
        const val ACTION_STOP = "com.undercode.sniffer.STOP"
        const val EXTRA_PKG = "pkg"
        const val EXTRA_LABEL = "label"
        private const val CHANNEL_ID = "sniffer"
        private const val NOTIF_ID = 1
    }

    private var tun: ParcelFileDescriptor? = null
    private var worker: Thread? = null
    private var forwarder: Forwarder? = null
    private var exec: ScheduledExecutorService? = null
    private var screenReceiver: BroadcastReceiver? = null
    @Volatile private var active = false
    private var stopped = true

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopCapture()
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_START -> startCapture(intent)
            else -> {
                stopSelf()
                return START_NOT_STICKY
            }
        }
        return START_NOT_STICKY
    }

    private fun startCapture(intent: Intent) {
        startForeground(NOTIF_ID, buildNotification())
        if (active) return
        Engine.init(this)

        val pkg = intent.getStringExtra(EXTRA_PKG)
        val label = intent.getStringExtra(EXTRA_LABEL) ?: pkg ?: "Todas las apps"

        val builder = Builder()
            .setSession("undercode-sniffer")
            .setMtu(1500)
            .addAddress("10.8.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("1.1.1.1")
            .setBlocking(true)

        try {
            if (pkg != null) builder.addAllowedApplication(pkg)
            else builder.addDisallowedApplication(packageName)
        } catch (e: PackageManager.NameNotFoundException) {
            Engine.log("[!] la app seleccionada ya no está instalada")
            stopSelf()
            return
        }

        tun = try {
            builder.establish()
        } catch (e: Exception) {
            null
        }
        val fd = tun
        if (fd == null) {
            Engine.log("[!] no se pudo establecer la interfaz TUN (¿permiso revocado?)")
            stopSelf()
            return
        }

        Engine.clearData()
        Engine.sessionStart = System.currentTimeMillis()
        Engine.sessionEnd = 0L
        Engine.sessionPkg = pkg
        Engine.sessionLabel = label
        Engine.screenOn = getSystemService(PowerManager::class.java)?.isInteractive ?: true

        var pcap: PcapWriter? = null
        if (Prefs.bool("save_pcap", true)) {
            try {
                pcap = PcapWriter(File(filesDir, "capture.pcap"), 64L * 1024 * 1024)
            } catch (_: Exception) {
            }
        }
        Engine.pcap = pcap

        val fwd = Forwarder(this, FileOutputStream(fd.fileDescriptor), pcap, pkg, label)
        forwarder = fwd

        screenReceiver = object : BroadcastReceiver() {
            override fun onReceive(c: Context?, i: Intent?) {
                Engine.screenOn = i?.action != Intent.ACTION_SCREEN_OFF
            }
        }
        registerReceiver(screenReceiver, IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_SCREEN_OFF)
        })

        active = true
        stopped = false
        Engine.running = true
        Engine.log("[+] tun0 arriba · objetivo: $label")

        worker = Thread({ readLoop(fd, fwd) }, "sniffer-tun-reader").also {
            it.isDaemon = true
            it.start()
        }
        exec = Executors.newSingleThreadScheduledExecutor().also { e ->
            e.scheduleWithFixedDelay({
                try {
                    fwd.janitor()
                    Engine.evaluateAll()
                } catch (_: Exception) {
                }
            }, 2, 2, TimeUnit.SECONDS)
        }
    }

    private fun readLoop(fd: ParcelFileDescriptor, fwd: Forwarder) {
        val input = FileInputStream(fd.fileDescriptor)
        val buf = ByteArray(32767)
        try {
            while (active) {
                val n = input.read(buf)
                if (n <= 0) continue
                try {
                    fwd.handlePacket(buf, n)
                } catch (e: Exception) {
                    Engine.log("[!] error procesando paquete: ${e.javaClass.simpleName}")
                }
            }
        } catch (e: IOException) {
            if (active) Engine.log("[!] error de lectura: ${e.message}")
        } finally {
            Engine.log("[-] hilo de captura finalizado")
        }
    }

    private fun stopCapture() {
        if (stopped) return
        stopped = true
        active = false
        Engine.running = false
        Engine.sessionEnd = System.currentTimeMillis()
        try { screenReceiver?.let { unregisterReceiver(it) } } catch (_: Exception) {}
        screenReceiver = null
        exec?.shutdownNow()
        exec = null
        try { forwarder?.shutdown() } catch (_: Exception) {}
        forwarder = null
        try { tun?.close() } catch (_: IOException) {}
        tun = null
        worker = null
        Engine.pcap?.close()
        try { SessionStore.saveCurrent(this) } catch (_: Exception) {}
        stopForeground(STOP_FOREGROUND_REMOVE)
        Engine.log("[-] captura detenida")
    }

    override fun onRevoke() {
        stopCapture()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopCapture()
        super.onDestroy()
    }

    private fun buildNotification(): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "Sniffer", NotificationManager.IMPORTANCE_LOW)
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_menu_view)
            .setContentTitle("Undercode Sniffer")
            .setContentText("Analizando tráfico")
            .setOngoing(true)
            .build()
    }
}
