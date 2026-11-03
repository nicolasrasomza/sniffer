package com.undercode.sniffer

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.AppCompatButton
import androidx.core.content.ContextCompat

class MainActivity : AppCompatActivity() {

    private lateinit var tvSys: TextView
    private lateinit var tvLog: TextView
    private lateinit var tvPackets: TextView
    private lateinit var tvBytes: TextView
    private lateinit var tvStatus: TextView
    private lateinit var scrollLog: ScrollView
    private lateinit var btnStart: AppCompatButton
    private lateinit var btnStop: AppCompatButton

    private val ui = Handler(Looper.getMainLooper())
    private val maxLogChars = 40_000

    // Lanzador moderno para el diálogo de consentimiento de VPN
    private val vpnPermission =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == RESULT_OK) {
                startCapture()
            } else {
                appendLog("[!] permiso VPN denegado por el usuario")
            }
        }

    private val statsTicker = object : Runnable {
        override fun run() {
            refreshStats()
            ui.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        tvSys = findViewById(R.id.tvSys)
        tvLog = findViewById(R.id.tvLog)
        tvPackets = findViewById(R.id.tvPackets)
        tvBytes = findViewById(R.id.tvBytes)
        tvStatus = findViewById(R.id.tvStatus)
        scrollLog = findViewById(R.id.scrollLog)
        btnStart = findViewById(R.id.btnStart)
        btnStop = findViewById(R.id.btnStop)

        btnStart.setOnClickListener { requestVpnAndStart() }
        btnStop.setOnClickListener { stopCapture() }

        refreshStats()
    }

    override fun onStart() {
        super.onStart()
        CaptureBus.listener = { line -> appendLog(line) }
        ui.post(statsTicker)
    }

    override fun onStop() {
        super.onStop()
        CaptureBus.listener = null
        ui.removeCallbacks(statsTicker)
    }

    private fun requestVpnAndStart() {
        // prepare() devuelve null si el permiso ya fue concedido antes
        val intent = VpnService.prepare(this)
        if (intent != null) vpnPermission.launch(intent) else startCapture()
    }

    private fun startCapture() {
        val i = Intent(this, MyVpnService::class.java).setAction(MyVpnService.ACTION_START)
        ContextCompat.startForegroundService(this, i)
        appendLog("$ ./traffic-sniffer --start")
    }

    private fun stopCapture() {
        val i = Intent(this, MyVpnService::class.java).setAction(MyVpnService.ACTION_STOP)
        startService(i)
        appendLog("$ ./traffic-sniffer --stop")
    }

    private fun refreshStats() {
        val running = CaptureBus.running
        tvPackets.text = CaptureBus.packets.get().toString()
        tvBytes.text = humanBytes(CaptureBus.bytes.get())
        tvStatus.text = if (running) "ON" else "OFF"
        tvStatus.setTextColor(
            ContextCompat.getColor(this, if (running) R.color.green else R.color.red)
        )
        tvSys.text = "SYS://UNDERCODE.ORG · " + if (running) "CAPTURING" else "IDLE"
        btnStart.isEnabled = !running
        btnStart.alpha = if (running) 0.4f else 1f
        btnStop.isEnabled = running
        btnStop.alpha = if (running) 1f else 0.4f
    }

    private fun appendLog(line: String) {
        tvLog.append(line + "\n")
        val text = tvLog.text
        if (text.length > maxLogChars) {
            tvLog.text = text.subSequence(text.length - maxLogChars / 2, text.length)
        }
        scrollLog.post { scrollLog.fullScroll(ScrollView.FOCUS_DOWN) }
    }

    private fun humanBytes(b: Long): String = when {
        b < 1024 -> "$b B"
        b < 1024 * 1024 -> "%.1f KB".format(b / 1024.0)
        else -> "%.1f MB".format(b / (1024.0 * 1024.0))
    }
}
