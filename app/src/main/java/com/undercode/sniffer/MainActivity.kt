package com.undercode.sniffer

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.Editable
import android.text.TextWatcher
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.BaseAdapter
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.AppCompatButton
import androidx.appcompat.widget.SwitchCompat
import androidx.core.content.ContextCompat
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : AppCompatActivity() {

    private class AppItem(val pkg: String?, val label: String) {
        override fun toString(): String = if (pkg == null) label else "$label\n$pkg"
    }

    private lateinit var tvSys: TextView
    private lateinit var tvLog: TextView
    private lateinit var tvPackets: TextView
    private lateinit var tvBytes: TextView
    private lateinit var tvStatus: TextView
    private lateinit var tvConns: TextView
    private lateinit var tvReds: TextView
    private lateinit var tvAppReport: TextView
    private lateinit var tvSummary: TextView
    private lateinit var tvIoc: TextView
    private lateinit var tabApp: TextView
    private lateinit var tabConn: TextView
    private lateinit var tabTools: TextView
    private lateinit var fAll: TextView
    private lateinit var fRed: TextView
    private lateinit var fAmber: TextView
    private lateinit var fTime: TextView
    private lateinit var panelApp: View
    private lateinit var panelConn: View
    private lateinit var panelTools: View
    private lateinit var btnPick: AppCompatButton
    private lateinit var btnStart: AppCompatButton
    private lateinit var btnStop: AppCompatButton
    private lateinit var btnUpdate: AppCompatButton
    private lateinit var rulesContainer: LinearLayout
    private lateinit var listConn: ListView
    private lateinit var adapter: ConnAdapter

    private val ui = Handler(Looper.getMainLooper())
    private val logLines = ArrayList<String>()
    private var tab = 0
    private var filter = 0 // 0 todas, 1 rojas, 2 ámbar, 3 línea de tiempo
    private var selPkg: String? = null
    private var selLabel = "Todas las apps"

    private val vpnPermission =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == RESULT_OK) startCapture()
            else appendLog("[!] permiso VPN denegado por el usuario")
        }

    private val notifPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    private val statsTicker = object : Runnable {
        override fun run() {
            refreshStats()
            if (tab == 1) refreshList()
            ui.postDelayed(this, 1000)
        }
    }

    // ------------------------------------------------------------------ ciclo de vida

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Engine.init(this)
        setContentView(R.layout.activity_main)

        tvSys = findViewById(R.id.tvSys)
        tvLog = findViewById(R.id.tvLog)
        tvPackets = findViewById(R.id.tvPackets)
        tvBytes = findViewById(R.id.tvBytes)
        tvStatus = findViewById(R.id.tvStatus)
        tvConns = findViewById(R.id.tvConns)
        tvReds = findViewById(R.id.tvReds)
        tvAppReport = findViewById(R.id.tvAppReport)
        tvSummary = findViewById(R.id.tvSummary)
        tvIoc = findViewById(R.id.tvIoc)
        tabApp = findViewById(R.id.tabApp)
        tabConn = findViewById(R.id.tabConn)
        tabTools = findViewById(R.id.tabTools)
        fAll = findViewById(R.id.fAll)
        fRed = findViewById(R.id.fRed)
        fAmber = findViewById(R.id.fAmber)
        fTime = findViewById(R.id.fTime)
        panelApp = findViewById(R.id.panelApp)
        panelConn = findViewById(R.id.panelConn)
        panelTools = findViewById(R.id.panelTools)
        btnPick = findViewById(R.id.btnPick)
        btnStart = findViewById(R.id.btnStart)
        btnStop = findViewById(R.id.btnStop)
        btnUpdate = findViewById(R.id.btnUpdate)
        rulesContainer = findViewById(R.id.rulesContainer)
        listConn = findViewById(R.id.listConn)

        adapter = ConnAdapter()
        listConn.adapter = adapter
        listConn.setOnItemClickListener { _, _, pos, _ ->
            val o = adapter.getItem(pos)
            if (o is ConnRecord) showDetail(o) else if (o is Event) showDetail(o.rec)
        }

        tabApp.setOnClickListener { showTab(0) }
        tabConn.setOnClickListener { showTab(1) }
        tabTools.setOnClickListener { showTab(2) }
        fAll.setOnClickListener { setFilter(0) }
        fRed.setOnClickListener { setFilter(1) }
        fAmber.setOnClickListener { setFilter(2) }
        fTime.setOnClickListener { setFilter(3) }

        btnPick.setOnClickListener { pickApp() }
        btnStart.setOnClickListener { requestVpnAndStart() }
        btnStop.setOnClickListener { stopCapture() }
        btnUpdate.setOnClickListener { updateIoc() }
        findViewById<View>(R.id.btnAddIoc).setOnClickListener { addIocDialog() }
        findViewById<View>(R.id.btnPcap).setOnClickListener { runExport { Exporter.exportPcap(applicationContext) } }
        findViewById<View>(R.id.btnHtml).setOnClickListener { runExport { Exporter.exportHtml(applicationContext) } }
        findViewById<View>(R.id.btnJson).setOnClickListener { runExport { Exporter.exportJson(applicationContext) } }
        findViewById<View>(R.id.btnHistory).setOnClickListener { showHistory() }
        findViewById<View>(R.id.btnLists).setOnClickListener { showLists() }
        findViewById<View>(R.id.btnClear).setOnClickListener {
            if (Engine.running) toast("Detén la captura antes de limpiar")
            else {
                Engine.clearData()
                refreshList()
                refreshStats()
                toast("Datos de la sesión eliminados")
            }
        }

        selPkg = Prefs.str("sel_pkg")
        selLabel = Prefs.str("sel_label") ?: "Todas las apps"
        updateSelection()
        val p = selPkg
        if (p != null) runScan(p)

        buildRules()
        updateIocInfo()
        showTab(0)
        setFilter(0)
        refreshStats()

        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notifPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    override fun onStart() {
        super.onStart()
        Engine.logListener = { line -> appendLog(line) }
        ui.post(statsTicker)
    }

    override fun onStop() {
        super.onStop()
        Engine.logListener = null
        ui.removeCallbacks(statsTicker)
    }

    // ------------------------------------------------------------------ helpers de UI

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()
    private fun toast(s: String) = Toast.makeText(this, s, Toast.LENGTH_SHORT).show()
    private fun col(id: Int) = ContextCompat.getColor(this, id)

    private fun info(title: String, msg: String) {
        AlertDialog.Builder(this).setTitle(title).setMessage(msg).setPositiveButton("OK", null).show()
    }

    private fun styleChip(v: TextView, selected: Boolean) {
        v.setTextColor(col(if (selected) R.color.cyan else R.color.gray))
        v.setBackgroundResource(if (selected) R.drawable.bg_btn_ghost else R.drawable.bg_card)
    }

    private fun showTab(i: Int) {
        tab = i
        panelApp.visibility = if (i == 0) View.VISIBLE else View.GONE
        panelConn.visibility = if (i == 1) View.VISIBLE else View.GONE
        panelTools.visibility = if (i == 2) View.VISIBLE else View.GONE
        styleChip(tabApp, i == 0)
        styleChip(tabConn, i == 1)
        styleChip(tabTools, i == 2)
        if (i == 1) refreshList()
        if (i == 2) updateIocInfo()
    }

    private fun setFilter(f: Int) {
        filter = f
        styleChip(fAll, f == 0)
        styleChip(fRed, f == 1)
        styleChip(fAmber, f == 2)
        styleChip(fTime, f == 3)
        refreshList()
    }

    private fun appendLog(line: String) {
        logLines.add(line)
        while (logLines.size > 25) logLines.removeAt(0)
        tvLog.text = logLines.joinToString("\n")
    }

    private fun updateSelection() {
        btnPick.text = "[ APP: $selLabel ]"
    }

    // ------------------------------------------------------------------ selección y escaneo de app

    private fun pickApp() {
        btnPick.isEnabled = false
        Thread {
            val pm = packageManager
            val list = ArrayList<AppItem>()
            for (ai in pm.getInstalledApplications(PackageManager.GET_META_DATA)) {
                if (ai.packageName == packageName) continue
                if (pm.getLaunchIntentForPackage(ai.packageName) == null) continue
                list.add(AppItem(ai.packageName, pm.getApplicationLabel(ai).toString()))
            }
            list.sortBy { it.label.lowercase() }
            list.add(0, AppItem(null, "Todas las apps (excepto Sniffer)"))
            runOnUiThread {
                btnPick.isEnabled = !Engine.running
                showAppDialog(list)
            }
        }.start()
    }

    private fun showAppDialog(all: List<AppItem>) {
        val box = LinearLayout(this)
        box.orientation = LinearLayout.VERTICAL
        box.setPadding(dp(16), dp(8), dp(16), 0)
        val search = EditText(this)
        search.hint = "Buscar app…"
        search.setSingleLine()
        val lv = ListView(this)
        box.addView(search)
        box.addView(lv, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(380)))

        var shown: List<AppItem> = all
        val ad = ArrayAdapter(this, android.R.layout.simple_list_item_1, ArrayList(all))
        lv.adapter = ad
        search.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, st: Int, c: Int, a: Int) {}
            override fun onTextChanged(s: CharSequence?, st: Int, b: Int, c: Int) {}
            override fun afterTextChanged(s: Editable?) {
                val q = s.toString().trim().lowercase()
                shown = all.filter { q.isEmpty() || it.label.lowercase().contains(q) || (it.pkg ?: "").contains(q) }
                ad.clear()
                ad.addAll(shown)
                ad.notifyDataSetChanged()
            }
        })
        val dlg = AlertDialog.Builder(this)
            .setTitle("Elegir app a capturar")
            .setView(box)
            .setNegativeButton("Cancelar", null)
            .create()
        lv.setOnItemClickListener { _, _, pos, _ ->
            val chosen = shown[pos]
            dlg.dismiss()
            onAppChosen(chosen)
        }
        dlg.show()
    }

    private fun onAppChosen(item: AppItem) {
        selPkg = item.pkg
        selLabel = item.label
        Prefs.setStr("sel_pkg", item.pkg)
        Prefs.setStr("sel_label", item.label)
        updateSelection()
        val p = item.pkg
        if (p == null) {
            Engine.lastScan = null
            tvAppReport.setTextColor(col(R.color.gray))
            tvAppReport.text = "Modo todas las apps: se capturará el tráfico de todo el dispositivo y cada conexión se atribuirá a su app (Android 10 o superior).\n\nElige una app concreta para ver su ficha de escaneo antes de capturar."
        } else {
            runScan(p)
        }
    }

    private fun runScan(pkg: String) {
        tvAppReport.setTextColor(col(R.color.gray))
        tvAppReport.text = "Escaneando $pkg…"
        Thread {
            val r = try { AppScanner.scan(applicationContext, pkg) } catch (e: Exception) { null }
            runOnUiThread {
                if (r == null) {
                    tvAppReport.text = "No se pudo escanear la app (¿fue desinstalada?)."
                } else {
                    Engine.lastScan = r
                    tvAppReport.text = Report.format(r)
                }
            }
        }.start()
    }

    // ------------------------------------------------------------------ captura

    private fun requestVpnAndStart() {
        val intent = VpnService.prepare(this)
        if (intent != null) vpnPermission.launch(intent) else startCapture()
    }

    private fun startCapture() {
        val i = Intent(this, MyVpnService::class.java)
            .setAction(MyVpnService.ACTION_START)
            .putExtra(MyVpnService.EXTRA_PKG, selPkg)
            .putExtra(MyVpnService.EXTRA_LABEL, selLabel)
        ContextCompat.startForegroundService(this, i)
        appendLog("$ ./traffic-sniffer --start --target \"$selLabel\"")
        showTab(1)
    }

    private fun stopCapture() {
        val i = Intent(this, MyVpnService::class.java).setAction(MyVpnService.ACTION_STOP)
        startService(i)
        appendLog("$ ./traffic-sniffer --stop")
    }

    private fun refreshStats() {
        val running = Engine.running
        tvPackets.text = Engine.packets.get().toString()
        tvBytes.text = humanBytes(Engine.bytes.get())
        tvStatus.text = if (running) "ON" else "OFF"
        tvStatus.setTextColor(col(if (running) R.color.green else R.color.red))
        tvSys.text = "SYS://UNDERCODE.ORG · " + if (running) "CAPTURING · ${Engine.sessionLabel}" else "IDLE"
        btnStart.isEnabled = !running
        btnStart.alpha = if (running) 0.4f else 1f
        btnStop.isEnabled = running
        btnStop.alpha = if (running) 1f else 0.4f
        btnPick.isEnabled = !running
        val recs = Engine.records.values
        val red = recs.count { it.level == Level.RED }
        val amber = recs.count { it.level == Level.AMBER }
        tvConns.text = recs.size.toString()
        tvReds.text = "$red / $amber"
        tvReds.setTextColor(col(if (red > 0) R.color.red else if (amber > 0) R.color.amber else R.color.white))
    }

    // ------------------------------------------------------------------ lista de conexiones

    private fun refreshList() {
        val recs = Engine.records.values.toList()
        val red = recs.count { it.level == Level.RED }
        val amber = recs.count { it.level == Level.AMBER }
        val upOff = recs.sumOf { it.screenOffUp.get() }
        tvSummary.text = "${recs.size} destinos · $red rojos · $amber ámbar · QUIC bloqueado: ${Engine.quicBlocked.get()} · ↑ pantalla apagada: ${humanBytes(upOff)}"
        if (filter == 3) {
            adapter.setEvents(Engine.eventsSnapshot().asReversed().take(400))
        } else {
            var l = recs
            if (filter == 1) l = l.filter { it.level == Level.RED }
            else if (filter == 2) l = l.filter { it.level == Level.AMBER }
            l = l.sortedWith(
                compareByDescending<ConnRecord> { it.level.ordinal }
                    .thenByDescending { it.score }
                    .thenByDescending { it.lastSeen }
            ).take(500)
            adapter.setRecords(l)
        }
    }

    private inner class ConnAdapter : BaseAdapter() {
        private var recs: List<ConnRecord> = emptyList()
        private var evs: List<Event> = emptyList()
        private var timeline = false
        private val tf = SimpleDateFormat("HH:mm:ss", Locale.getDefault())

        fun setRecords(l: List<ConnRecord>) { recs = l; timeline = false; notifyDataSetChanged() }
        fun setEvents(l: List<Event>) { evs = l; timeline = true; notifyDataSetChanged() }

        override fun getCount(): Int = if (timeline) evs.size else recs.size
        override fun getItem(position: Int): Any = if (timeline) evs[position] else recs[position]
        override fun getItemId(position: Int): Long = position.toLong()

        private fun levelColor(l: Level) = col(
            when (l) { Level.RED -> R.color.red; Level.AMBER -> R.color.amber; Level.GREEN -> R.color.green }
        )

        override fun getView(position: Int, convertView: View?, parent: ViewGroup?): View {
            val v = convertView ?: layoutInflater.inflate(R.layout.row_conn, parent, false)
            val dot = v.findViewById<View>(R.id.viewDot)
            val title = v.findViewById<TextView>(R.id.tvRowTitle)
            val sub = v.findViewById<TextView>(R.id.tvRowSub)
            val why = v.findViewById<TextView>(R.id.tvRowReasons)
            val level: Level
            if (timeline) {
                val e = evs[position]
                level = e.rec.level
                title.text = e.text
                sub.text = "${tf.format(Date(e.time))} · ${e.rec.appLabel} · pantalla ${if (e.screenOn) "on" else "off"}"
                why.text = ""
            } else {
                val r = recs[position]
                level = r.level
                val blocked = r.blockedCount.get() > 0
                title.text = (if (blocked) "[BLOQ] " else "") + r.title()
                sub.text = "${r.proto} · ${r.appLabel} · ↑${humanBytes(r.bytesUp.get())} ↓${humanBytes(r.bytesDown.get())} · ${r.flows.get()} conex."
                why.text = if (r.reasonText.isEmpty()) "" else r.reasonText.take(2).joinToString(" | ")
            }
            val gd = GradientDrawable()
            gd.shape = GradientDrawable.OVAL
            gd.setColor(levelColor(level))
            dot.background = gd
            why.setTextColor(levelColor(level))
            return v
        }
    }

    private fun showDetail(r: ConnRecord) {
        val df = SimpleDateFormat("HH:mm:ss", Locale.getDefault())
        val sb = StringBuilder()
        sb.append("Destino: ${r.title()}\n")
        sb.append("IP: ${r.ip}:${r.port} (${r.proto})\n")
        sb.append("App: ${r.appLabel}\n")
        val names = r.names()
        if (names.isNotEmpty()) sb.append("Nombres vistos: ${names.joinToString(", ")}\n")
        r.tlsVersion?.let { sb.append("TLS: $it\n") }
        sb.append("Conexiones: ${r.flows.get()} · ↑ ${humanBytes(r.bytesUp.get())} · ↓ ${humanBytes(r.bytesDown.get())}\n")
        sb.append("Primera vez: ${df.format(Date(r.firstSeen))} · última: ${df.format(Date(r.lastSeen))}\n")
        sb.append("Puntuación: ${r.score} → ${Report.levelName(r.level).replace("ALTO", "ROJO").replace("MEDIO", "ÁMBAR").replace("BAJO", "VERDE")}\n")
        if (r.blockedCount.get() > 0) sb.append("Intentos bloqueados: ${r.blockedCount.get()}\n")
        sb.append("\n")
        if (r.reasonText.isEmpty()) sb.append("Sin indicios de riesgo con las reglas activas.")
        else {
            sb.append("Motivos:\n")
            for (x in r.reasonText) sb.append("• $x\n")
        }
        val target = r.domain ?: r.ip
        val isBlocked = Firewall.isDomainBlocked(target) || Firewall.isIpBlocked(r.ip)
        AlertDialog.Builder(this)
            .setTitle(r.title())
            .setMessage(sb.toString())
            .setPositiveButton(if (r.trusted) "Quitar confianza" else "Confiar") { _, _ ->
                Engine.setTrusted(r.key, !r.trusted)
                refreshList()
            }
            .setNegativeButton(if (isBlocked) "Desbloquear" else "Bloquear") { _, _ ->
                if (isBlocked) {
                    Firewall.unblock(target)
                    Firewall.unblock(r.ip)
                    toast("Desbloqueado")
                } else {
                    Firewall.block(target)
                    toast("Bloqueado: $target")
                }
            }
            .setNeutralButton("VirusTotal") { _, _ ->
                val d = r.domain
                val url = if (d != null && !Analyzer.isIp(d)) "https://www.virustotal.com/gui/domain/$d"
                else "https://www.virustotal.com/gui/ip-address/${r.ip}"
                try { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) } catch (_: Exception) {}
            }
            .show()
    }

    // ------------------------------------------------------------------ herramientas

    private fun buildRules() {
        rulesContainer.removeAllViews()
        for (r in Rule.values()) addSwitch("rule_" + r.id, r.title, r.defaultOn)
        addSwitch("block_quic", "Bloquear QUIC (UDP 443) para poder ver el SNI", true)
        addSwitch("autoblock_ioc", "Bloquear automáticamente lo que coincida con un IoC", false)
        addSwitch("save_pcap", "Guardar PCAP durante la captura (máx. 64 MB)", true)
    }

    private fun addSwitch(key: String, title: String, def: Boolean) {
        val sw = SwitchCompat(this)
        sw.text = title
        sw.textSize = 12f
        sw.typeface = Typeface.MONOSPACE
        sw.setTextColor(col(R.color.white))
        sw.isChecked = Prefs.bool(key, def)
        sw.setOnCheckedChangeListener { _, c ->
            Prefs.setBool(key, c)
            if (key.startsWith("rule_")) Engine.evaluateAll()
        }
        val lp = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        lp.topMargin = dp(8)
        rulesContainer.addView(sw, lp)
    }

    private fun updateIocInfo() {
        val t = Prefs.long("ioc_updated", 0)
        val whenTxt = if (t == 0L) "nunca" else SimpleDateFormat("dd/MM HH:mm", Locale.getDefault()).format(Date(t))
        tvIoc.text = "Cargados: ${Analyzer.iocDomainCount} dominios · ${Analyzer.iocIpCount} IPs\n" +
            "Última actualización: $whenTxt\n" +
            "Fuentes: abuse.ch (URLhaus, Feodo Tracker) + tus IoC manuales."
    }

    private fun updateIoc() {
        btnUpdate.isEnabled = false
        tvIoc.text = "Descargando listas…"
        Thread {
            val res = try { IocUpdater.update(applicationContext) } catch (e: Exception) { "Error: ${e.message}" }
            runOnUiThread {
                btnUpdate.isEnabled = true
                updateIocInfo()
                Engine.evaluateAll()
                info("Listas de amenazas", res)
            }
        }.start()
    }

    private fun addIocDialog() {
        val et = EditText(this)
        et.hint = "Un dominio o IP por línea"
        et.minLines = 4
        et.gravity = Gravity.TOP
        AlertDialog.Builder(this)
            .setTitle("Añadir IoC manual")
            .setView(et)
            .setPositiveButton("Añadir") { _, _ ->
                val set = Prefs.set("custom_ioc")
                et.text.toString().lines().map { it.trim().lowercase() }.filter { it.isNotEmpty() }.forEach { set.add(it) }
                Prefs.setSet("custom_ioc", set)
                Analyzer.load(applicationContext)
                updateIocInfo()
                Engine.evaluateAll()
                toast("IoC añadidos")
            }
            .setNegativeButton("Cancelar", null)
            .show()
    }

    private fun runExport(task: () -> String) {
        Thread {
            val m = try { task() } catch (e: Exception) { "Error: ${e.message}" }
            runOnUiThread { info("Exportar", m) }
        }.start()
    }

    private fun showHistory() {
        val list = SessionStore.load(this).reversed()
        if (list.isEmpty()) {
            info("Historial", "Aún no hay sesiones guardadas. Se guardan al detener una captura.")
            return
        }
        val df = SimpleDateFormat("dd/MM HH:mm", Locale.getDefault())
        val items = list.map {
            "${df.format(Date(it.start))} · ${it.label} v${it.version}\n   rojos ${it.red} · ámbar ${it.amber} · destinos ${it.total}"
        }.toTypedArray()
        AlertDialog.Builder(this)
            .setTitle("Historial de sesiones")
            .setItems(items) { _, i -> showSession(list[i]) }
            .setNegativeButton("Cerrar", null)
            .show()
    }

    private fun showSession(s: Session) {
        val all = SessionStore.load(this)
        val prev = all.filter { it.pkg == s.pkg && it.start < s.start }.maxByOrNull { it.start }
        val df = SimpleDateFormat("dd/MM/yyyy HH:mm", Locale.getDefault())
        val sb = StringBuilder()
        sb.append("${s.label} · v${s.version}\n")
        sb.append("Inicio: ${df.format(Date(s.start))} · duración ${(s.end - s.start) / 1000} s\n")
        sb.append("Paquetes: ${s.packets} · datos: ${humanBytes(s.bytes)}\n")
        sb.append("Destinos: ${s.total} · rojos ${s.red} · ámbar ${s.amber}\n\n")
        sb.append(SessionStore.diffText(s, prev))
        info("Sesión", sb.toString())
    }

    private fun showLists() {
        val blocked = Firewall.entries.toList().sorted()
        val trusted = Engine.trusted.toList().sorted()
        val labels = ArrayList<String>()
        for (b in blocked) labels.add("🚫 $b")
        for (t in trusted) labels.add("✔ $t")
        if (labels.isEmpty()) {
            info("Bloqueados y confiables", "Todavía no bloqueaste ni marcaste como confiable ningún destino.\n\nHazlo tocando una conexión en la pestaña CONEXIONES.")
            return
        }
        val checked = BooleanArray(labels.size)
        AlertDialog.Builder(this)
            .setTitle("Marca los que quieras quitar")
            .setMultiChoiceItems(labels.toTypedArray(), checked) { _, i, c -> checked[i] = c }
            .setPositiveButton("Quitar seleccionados") { _, _ ->
                for (i in checked.indices) {
                    if (!checked[i]) continue
                    if (i < blocked.size) Firewall.unblock(blocked[i])
                    else Engine.setTrusted(trusted[i - blocked.size], false)
                }
                refreshList()
            }
            .setNegativeButton("Cerrar", null)
            .show()
    }
}
