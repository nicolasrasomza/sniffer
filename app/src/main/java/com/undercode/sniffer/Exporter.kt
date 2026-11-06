package com.undercode.sniffer

import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Environment
import android.provider.MediaStore
import androidx.core.content.FileProvider
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.OutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Exporta PCAP e informes (HTML / JSON) a la carpeta Descargas/UndercodeSniffer. */
private const val HTTP_SHOWN_CHARS = 1500

object Exporter {
    private val stamp get() = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())

    private fun saveToDownloads(ctx: Context, name: String, mime: String, write: (OutputStream) -> Unit): String? {
        val cv = ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, name)
            put(MediaStore.MediaColumns.MIME_TYPE, mime)
            put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/UndercodeSniffer")
        }
        val uri = ctx.contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv) ?: return null
        ctx.contentResolver.openOutputStream(uri)?.use { write(it) } ?: return null
        return "Descargas/UndercodeSniffer/$name"
    }

    /** Resultado de una exportación: mensaje + Uri compartible (null si no hay archivo). */
    class ExportResult(val message: String, val uri: Uri?, val mime: String, val name: String)

    /**
     * Genera el archivo en la caché de la app (para poder compartirlo) y además lo copia
     * a Descargas/UndercodeSniffer.
     */
    private fun export(ctx: Context, name: String, mime: String, write: (OutputStream) -> Unit): ExportResult {
        val dir = File(ctx.cacheDir, "exports")
        dir.mkdirs()
        dir.listFiles()?.forEach { it.delete() }
        val f = File(dir, name)
        f.outputStream().use { write(it) }
        val saved = try {
            saveToDownloads(ctx, name, mime) { out -> f.inputStream().use { it.copyTo(out) } }
        } catch (_: Exception) {
            null
        }
        val uri = FileProvider.getUriForFile(ctx, ctx.packageName + ".fileprovider", f)
        val msg = if (saved != null) "Guardado en $saved\n\n¿Quieres enviarlo por WhatsApp, correo u otra app?"
        else "No se pudo guardar en Descargas, pero puedes compartirlo ahora."
        return ExportResult(msg, uri, mime, name)
    }

    fun exportPcap(ctx: Context): ExportResult {
        Engine.pcap?.flush()
        val f = File(ctx.filesDir, "capture.pcap")
        if (!f.exists() || f.length() <= 24) {
            return ExportResult("No hay ninguna captura PCAP todavía (inicia una captura con \"Guardar PCAP\" activado).", null, "", "")
        }
        return export(ctx, "captura_$stamp.pcap", "application/vnd.tcpdump.pcap") { out ->
            f.inputStream().use { it.copyTo(out) }
        }
    }

    fun exportHtml(ctx: Context): ExportResult {
        val html = buildHtml()
        return export(ctx, "informe_$stamp.html", "text/html") { it.write(html.toByteArray(Charsets.UTF_8)) }
    }

    fun exportJson(ctx: Context): ExportResult {
        val json = buildJson().toString(2)
        return export(ctx, "informe_$stamp.json", "application/json") { it.write(json.toByteArray(Charsets.UTF_8)) }
    }

    private fun sortedRecords(): List<ConnRecord> =
        Engine.records.values.sortedWith(
            compareByDescending<ConnRecord> { it.level.ordinal }.thenByDescending { it.score }
        )

    private fun duration(): Long {
        val end = if (Engine.running || Engine.sessionEnd == 0L) System.currentTimeMillis() else Engine.sessionEnd
        return if (Engine.sessionStart == 0L) 0 else (end - Engine.sessionStart) / 1000
    }

    private fun esc(s: String) = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")

    private fun levelName(l: Level) = when (l) { Level.RED -> "ROJO"; Level.AMBER -> "ÁMBAR"; Level.GREEN -> "VERDE" }
    private fun levelCss(l: Level) = when (l) { Level.RED -> "#ff5252"; Level.AMBER -> "#ffb300"; Level.GREEN -> "#4caf50" }

    fun buildHtml(): String {
        val recs = sortedRecords()
        val tf = SimpleDateFormat("HH:mm:ss", Locale.getDefault())
        val df = SimpleDateFormat("dd/MM/yyyy HH:mm:ss", Locale.getDefault())
        val sb = StringBuilder()
        sb.append("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Undercode Sniffer · Informe</title><style>")
        sb.append("body{background:#0b0e14;color:#dfe6ee;font-family:monospace;padding:18px;max-width:1100px;margin:auto}")
        sb.append("h1,h2{color:#00e5ff}table{border-collapse:collapse;width:100%;margin:8px 0}")
        sb.append("td,th{border-bottom:1px solid #1e2a3a;padding:5px 8px;text-align:left;font-size:12px;vertical-align:top}")
        sb.append(".dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px}")
        sb.append("h3{color:#9fb3c8;font-size:13px;margin:16px 0 4px}.warn{color:#ffb300}")
        sb.append(".g{color:#8a97a8}pre{white-space:pre-wrap;background:#121826;padding:10px;border-radius:6px}</style></head><body>")
        sb.append("<h1>Undercode Sniffer · Informe de captura</h1>")
        sb.append("<p class=\"g\">Generado: ${df.format(Date())}</p>")

        sb.append("<h2>Resumen</h2><table>")
        fun row(k: String, v: String) { sb.append("<tr><td class=\"g\">${esc(k)}</td><td>${esc(v)}</td></tr>") }
        row("Objetivo", Engine.sessionLabel + (Engine.sessionPkg?.let { " ($it)" } ?: ""))
        row("Inicio", if (Engine.sessionStart > 0) df.format(Date(Engine.sessionStart)) else "-")
        row("Duración", "${duration()} s")
        row("Paquetes / bytes", "${Engine.packets.get()} / ${humanBytes(Engine.bytes.get())}")
        row("Destinos", recs.size.toString())
        row("Rojos / ámbar", "${recs.count { it.level == Level.RED }} / ${recs.count { it.level == Level.AMBER }}")
        val up = recs.sumOf { it.bytesUp.get() }
        val upOff = recs.sumOf { it.screenOffUp.get() }
        row("Subida total / con pantalla apagada", "${humanBytes(up)} / ${humanBytes(upOff)}")
        row("QUIC bloqueado (paquetes)", Engine.quicBlocked.get().toString())
        sb.append("</table>")

        val scan = Engine.lastScan
        if (scan != null && scan.pkg == Engine.sessionPkg) {
            sb.append("<h2>Ficha de la app (análisis estático)</h2><pre>${esc(Report.plain(scan))}</pre>")
        }

        sb.append("<h2>Conexiones</h2><table><tr><th>Nivel</th><th>Destino</th><th>App</th><th>Proto</th><th>IP:puerto</th><th>↑</th><th>↓</th><th>Flujos</th><th>Motivos</th></tr>")
        for (r in recs) {
            sb.append("<tr><td><span class=\"dot\" style=\"background:${levelCss(r.level)}\"></span>${levelName(r.level)}</td>")
            sb.append("<td>${esc(r.title())}</td><td>${esc(r.appLabel)}</td><td>${r.proto}</td>")
            sb.append("<td>${esc(r.ip)}:${r.port}</td><td>${humanBytes(r.bytesUp.get())}</td><td>${humanBytes(r.bytesDown.get())}</td>")
            sb.append("<td>${r.flows.get()}</td><td>${esc(r.reasonText.joinToString(" · "))}</td></tr>")
        }
        sb.append("</table>")

        val withHttp = recs.filter { it.httpSamplesList().isNotEmpty() }
        if (withHttp.isNotEmpty()) {
            sb.append("<h2>Contenido HTTP sin cifrar</h2>")
            sb.append("<p class=\"warn\">⚠ Este bloque puede contener contraseñas, tokens o datos personales en texto plano. Compártelo con cuidado.</p>")
            sb.append("<p class=\"g\">Se muestran los primeros ${HTTP_SHOWN_CHARS} caracteres de cada mensaje (hasta 30 por destino). Los cuerpos binarios o comprimidos aparecen con puntos.</p>")
            for (r in withHttp) {
                sb.append("<h3>${esc(r.title())} · ${esc(r.appLabel)}</h3>")
                for (h in r.httpSamplesList()) {
                    sb.append("<div class=\"g\">${tf.format(Date(h.time))} · ${if (h.up) "↑ petición" else "↓ respuesta"}</div>")
                    sb.append("<pre>${esc(h.text)}</pre>")
                }
            }
        }

        sb.append("<h2>Línea de tiempo (últimos 500 eventos)</h2><table><tr><th>Hora</th><th>Pantalla</th><th>Nivel</th><th>Evento</th></tr>")
        for (e in Engine.eventsSnapshot().takeLast(500)) {
            sb.append("<tr><td>${tf.format(Date(e.time))}</td><td>${if (e.screenOn) "on" else "off"}</td>")
            sb.append("<td style=\"color:${levelCss(e.rec.level)}\">${levelName(e.rec.level)}</td><td>${esc(e.text)}</td></tr>")
        }
        sb.append("</table><p class=\"g\">Análisis heurístico: los marcadores rojos / ámbar indican dónde investigar, no son un veredicto de malware. El contenido HTTPS no es visible.</p></body></html>")
        return sb.toString()
    }

    fun buildJson(): JSONObject {
        val recs = sortedRecords()
        val o = JSONObject()
        o.put("target", Engine.sessionLabel)
        o.put("package", Engine.sessionPkg ?: JSONObject.NULL)
        o.put("start", Engine.sessionStart)
        o.put("duration_s", duration())
        o.put("packets", Engine.packets.get())
        o.put("bytes", Engine.bytes.get())
        val scan = Engine.lastScan
        if (scan != null && scan.pkg == Engine.sessionPkg) {
            val s = JSONObject()
            s.put("version", scan.versionName)
            s.put("installer", scan.installer)
            s.put("target_sdk", scan.targetSdk)
            s.put("score", scan.score)
            s.put("level", scan.level.name)
            s.put("cert_sha256", scan.certSha)
            s.put("reasons", JSONArray(scan.reasons))
            s.put("permissions", JSONArray(scan.perms))
            s.put("trackers", JSONArray(scan.trackers))
            s.put("capabilities", JSONArray(scan.caps))
            o.put("static_scan", s)
        }
        val arr = JSONArray()
        for (r in recs) {
            val c = JSONObject()
            c.put("level", r.level.name)
            c.put("score", r.score)
            c.put("ioc", r.ioc)
            c.put("app", r.appLabel)
            c.put("package", r.pkg)
            c.put("proto", r.proto)
            c.put("ip", r.ip)
            c.put("port", r.port)
            c.put("names", JSONArray(r.names()))
            c.put("tls", r.tlsVersion ?: JSONObject.NULL)
            c.put("bytes_up", r.bytesUp.get())
            c.put("bytes_down", r.bytesDown.get())
            c.put("bytes_up_screen_off", r.screenOffUp.get())
            c.put("flows", r.flows.get())
            c.put("first_seen", r.firstSeen)
            c.put("last_seen", r.lastSeen)
            c.put("reasons", JSONArray(r.reasonText))
            val http = JSONArray()
            for (h in r.httpSamplesList()) {
                val x = JSONObject()
                x.put("time", h.time)
                x.put("direction", if (h.up) "request" else "response")
                x.put("text", h.text)
                http.put(x)
            }
            c.put("http_cleartext", http)
            arr.put(c)
        }
        o.put("connections", arr)
        val ev = JSONArray()
        for (e in Engine.eventsSnapshot().takeLast(500)) {
            val x = JSONObject()
            x.put("time", e.time)
            x.put("screen_on", e.screenOn)
            x.put("level", e.rec.level.name)
            x.put("text", e.text)
            ev.put(x)
        }
        o.put("timeline", ev)
        return o
    }
}
