package com.undercode.sniffer

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

class Session(
    val id: Long,
    val start: Long,
    val end: Long,
    val pkg: String?,
    val label: String,
    val version: String,
    val packets: Long,
    val bytes: Long,
    val red: Int,
    val amber: Int,
    val total: Int,
    val dests: Map<String, String>
)

/** Historial de sesiones de captura (para comparar versiones de una misma app). */
object SessionStore {
    private const val FILE = "sessions.json"

    fun load(ctx: Context): List<Session> {
        val out = ArrayList<Session>()
        try {
            val f = File(ctx.filesDir, FILE)
            if (!f.exists()) return out
            val arr = JSONArray(f.readText())
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                val d = LinkedHashMap<String, String>()
                val dj = o.optJSONObject("dests")
                if (dj != null) {
                    val it = dj.keys()
                    while (it.hasNext()) {
                        val k = it.next()
                        d[k] = dj.optString(k)
                    }
                }
                out.add(
                    Session(
                        o.optLong("id"), o.optLong("start"), o.optLong("end"),
                        if (o.isNull("pkg")) null else o.optString("pkg"),
                        o.optString("label"), o.optString("version"),
                        o.optLong("packets"), o.optLong("bytes"),
                        o.optInt("red"), o.optInt("amber"), o.optInt("total"), d
                    )
                )
            }
        } catch (_: Exception) {
        }
        return out
    }

    fun saveCurrent(ctx: Context) {
        val recs = Engine.records.values.toList()
        if (recs.isEmpty() && Engine.packets.get() == 0L) return
        val pkg = Engine.sessionPkg
        val version = try {
            if (pkg != null) ctx.packageManager.getPackageInfo(pkg, 0).versionName ?: "?" else "-"
        } catch (_: Exception) {
            "?"
        }
        val dests = JSONObject()
        val sorted = recs.sortedByDescending { it.level.ordinal * 1000 + it.score }
        var n = 0
        for (r in sorted) {
            val name = if (r.isDns) (r.domain ?: r.ip) else (r.domain ?: r.ip)
            if (!dests.has(name)) {
                dests.put(name, r.level.name)
                n++
            }
            if (n >= 300) break
        }
        val o = JSONObject()
        o.put("id", Engine.sessionStart)
        o.put("start", Engine.sessionStart)
        o.put("end", if (Engine.sessionEnd > 0) Engine.sessionEnd else System.currentTimeMillis())
        o.put("pkg", pkg ?: JSONObject.NULL)
        o.put("label", Engine.sessionLabel)
        o.put("version", version)
        o.put("packets", Engine.packets.get())
        o.put("bytes", Engine.bytes.get())
        o.put("red", recs.count { it.level == Level.RED })
        o.put("amber", recs.count { it.level == Level.AMBER })
        o.put("total", recs.size)
        o.put("dests", dests)

        val existing = ArrayList<JSONObject>()
        try {
            val f = File(ctx.filesDir, FILE)
            if (f.exists()) {
                val arr = JSONArray(f.readText())
                for (i in 0 until arr.length()) existing.add(arr.getJSONObject(i))
            }
        } catch (_: Exception) {
        }
        existing.add(o)
        val keep = existing.takeLast(50)
        val outArr = JSONArray()
        for (e in keep) outArr.put(e)
        File(ctx.filesDir, FILE).writeText(outArr.toString())
    }

    fun diffText(cur: Session, prev: Session?): String {
        if (prev == null) return "No hay una sesión anterior de esta app para comparar."
        val added = cur.dests.keys.filter { it !in prev.dests }
        val removed = prev.dests.keys.filter { it !in cur.dests }
        val sb = StringBuilder()
        sb.append("Comparado con la sesión anterior (v${prev.version}):\n")
        sb.append("• Destinos nuevos: ${added.size}\n")
        for (a in added.take(25)) sb.append("   + $a [${cur.dests[a]}]\n")
        if (added.size > 25) sb.append("   … y ${added.size - 25} más\n")
        sb.append("• Destinos que ya no aparecen: ${removed.size}\n")
        for (a in removed.take(15)) sb.append("   - $a\n")
        if (removed.size > 15) sb.append("   … y ${removed.size - 15} más\n")
        return sb.toString()
    }
}
