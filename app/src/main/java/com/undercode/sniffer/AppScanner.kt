package com.undercode.sniffer

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Typeface
import android.os.Build
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.text.style.StyleSpan
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.zip.ZipFile

class ScanResult(
    val pkg: String,
    val label: String,
    val versionName: String,
    val installer: String,
    val targetSdk: Int,
    val debuggable: Boolean,
    val cleartext: Boolean,
    val system: Boolean,
    val firstInstall: Long,
    val lastUpdate: Long,
    val certSha: String,
    val debugCert: Boolean,
    val perms: List<String>,
    val trackers: List<String>,
    val caps: List<String>,
    val score: Int,
    val level: Level,
    val reasons: List<String>
)

/** Análisis estático (sin ejecutar la app): permisos, configuración, firma y SDKs incluidos. */
object AppScanner {

    private val permWeights = mapOf(
        "RECORD_AUDIO" to Pair(8, "micrófono"),
        "CAMERA" to Pair(5, "cámara"),
        "READ_SMS" to Pair(12, "leer SMS"),
        "SEND_SMS" to Pair(12, "enviar SMS"),
        "RECEIVE_SMS" to Pair(10, "recibir SMS"),
        "READ_CONTACTS" to Pair(6, "leer contactos"),
        "READ_CALL_LOG" to Pair(8, "registro de llamadas"),
        "PROCESS_OUTGOING_CALLS" to Pair(8, "interceptar llamadas salientes"),
        "READ_PHONE_STATE" to Pair(3, "estado e identificadores del teléfono"),
        "CALL_PHONE" to Pair(4, "realizar llamadas"),
        "ACCESS_FINE_LOCATION" to Pair(5, "ubicación precisa"),
        "ACCESS_BACKGROUND_LOCATION" to Pair(10, "ubicación en segundo plano"),
        "ACCESS_COARSE_LOCATION" to Pair(2, "ubicación aproximada"),
        "SYSTEM_ALERT_WINDOW" to Pair(12, "superposición sobre otras apps"),
        "BIND_ACCESSIBILITY_SERVICE" to Pair(20, "servicio de accesibilidad"),
        "REQUEST_INSTALL_PACKAGES" to Pair(10, "instalar otras apps"),
        "INSTALL_PACKAGES" to Pair(15, "instalar paquetes"),
        "BIND_DEVICE_ADMIN" to Pair(15, "administrador del dispositivo"),
        "MANAGE_EXTERNAL_STORAGE" to Pair(8, "acceso a todo el almacenamiento"),
        "READ_EXTERNAL_STORAGE" to Pair(2, "leer almacenamiento"),
        "QUERY_ALL_PACKAGES" to Pair(4, "listar todas las apps instaladas"),
        "BIND_NOTIFICATION_LISTENER_SERVICE" to Pair(12, "leer notificaciones"),
        "PACKAGE_USAGE_STATS" to Pair(6, "estadísticas de uso de apps"),
        "WRITE_SETTINGS" to Pair(4, "modificar ajustes del sistema"),
        "RECEIVE_BOOT_COMPLETED" to Pair(2, "iniciarse al encender")
    )

    private val trackerSigs = mapOf(
        "Lcom/google/firebase/analytics/" to "Firebase Analytics",
        "Lcom/google/android/gms/ads/" to "Google Ads / AdMob",
        "Lcom/facebook/ads/" to "Facebook Audience Network",
        "Lcom/facebook/appevents/" to "Facebook SDK (eventos)",
        "Lcom/appsflyer/" to "AppsFlyer",
        "Lcom/adjust/sdk/" to "Adjust",
        "Lio/branch/" to "Branch",
        "Lcom/mixpanel/" to "Mixpanel",
        "Lcom/amplitude/" to "Amplitude",
        "Lcom/flurry/" to "Flurry",
        "Lcom/unity3d/ads/" to "Unity Ads",
        "Lcom/applovin/" to "AppLovin",
        "Lcom/ironsource/" to "ironSource",
        "Lcom/vungle/" to "Vungle",
        "Lcom/chartboost/" to "Chartboost",
        "Lcom/inmobi/" to "InMobi",
        "Lcom/mopub/" to "MoPub",
        "Lcom/startapp/" to "StartApp",
        "Lcom/onesignal/" to "OneSignal",
        "Lcom/segment/analytics/" to "Segment",
        "Lcom/yandex/metrica/" to "Yandex Metrica",
        "Lcom/bytedance/sdk/openadsdk" to "Pangle (ByteDance)",
        "Lcom/adcolony/" to "AdColony",
        "Lcom/kochava/" to "Kochava",
        "Lcom/tapjoy/" to "Tapjoy",
        "Lcom/fyber/" to "Fyber"
    )

    private val capSigs = mapOf(
        "Ldalvik/system/DexClassLoader;" to Pair(8, "carga código dinámicamente (DexClassLoader)"),
        "Ldalvik/system/InMemoryDexClassLoader;" to Pair(8, "carga código dinámicamente en memoria"),
        "Landroid/telephony/SmsManager;" to Pair(6, "usa SmsManager (SMS)"),
        "Landroid/accessibilityservice/AccessibilityService;" to Pair(10, "implementa un servicio de accesibilidad"),
        "Landroid/app/admin/DevicePolicyManager;" to Pair(6, "usa administración de dispositivo"),
        "Landroid/media/projection/MediaProjection" to Pair(6, "puede capturar la pantalla"),
        "Ljavax/net/ssl/X509TrustManager;" to Pair(3, "implementa un TrustManager propio (revisar validación TLS)")
    )

    private val trustedInstallers = setOf(
        "com.android.vending", "com.sec.android.app.samsungapps", "com.huawei.appmarket",
        "com.amazon.venezia", "org.fdroid.fdroid", "com.xiaomi.mipicks", "com.heytap.market"
    )

    private fun scanDex(path: String, sigs: Collection<String>): Set<String> {
        val found = HashSet<String>()
        val remaining = ArrayList(sigs)
        try {
            ZipFile(path).use { zf ->
                val en = zf.entries()
                while (en.hasMoreElements() && remaining.isNotEmpty()) {
                    val e = en.nextElement()
                    if (!e.name.startsWith("classes") || !e.name.endsWith(".dex")) continue
                    zf.getInputStream(e).use { ins ->
                        val buf = ByteArray(256 * 1024)
                        var carry = ""
                        while (remaining.isNotEmpty()) {
                            val n = ins.read(buf)
                            if (n < 0) break
                            val chunk = carry + String(buf, 0, n, Charsets.ISO_8859_1)
                            val iter = remaining.iterator()
                            while (iter.hasNext()) {
                                val s = iter.next()
                                if (chunk.contains(s)) {
                                    found.add(s)
                                    iter.remove()
                                }
                            }
                            carry = chunk.takeLast(100)
                        }
                    }
                }
            }
        } catch (_: Exception) {
        }
        return found
    }

    @Suppress("DEPRECATION")
    private fun legacyInstaller(pm: PackageManager, pkg: String): String? = pm.getInstallerPackageName(pkg)

    private fun installerOf(pm: PackageManager, pkg: String): String? = try {
        if (Build.VERSION.SDK_INT >= 30) pm.getInstallSourceInfo(pkg).installingPackageName
        else legacyInstaller(pm, pkg)
    } catch (_: Exception) {
        null
    }

    fun scan(ctx: Context, pkg: String): ScanResult {
        val pm = ctx.packageManager
        val pi = pm.getPackageInfo(
            pkg, PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNING_CERTIFICATES
        )
        val ai: ApplicationInfo = pi.applicationInfo ?: pm.getApplicationInfo(pkg, 0)
        val label = pm.getApplicationLabel(ai).toString()
        val system = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0
        val debuggable = (ai.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        val cleartext = (ai.flags and ApplicationInfo.FLAG_USES_CLEARTEXT_TRAFFIC) != 0
        val installerRaw = installerOf(pm, pkg)
        val installer = installerRaw ?: "desconocido (instalación manual)"

        var certSha = "desconocida"
        var debugCert = false
        try {
            val sigs = pi.signingInfo?.apkContentsSigners
            if (sigs != null && sigs.isNotEmpty()) {
                val der = sigs[0].toByteArray()
                certSha = MessageDigest.getInstance("SHA-256").digest(der)
                    .joinToString(":") { "%02X".format(it) }
                val cert = CertificateFactory.getInstance("X.509")
                    .generateCertificate(ByteArrayInputStream(der)) as X509Certificate
                debugCert = cert.subjectX500Principal.name.contains("Android Debug", ignoreCase = true)
            }
        } catch (_: Exception) {
        }

        var score = 0
        val reasons = ArrayList<String>()
        val permList = ArrayList<String>()
        val requested = pi.requestedPermissions ?: emptyArray()
        for (full in requested) {
            val short = full.substringAfterLast('.')
            val w = permWeights[short] ?: continue
            score += w.first
            permList.add("$short — ${w.second}")
        }
        if (permList.isNotEmpty()) reasons.add("Pide ${permList.size} permisos sensibles")

        if (!system && (installerRaw == null || installerRaw !in trustedInstallers)) {
            score += 10
            reasons.add("No procede de una tienda conocida (instalador: $installer)")
        }
        if (debuggable) {
            score += 12
            reasons.add("Es depurable (debuggable): permite inspeccionarla")
        }
        if (cleartext) {
            score += 5
            reasons.add("Permite tráfico HTTP sin cifrar")
        }
        if (ai.targetSdkVersion < 28) {
            score += 8
            reasons.add("Apunta a Android ${ai.targetSdkVersion}: omite protecciones modernas")
        }
        if (debugCert) {
            score += 10
            reasons.add("Está firmada con un certificado de depuración")
        }

        val allSigs = ArrayList<String>()
        allSigs.addAll(trackerSigs.keys)
        allSigs.addAll(capSigs.keys)
        val found = scanDex(ai.sourceDir, allSigs)
        val trackers = trackerSigs.filterKeys { it in found }.values.distinct()
        if (trackers.isNotEmpty()) {
            score += minOf(15, trackers.size * 3)
            reasons.add("Incluye ${trackers.size} SDK de rastreo / publicidad")
        }
        val caps = ArrayList<String>()
        for ((sig, info) in capSigs) {
            if (sig in found) {
                score += info.first
                caps.add(info.second)
            }
        }
        if (caps.isNotEmpty()) reasons.add("Capacidades notables en el código (${caps.size})")

        score = minOf(score, 100)
        val level = when {
            score >= 45 -> Level.RED
            score >= 20 -> Level.AMBER
            else -> Level.GREEN
        }
        return ScanResult(
            pkg, label, pi.versionName ?: "?", installer, ai.targetSdkVersion, debuggable, cleartext,
            system, pi.firstInstallTime, pi.lastUpdateTime, certSha, debugCert,
            permList, trackers, caps, score, level, reasons
        )
    }
}

/** Formatea la ficha de escaneo para mostrarla con colores. */
object Report {
    const val CYAN = 0xFF00E5FF.toInt()
    const val RED = 0xFFFF5252.toInt()
    const val AMBER = 0xFFFFB300.toInt()
    const val GREEN = 0xFF4CAF50.toInt()
    const val GRAY = 0xFF8A97A8.toInt()
    const val TEXT = 0xFFDDE6EE.toInt()

    fun levelColor(l: Level) = when (l) { Level.RED -> RED; Level.AMBER -> AMBER; Level.GREEN -> GREEN }
    fun levelName(l: Level) = when (l) { Level.RED -> "ALTO"; Level.AMBER -> "MEDIO"; Level.GREEN -> "BAJO" }

    fun format(r: ScanResult): CharSequence {
        val sb = SpannableStringBuilder()
        val df = SimpleDateFormat("dd/MM/yyyy HH:mm", Locale.getDefault())
        fun add(text: String, color: Int = TEXT, bold: Boolean = false) {
            val st = sb.length
            sb.append(text)
            sb.setSpan(ForegroundColorSpan(color), st, sb.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            if (bold) sb.setSpan(StyleSpan(Typeface.BOLD), st, sb.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
        }
        add("${r.label}\n", CYAN, true)
        add("${r.pkg} · v${r.versionName}\n", GRAY)
        add("RIESGO ESTÁTICO: ${levelName(r.level)} (${r.score}/100)\n", levelColor(r.level), true)
        for (x in r.reasons) add("• $x\n")
        if (r.perms.isNotEmpty()) {
            add("\nPermisos sensibles\n", CYAN, true)
            for (x in r.perms) add("  $x\n", AMBER)
        }
        if (r.trackers.isNotEmpty()) {
            add("\nSDK de rastreo / publicidad\n", CYAN, true)
            add("  " + r.trackers.joinToString(", ") + "\n", AMBER)
        }
        if (r.caps.isNotEmpty()) {
            add("\nCapacidades en el código\n", CYAN, true)
            for (x in r.caps) add("  $x\n", AMBER)
        }
        add("\nDatos de la app\n", CYAN, true)
        add("  Instalador: ${r.installer}\n", GRAY)
        add("  Instalada: ${df.format(Date(r.firstInstall))}\n", GRAY)
        add("  Actualizada: ${df.format(Date(r.lastUpdate))}\n", GRAY)
        add("  Target SDK: ${r.targetSdk}${if (r.system) " · app del sistema" else ""}\n", GRAY)
        add("  Cert SHA-256: ${r.certSha.take(47)}…\n", GRAY)
        add("\nEs un análisis heurístico: indica motivos de sospecha, no un veredicto de malware.\n", GRAY)
        return sb
    }

    fun plain(r: ScanResult): String = format(r).toString()
}
