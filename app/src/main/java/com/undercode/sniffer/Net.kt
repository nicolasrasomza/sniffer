package com.undercode.sniffer

/** Utilidades de bajo nivel: lectura/escritura de campos, checksums y construcción de paquetes IPv4. */
object Net {
    fun u8(b: ByteArray, i: Int): Int = b[i].toInt() and 0xFF
    fun u16(b: ByteArray, i: Int): Int = (u8(b, i) shl 8) or u8(b, i + 1)
    fun u32(b: ByteArray, i: Int): Long =
        (u8(b, i).toLong() shl 24) or (u8(b, i + 1).toLong() shl 16) or
            (u8(b, i + 2).toLong() shl 8) or u8(b, i + 3).toLong()

    fun put16(b: ByteArray, i: Int, v: Int) {
        b[i] = (v shr 8).toByte()
        b[i + 1] = v.toByte()
    }

    fun put32(b: ByteArray, i: Int, v: Long) {
        b[i] = (v shr 24).toByte()
        b[i + 1] = (v shr 16).toByte()
        b[i + 2] = (v shr 8).toByte()
        b[i + 3] = v.toByte()
    }

    fun ipStr(b: ByteArray, i: Int): String =
        "${u8(b, i)}.${u8(b, i + 1)}.${u8(b, i + 2)}.${u8(b, i + 3)}"

    fun checksum(b: ByteArray, off: Int, len: Int, init: Long): Int {
        var sum = init
        var i = off
        val end = off + len
        while (i + 1 < end) {
            sum += ((u8(b, i) shl 8) or u8(b, i + 1)).toLong()
            i += 2
        }
        if (i < end) sum += (u8(b, i) shl 8).toLong()
        while ((sum shr 16) != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        return (sum.inv() and 0xFFFF).toInt()
    }

    private fun pseudo(src: ByteArray, dst: ByteArray, proto: Int, len: Int): Long {
        var s = 0L
        s += ((u8(src, 0) shl 8) or u8(src, 1)).toLong()
        s += ((u8(src, 2) shl 8) or u8(src, 3)).toLong()
        s += ((u8(dst, 0) shl 8) or u8(dst, 1)).toLong()
        s += ((u8(dst, 2) shl 8) or u8(dst, 3)).toLong()
        s += proto.toLong()
        s += len.toLong()
        return s
    }

    private var ident = 1
    @Synchronized private fun nextIdent(): Int {
        ident = (ident + 1) and 0xFFFF
        return ident
    }

    private fun ipHeader(p: ByteArray, total: Int, proto: Int, src: ByteArray, dst: ByteArray) {
        p[0] = 0x45.toByte()
        p[1] = 0
        put16(p, 2, total)
        put16(p, 4, nextIdent())
        put16(p, 6, 0x4000)
        p[8] = 64
        p[9] = proto.toByte()
        p[10] = 0
        p[11] = 0
        System.arraycopy(src, 0, p, 12, 4)
        System.arraycopy(dst, 0, p, 16, 4)
        put16(p, 10, checksum(p, 0, 20, 0))
    }

    fun buildTcp(
        src: ByteArray, dst: ByteArray, sp: Int, dp: Int,
        seq: Long, ack: Long, flags: Int, window: Int,
        payload: ByteArray?, pOff: Int, pLen: Int, mss: Int
    ): ByteArray {
        val opt = if (mss > 0) 4 else 0
        val tcpLen = 20 + opt + pLen
        val total = 20 + tcpLen
        val p = ByteArray(total)
        ipHeader(p, total, 6, src, dst)
        val t = 20
        put16(p, t, sp)
        put16(p, t + 2, dp)
        put32(p, t + 4, seq)
        put32(p, t + 8, ack)
        p[t + 12] = (((20 + opt) / 4) shl 4).toByte()
        p[t + 13] = flags.toByte()
        put16(p, t + 14, window)
        if (mss > 0) {
            p[t + 20] = 2
            p[t + 21] = 4
            put16(p, t + 22, mss)
        }
        if (payload != null && pLen > 0) System.arraycopy(payload, pOff, p, t + 20 + opt, pLen)
        put16(p, t + 16, checksum(p, t, tcpLen, pseudo(src, dst, 6, tcpLen)))
        return p
    }

    fun buildUdp(
        src: ByteArray, dst: ByteArray, sp: Int, dp: Int,
        payload: ByteArray, pOff: Int, pLen: Int
    ): ByteArray {
        val udpLen = 8 + pLen
        val total = 20 + udpLen
        val p = ByteArray(total)
        ipHeader(p, total, 17, src, dst)
        val t = 20
        put16(p, t, sp)
        put16(p, t + 2, dp)
        put16(p, t + 4, udpLen)
        System.arraycopy(payload, pOff, p, t + 8, pLen)
        var c = checksum(p, t, udpLen, pseudo(src, dst, 17, udpLen))
        if (c == 0) c = 0xFFFF
        put16(p, t + 6, c)
        return p
    }
}

/** Parser mínimo de DNS (consultas y respuestas tipo A). */
object Dns {
    private fun readName(p: ByteArray, start: Int, base: Int, end: Int): Pair<String, Int>? {
        val sb = StringBuilder()
        var i = start
        var next = -1
        var jumps = 0
        while (true) {
            if (i >= end) return null
            val l = Net.u8(p, i)
            if (l == 0) {
                if (next < 0) next = i + 1
                break
            }
            if ((l and 0xC0) == 0xC0) {
                if (i + 1 >= end) return null
                val ptr = ((l and 0x3F) shl 8) or Net.u8(p, i + 1)
                if (next < 0) next = i + 2
                i = base + ptr
                jumps++
                if (jumps > 10) return null
                continue
            }
            if ((l and 0xC0) != 0) return null
            i++
            if (i + l > end) return null
            sb.append(String(p, i, l, Charsets.US_ASCII)).append('.')
            i += l
        }
        val name = sb.toString().trimEnd('.').lowercase()
        return Pair(name, next)
    }

    /** Devuelve (nombre consultado, offset donde termina la sección de pregunta). */
    fun parseQuestion(p: ByteArray, off: Int, end: Int): Pair<String, Int>? {
        if (end - off < 17) return null
        val flags = Net.u16(p, off + 2)
        if ((flags and 0x8000) != 0) return null // es respuesta
        if (Net.u16(p, off + 4) < 1) return null
        val r = readName(p, off + 12, off, end) ?: return null
        if (r.first.isEmpty()) return null
        val qEnd = r.second + 4
        if (qEnd > end) return null
        return Pair(r.first, qEnd)
    }

    /** Recorre las respuestas A y llama onA(nombrePreguntado, ip). */
    fun parseAnswers(p: ByteArray, off: Int, end: Int, onA: (String, String) -> Unit) {
        try {
            if (end - off < 12) return
            val flags = Net.u16(p, off + 2)
            if ((flags and 0x8000) == 0) return
            val qd = Net.u16(p, off + 4)
            val an = Net.u16(p, off + 6)
            var pos = off + 12
            var qname = ""
            for (k in 0 until qd) {
                val r = readName(p, pos, off, end) ?: return
                if (k == 0) qname = r.first
                pos = r.second + 4
            }
            for (k in 0 until an) {
                val r = readName(p, pos, off, end) ?: return
                pos = r.second
                if (pos + 10 > end) return
                val type = Net.u16(p, pos)
                val rdlen = Net.u16(p, pos + 8)
                val rd = pos + 10
                if (rd + rdlen > end) return
                if (type == 1 && rdlen == 4 && qname.isNotEmpty()) {
                    onA(qname, Net.ipStr(p, rd))
                }
                pos = rd + rdlen
            }
        } catch (_: Exception) {
        }
    }

    /** Construye una respuesta NXDOMAIN a partir de una consulta (para bloqueo por dominio). */
    fun nxdomain(p: ByteArray, off: Int, end: Int): ByteArray? {
        val q = parseQuestion(p, off, end) ?: return null
        val qEnd = q.second
        val len = qEnd - off
        val r = ByteArray(len)
        System.arraycopy(p, off, r, 0, len)
        Net.put16(r, 2, 0x8183)
        Net.put16(r, 4, 1)
        Net.put16(r, 6, 0)
        Net.put16(r, 8, 0)
        Net.put16(r, 10, 0)
        return r
    }
}

class TlsInfo(val sni: String?, val version: String, val old: Boolean)

/** Parser de ClientHello TLS: extrae SNI y versión. */
object Tls {
    private fun verName(v: Int): String = when (v) {
        0x0304 -> "TLS 1.3"
        0x0303 -> "TLS 1.2"
        0x0302 -> "TLS 1.1"
        0x0301 -> "TLS 1.0"
        0x0300 -> "SSL 3.0"
        else -> "TLS 0x" + Integer.toHexString(v)
    }

    fun parse(p: ByteArray, off: Int, end: Int): TlsInfo? {
        try {
            if (end - off < 12) return null
            if (Net.u8(p, off) != 0x16) return null
            var i = off + 5
            if (Net.u8(p, i) != 0x01) return null
            i += 4
            if (i + 2 > end) return null
            val legacy = Net.u16(p, i)
            i += 2 + 32
            if (i >= end) return null
            i += 1 + Net.u8(p, i)
            if (i + 2 > end) return null
            i += 2 + Net.u16(p, i)
            if (i + 1 > end) return null
            i += 1 + Net.u8(p, i)
            var maxVer = legacy
            var sni: String? = null
            if (i + 2 <= end) {
                val extTotal = Net.u16(p, i)
                i += 2
                val extEnd = minOf(end, i + extTotal)
                while (i + 4 <= extEnd) {
                    val type = Net.u16(p, i)
                    val l = Net.u16(p, i + 2)
                    i += 4
                    if (i + l > extEnd) break
                    if (type == 0 && l >= 5) {
                        val nl = Net.u16(p, i + 3)
                        if (5 + nl <= l) {
                            sni = String(p, i + 5, nl, Charsets.US_ASCII).lowercase()
                        }
                    } else if (type == 43 && l >= 3) {
                        val ll = Net.u8(p, i)
                        var j = i + 1
                        while (j + 1 < i + 1 + ll && j + 1 < i + l) {
                            val v = Net.u16(p, j)
                            val grease = (v and 0x0F0F) == 0x0A0A
                            if (!grease && v > maxVer) maxVer = v
                            j += 2
                        }
                    }
                    i += l
                }
            }
            return TlsInfo(sni, verName(maxVer), maxVer < 0x0303)
        } catch (_: Exception) {
            return null
        }
    }
}

/** Detección de HTTP en claro y búsqueda de datos sensibles. */
object Http {
    private val methods = arrayOf("GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ")
    private val emailRe = Regex("[a-z0-9._%+-]{2,}@[a-z0-9.-]+\\.[a-z]{2,}")

    fun isRequest(b: ByteArray, len: Int): Boolean {
        if (len < 4) return false
        val s = String(b, 0, minOf(len, 8), Charsets.ISO_8859_1)
        return methods.any { s.startsWith(it) }
    }

    fun isResponse(b: ByteArray, len: Int): Boolean {
        if (len < 5) return false
        return String(b, 0, 5, Charsets.ISO_8859_1) == "HTTP/"
    }

    fun host(b: ByteArray, len: Int): String? {
        val s = String(b, 0, minOf(len, 2048), Charsets.ISO_8859_1)
        val i = s.indexOf("\r\nHost:", ignoreCase = true)
        if (i < 0) return null
        val st = i + 7
        val e = s.indexOf("\r\n", st)
        val h = (if (e < 0) s.substring(st) else s.substring(st, e)).trim()
        val name = h.substringBefore(':').lowercase()
        return if (name.isEmpty()) null else name
    }

    fun scan(b: ByteArray, off: Int, len: Int): Set<String> {
        val s = String(b, off, minOf(len, 8192), Charsets.ISO_8859_1).lowercase()
        val out = LinkedHashSet<String>()
        if (s.contains("password=") || s.contains("passwd=") || s.contains("pwd=") || s.contains("\"password\"")) out.add("contraseña")
        if (s.contains("token=") || s.contains("access_token") || s.contains("api_key") || s.contains("apikey=") || s.contains("secret=")) out.add("token / clave API")
        if (s.contains("authorization: bearer") || s.contains("authorization: basic")) out.add("cabecera Authorization")
        if (s.contains("imei=") || s.contains("imsi=") || s.contains("\"imei\"")) out.add("IMEI / IMSI")
        if (s.contains("advertising_id") || s.contains("gaid=") || s.contains("adid=") || s.contains("idfa=")) out.add("ID de publicidad")
        val aid = Engine.androidId
        if (aid.length >= 8 && s.contains(aid)) out.add("ANDROID_ID del dispositivo")
        val hasLat = s.contains("lat=") || s.contains("\"lat\"") || s.contains("latitude")
        val hasLon = s.contains("lon=") || s.contains("lng=") || s.contains("\"lon\"") || s.contains("longitude")
        if (hasLat && hasLon) out.add("ubicación")
        if (emailRe.containsMatchIn(s)) out.add("correo electrónico")
        return out
    }
}
