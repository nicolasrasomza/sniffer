package com.undercode.sniffer

import java.io.BufferedOutputStream
import java.io.File
import java.io.FileOutputStream

/** Escribe un archivo .pcap (LINKTYPE_RAW) legible con Wireshark. */
class PcapWriter(file: File, private val maxBytes: Long) {
    private val out = BufferedOutputStream(FileOutputStream(file), 64 * 1024)
    private var written = 0L
    private var closed = false

    init {
        val h = ByteArray(24)
        le32(h, 0, 0xA1B2C3D4L)
        h[4] = 2; h[5] = 0
        h[6] = 4; h[7] = 0
        le32(h, 16, 65535)
        le32(h, 20, 101)
        out.write(h)
        written = 24
    }

    private fun le32(b: ByteArray, i: Int, v: Long) {
        b[i] = v.toByte()
        b[i + 1] = (v shr 8).toByte()
        b[i + 2] = (v shr 16).toByte()
        b[i + 3] = (v shr 24).toByte()
    }

    @Synchronized
    fun write(b: ByteArray, off: Int, len: Int) {
        if (closed || written >= maxBytes) return
        try {
            val ts = System.currentTimeMillis()
            val h = ByteArray(16)
            le32(h, 0, ts / 1000)
            le32(h, 4, (ts % 1000) * 1000)
            le32(h, 8, len.toLong())
            le32(h, 12, len.toLong())
            out.write(h)
            out.write(b, off, len)
            written += 16L + len
        } catch (_: Exception) {
        }
    }

    @Synchronized
    fun flush() {
        if (!closed) try { out.flush() } catch (_: Exception) {}
    }

    @Synchronized
    fun close() {
        if (closed) return
        closed = true
        try { out.flush(); out.close() } catch (_: Exception) {}
    }
}
