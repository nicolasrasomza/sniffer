package com.undercode.sniffer

import android.net.ConnectivityManager
import android.net.VpnService
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.locks.Condition
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Reenvía el tráfico que llega al túnel hacia internet (mini pila TCP en espacio de usuario + UDP)
 * y mientras tanto lo analiza: DNS, SNI, HTTP en claro, volúmenes, atribución por app.
 */
class Forwarder(
    private val vpn: VpnService,
    private val tunOut: FileOutputStream,
    private val pcap: PcapWriter?,
    private val fixedPkg: String?,
    private val fixedLabel: String
) {
    companion object {
        val LOCAL_IP = byteArrayOf(10, 8, 0, 2)
        private const val MASK = 0xFFFFFFFFL
        private const val MSS = 1360
        private const val F_FIN = 0x01
        private const val F_SYN = 0x02
        private const val F_RST = 0x04
        private const val F_PSH = 0x08
        private const val F_ACK = 0x10
        private val FIN_MARK = ByteArray(0)
    }

    private class TcpFlow(
        val key: Long,
        val clientPort: Int,
        val serverIp: ByteArray,
        val serverPort: Int,
        val rec: ConnRecord
    ) {
        val lock = ReentrantLock()
        val cond: Condition = lock.newCondition()
        @Volatile var socket: Socket? = null
        @Volatile var state = 0 // 0 conectando, 1 establecida, 2 cerrada
        var isn = 0L
        var synNext = 0L
        var clientNext = 0L
        var serverSeq = 0L
        var clientAck = 0L
        var clientWnd = 65535
        var clientFin = false
        var serverFin = false
        val outQueue = LinkedBlockingQueue<ByteArray>()
        val pending = AtomicInteger(0)
        @Volatile var lastActive = System.currentTimeMillis()
        val head = ByteArray(4096)
        var headLen = 0
        var parsedHead = false
        var isHttp = false
        var httpScanned = 0
    }

    private class UdpFlow(
        val key: Long,
        val clientPort: Int,
        val serverIp: ByteArray,
        val serverPort: Int,
        val rec: ConnRecord,
        val sock: DatagramSocket,
        val isDns: Boolean
    ) {
        @Volatile var lastActive = System.currentTimeMillis()
        @Volatile var closed = false
    }

    private val tcpFlows = ConcurrentHashMap<Long, TcpFlow>()
    private val udpFlows = ConcurrentHashMap<Long, UdpFlow>()
    private val pool: ExecutorService = Executors.newCachedThreadPool()
    private val tunLock = Any()
    private val rnd = java.util.Random()
    private val cm: ConnectivityManager? = vpn.getSystemService(ConnectivityManager::class.java)
    private val uidCache = ConcurrentHashMap<Int, Pair<String, String>>()

    // ------------------------------------------------------------------ utilidades

    private fun flowKey(srcPort: Int, ip: ByteArray, dstPort: Int): Long =
        (srcPort.toLong() shl 48) or (Net.u32(ip, 0) shl 16) or dstPort.toLong()

    private fun writeTun(pkt: ByteArray) {
        try {
            synchronized(tunLock) { tunOut.write(pkt) }
        } catch (_: IOException) {
        }
        pcap?.write(pkt, 0, pkt.size)
        Engine.packets.incrementAndGet()
        Engine.bytes.addAndGet(pkt.size.toLong())
    }

    private fun owner(proto: Int, srcPort: Int, dst: ByteArray, dstPort: Int): Pair<String, String> {
        if (fixedPkg != null) return Pair(fixedPkg, fixedLabel)
        try {
            val uid = cm?.getConnectionOwnerUid(
                proto,
                InetSocketAddress(InetAddress.getByAddress(LOCAL_IP), srcPort),
                InetSocketAddress(InetAddress.getByAddress(dst), dstPort)
            ) ?: -1
            if (uid >= 0) {
                val cached = uidCache[uid]
                if (cached != null) return cached
                val pm = vpn.packageManager
                val pkg = pm.getPackagesForUid(uid)?.firstOrNull()
                if (pkg != null) {
                    val label = try {
                        pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString()
                    } catch (_: Exception) {
                        pkg
                    }
                    val res = Pair(pkg, label)
                    uidCache[uid] = res
                    return res
                }
                return Pair("uid:$uid", "UID $uid")
            }
        } catch (_: Exception) {
        }
        return Pair("?", "Desconocida")
    }

    // ------------------------------------------------------------------ entrada de paquetes

    fun handlePacket(p: ByteArray, len: Int) {
        if (len < 20) return
        if ((Net.u8(p, 0) shr 4) != 4) return
        val ihl = (Net.u8(p, 0) and 0x0F) * 4
        val total = Net.u16(p, 2)
        if (ihl < 20 || total > len || total < ihl) return
        if ((Net.u16(p, 6) and 0x3FFF) != 0) return // fragmentos: se descartan
        pcap?.write(p, 0, total)
        Engine.packets.incrementAndGet()
        Engine.bytes.addAndGet(total.toLong())
        when (Net.u8(p, 9)) {
            6 -> handleTcp(p, ihl, total)
            17 -> handleUdp(p, ihl, total)
        }
    }

    fun janitor() {
        val now = System.currentTimeMillis()
        for (f in tcpFlows.values) {
            val idle = now - f.lastActive
            if ((f.state == 0 && idle > 20_000) || (f.state == 1 && idle > 15 * 60_000)) closeTcp(f, true)
        }
    }

    fun shutdown() {
        for (f in tcpFlows.values) closeTcp(f, false)
        for (u in udpFlows.values) closeUdp(u)
        pool.shutdownNow()
    }

    // ------------------------------------------------------------------ TCP

    private fun sendSeg(
        f: TcpFlow, flags: Int, seq: Long, ack: Long,
        payload: ByteArray?, off: Int, len: Int, mss: Int
    ) {
        writeTun(
            Net.buildTcp(
                f.serverIp, LOCAL_IP, f.serverPort, f.clientPort,
                seq, ack, flags, 65535, payload, off, len, mss
            )
        )
    }

    private fun handleTcp(p: ByteArray, ihl: Int, total: Int) {
        if (total < ihl + 20) return
        val srcPort = Net.u16(p, ihl)
        val dstPort = Net.u16(p, ihl + 2)
        val seq = Net.u32(p, ihl + 4)
        val ack = Net.u32(p, ihl + 8)
        val dataOff = (Net.u8(p, ihl + 12) shr 4) * 4
        val flags = Net.u8(p, ihl + 13)
        val wnd = Net.u16(p, ihl + 14)
        val pOff = ihl + dataOff
        if (dataOff < 20 || pOff > total) return
        val pLen = total - pOff
        val dstIp = p.copyOfRange(16, 20)
        val key = flowKey(srcPort, dstIp, dstPort)
        val f = tcpFlows[key]

        if ((flags and F_RST) != 0) {
            if (f != null) closeTcp(f, false)
            return
        }
        if ((flags and F_SYN) != 0 && (flags and F_ACK) == 0) {
            onSyn(srcPort, dstIp, dstPort, key, seq, wnd)
            return
        }
        if (f == null) {
            if (pLen > 0 || (flags and F_FIN) != 0) {
                if ((flags and F_ACK) != 0) {
                    writeTun(Net.buildTcp(dstIp, LOCAL_IP, dstPort, srcPort, ack, 0, F_RST, 0, null, 0, 0, 0))
                } else {
                    val a = (seq + pLen + (if ((flags and F_FIN) != 0) 1 else 0)) and MASK
                    writeTun(Net.buildTcp(dstIp, LOCAL_IP, dstPort, srcPort, 0, a, F_RST or F_ACK, 0, null, 0, 0, 0))
                }
            }
            return
        }

        f.lastActive = System.currentTimeMillis()
        f.lock.withLock {
            if (f.state == 2) return
            if ((flags and F_ACK) != 0) {
                if (((ack - f.clientAck) and MASK) < 0x80000000L) f.clientAck = ack
                f.clientWnd = wnd
                f.cond.signalAll()
            }
            if (f.state == 0) return
            var needAck = false
            if (pLen > 0) {
                val behind = (f.clientNext - seq) and MASK
                var skip = -1
                if (behind == 0L) skip = 0
                else if (behind < 0x80000000L && behind < pLen) skip = behind.toInt()
                if (skip >= 0) {
                    if (f.pending.get() > 512 * 1024) return // contrapresión: el cliente reintentará
                    val n = pLen - skip
                    val data = p.copyOfRange(pOff + skip, pOff + pLen)
                    f.pending.addAndGet(n)
                    f.outQueue.add(data)
                    f.clientNext = (f.clientNext + n) and MASK
                    f.rec.bytesUp.addAndGet(n.toLong())
                    if (!Engine.screenOn) f.rec.screenOffUp.addAndGet(n.toLong())
                    f.rec.lastSeen = f.lastActive
                    inspect(f, data)
                }
                needAck = true
            }
            if ((flags and F_FIN) != 0) {
                val endSeq = (seq + pLen) and MASK
                if (endSeq == f.clientNext && !f.clientFin) {
                    f.clientFin = true
                    f.clientNext = (f.clientNext + 1) and MASK
                    f.outQueue.add(FIN_MARK)
                }
                needAck = true
            }
            if (needAck) sendSeg(f, F_ACK, f.serverSeq, f.clientNext, null, 0, 0, 0)
            if (f.clientFin && f.serverFin) closeTcp(f, false)
        }
    }

    private fun onSyn(srcPort: Int, dstIp: ByteArray, dstPort: Int, key: Long, seq: Long, wnd: Int) {
        val nextSeq = (seq + 1) and MASK
        val existing = tcpFlows[key]
        if (existing != null) {
            if (existing.synNext == nextSeq) {
                existing.lock.withLock {
                    if (existing.state == 1) {
                        sendSeg(existing, F_SYN or F_ACK, existing.isn, existing.synNext, null, 0, 0, MSS)
                    }
                }
                return
            }
            closeTcp(existing, false)
        }
        val ipStr = Net.ipStr(dstIp, 0)
        val (pkg, label) = owner(6, srcPort, dstIp, dstPort)
        val rec = Engine.record(pkg, label, "TCP", ipStr, dstPort)
        Engine.dnsMap[ipStr]?.let { rec.addName(it) }
        rec.flows.incrementAndGet()
        rec.noteStart()
        if (dstPort == 80) rec.cleartext = true
        Engine.noteConnect(ipStr, dstPort)
        Engine.evaluate(rec)

        if (Firewall.blocks(rec)) {
            rec.blockedCount.incrementAndGet()
            Engine.addEvent(rec, "BLOQUEADO TCP → ${rec.title()}")
            writeTun(Net.buildTcp(dstIp, LOCAL_IP, dstPort, srcPort, 0, nextSeq, F_RST or F_ACK, 0, null, 0, 0, 0))
            return
        }

        val f = TcpFlow(key, srcPort, dstIp, dstPort, rec)
        f.isn = rnd.nextInt().toLong() and MASK
        f.synNext = nextSeq
        f.clientNext = nextSeq
        f.serverSeq = f.isn
        f.clientAck = (f.isn + 1) and MASK
        f.clientWnd = if (wnd > 0) wnd else 65535
        tcpFlows[key] = f
        Engine.addEvent(rec, "TCP → ${rec.title()}")
        try {
            pool.execute { runTcp(f) }
        } catch (_: Exception) {
            tcpFlows.remove(key, f)
        }
    }

    private fun runTcp(f: TcpFlow) {
        val sock = Socket()
        try {
            vpn.protect(sock)
            sock.tcpNoDelay = true
            sock.connect(InetSocketAddress(InetAddress.getByAddress(f.serverIp), f.serverPort), 8000)
        } catch (_: Exception) {
            try { sock.close() } catch (_: IOException) {}
            f.lock.withLock {
                if (f.state != 2) sendSeg(f, F_RST or F_ACK, 0, f.clientNext, null, 0, 0, 0)
            }
            Engine.addEvent(f.rec, "Conexión fallida → ${f.rec.title()}")
            closeTcp(f, false)
            return
        }
        f.socket = sock
        var alive = true
        f.lock.withLock {
            if (f.state == 2) {
                alive = false
            } else {
                f.state = 1
                sendSeg(f, F_SYN or F_ACK, f.isn, f.synNext, null, 0, 0, MSS)
                f.serverSeq = (f.isn + 1) and MASK
            }
        }
        if (!alive) {
            try { sock.close() } catch (_: IOException) {}
            return
        }
        try {
            pool.execute { tcpWriter(f, sock) }
        } catch (_: Exception) {
            closeTcp(f, true)
            return
        }

        val buf = ByteArray(MSS)
        try {
            val input = sock.getInputStream()
            while (true) {
                var toRead = 0
                f.lock.withLock {
                    while (true) {
                        if (f.state == 2) break
                        val d = (f.serverSeq - f.clientAck) and MASK
                        val inflight = if (d > 0x80000000L) 0L else d
                        val allowed = f.clientWnd - inflight
                        if (allowed > 0) {
                            toRead = minOf(MSS.toLong(), allowed).toInt()
                            break
                        }
                        f.cond.await(200, TimeUnit.MILLISECONDS)
                    }
                }
                if (f.state == 2) return
                val n = input.read(buf, 0, toRead)
                if (n < 0) break
                f.lock.withLock {
                    if (f.state != 2) {
                        sendSeg(f, F_PSH or F_ACK, f.serverSeq, f.clientNext, buf, 0, n, 0)
                        f.serverSeq = (f.serverSeq + n) and MASK
                        f.rec.bytesDown.addAndGet(n.toLong())
                        f.lastActive = System.currentTimeMillis()
                        f.rec.lastSeen = f.lastActive
                    }
                }
            }
            f.lock.withLock {
                if (f.state != 2 && !f.serverFin) {
                    sendSeg(f, F_FIN or F_ACK, f.serverSeq, f.clientNext, null, 0, 0, 0)
                    f.serverSeq = (f.serverSeq + 1) and MASK
                    f.serverFin = true
                    if (f.clientFin) closeTcp(f, false)
                }
            }
        } catch (_: Exception) {
            closeTcp(f, true)
        }
    }

    private fun tcpWriter(f: TcpFlow, sock: Socket) {
        try {
            val out = sock.getOutputStream()
            while (f.state != 2) {
                val d = f.outQueue.poll(500, TimeUnit.MILLISECONDS) ?: continue
                if (d === FIN_MARK) {
                    try { sock.shutdownOutput() } catch (_: IOException) {}
                    break
                }
                out.write(d)
                out.flush()
                f.pending.addAndGet(-d.size)
            }
        } catch (_: Exception) {
            closeTcp(f, true)
        }
    }

    private fun closeTcp(f: TcpFlow, rst: Boolean) {
        f.lock.withLock {
            if (f.state == 2) return
            val wasUp = f.state == 1
            f.state = 2
            if (rst && wasUp) {
                try { sendSeg(f, F_RST or F_ACK, f.serverSeq, f.clientNext, null, 0, 0, 0) } catch (_: Exception) {}
            }
            f.cond.signalAll()
        }
        try { f.socket?.close() } catch (_: IOException) {}
        tcpFlows.remove(f.key, f)
        f.outQueue.clear()
    }

    /** Inspección de los primeros bytes enviados por el cliente: SNI, versión TLS, HTTP en claro. */
    private fun inspect(f: TcpFlow, data: ByteArray) {
        val rec = f.rec
        if (!f.parsedHead) {
            val room = f.head.size - f.headLen
            val c = minOf(room, data.size)
            System.arraycopy(data, 0, f.head, f.headLen, c)
            f.headLen += c
            if (f.headLen >= 4) {
                if (Net.u8(f.head, 0) == 0x16 && Net.u8(f.head, 1) == 3) {
                    val info = Tls.parse(f.head, 0, f.headLen)
                    if (info != null) {
                        rec.tlsVersion = info.version
                        if (info.old) rec.oldTls = true
                        if (info.sni != null) {
                            rec.addName(info.sni)
                            f.parsedHead = true
                            Engine.evaluate(rec)
                        }
                    }
                    if (f.headLen >= f.head.size) f.parsedHead = true
                } else if (Http.isRequest(f.head, f.headLen)) {
                    f.isHttp = true
                    f.parsedHead = true
                    rec.cleartext = true
                    Http.host(f.head, f.headLen)?.let { rec.addName(it) }
                    val s = Http.scan(f.head, 0, f.headLen)
                    if (s.isNotEmpty()) rec.addSensitive(s)
                    f.httpScanned = f.headLen
                    Engine.evaluate(rec)
                } else {
                    f.parsedHead = true
                }
            }
        } else if (f.isHttp && f.httpScanned < 65536) {
            f.httpScanned += data.size
            val s = Http.scan(data, 0, data.size)
            if (s.isNotEmpty()) {
                rec.addSensitive(s)
                Engine.evaluate(rec)
            }
        }
    }

    // ------------------------------------------------------------------ UDP

    private fun handleUdp(p: ByteArray, ihl: Int, total: Int) {
        if (total < ihl + 8) return
        val srcPort = Net.u16(p, ihl)
        val dstPort = Net.u16(p, ihl + 2)
        val ulen = Net.u16(p, ihl + 4)
        val pOff = ihl + 8
        val pLen = minOf(ulen - 8, total - pOff)
        if (pLen < 0) return
        val dstIp = p.copyOfRange(16, 20)

        // Se bloquea QUIC para que las apps vuelvan a TCP/TLS, donde sí se ve el SNI
        if (dstPort == 443 && Prefs.bool("block_quic", true)) {
            Engine.quicBlocked.incrementAndGet()
            return
        }
        val key = flowKey(srcPort, dstIp, dstPort)
        if (dstPort == 53 && handleDnsQuery(p, pOff, pLen, srcPort, dstIp)) return

        var f = udpFlows[key]
        if (f == null) {
            f = createUdp(key, srcPort, dstIp, dstPort) ?: return
        }
        f.lastActive = System.currentTimeMillis()
        f.rec.bytesUp.addAndGet(pLen.toLong())
        if (!Engine.screenOn) f.rec.screenOffUp.addAndGet(pLen.toLong())
        f.rec.lastSeen = f.lastActive
        try {
            f.sock.send(DatagramPacket(p, pOff, pLen, InetAddress.getByAddress(dstIp), dstPort))
        } catch (_: Exception) {
        }
    }

    private fun handleDnsQuery(p: ByteArray, pOff: Int, pLen: Int, srcPort: Int, dstIp: ByteArray): Boolean {
        val q = Dns.parseQuestion(p, pOff, pOff + pLen) ?: return false
        val name = q.first
        val (pkg, label) = owner(17, srcPort, dstIp, 53)
        Engine.noteDns(pkg, label, name, Net.ipStr(dstIp, 0))
        val block = Firewall.isDomainBlocked(name) ||
            (Prefs.bool("autoblock_ioc", false) && Analyzer.matchIoc(name) != null)
        if (block) {
            val resp = Dns.nxdomain(p, pOff, pOff + pLen)
            if (resp != null) writeTun(Net.buildUdp(dstIp, LOCAL_IP, 53, srcPort, resp, 0, resp.size))
            val rec = Engine.record(pkg, label, "DNS", Net.ipStr(dstIp, 0), 53)
            rec.addName(name)
            rec.blockedCount.incrementAndGet()
            Engine.addEvent(rec, "BLOQUEADO DNS → $name")
            return true
        }
        return false
    }

    private fun createUdp(key: Long, srcPort: Int, dstIp: ByteArray, dstPort: Int): UdpFlow? {
        val ipStr = Net.ipStr(dstIp, 0)
        val (pkg, label) = owner(17, srcPort, dstIp, dstPort)
        val isDns = dstPort == 53
        val rec = Engine.record(pkg, label, "UDP", ipStr, dstPort)
        Engine.dnsMap[ipStr]?.let { if (!isDns) rec.addName(it) }
        rec.flows.incrementAndGet()
        rec.noteStart()
        if (!isDns) Engine.noteConnect(ipStr, dstPort)
        Engine.evaluate(rec)
        if (Firewall.blocks(rec)) {
            rec.blockedCount.incrementAndGet()
            Engine.addEvent(rec, "BLOQUEADO UDP → ${rec.title()}")
            return null
        }
        val sock = try {
            val s = DatagramSocket()
            vpn.protect(s)
            s.soTimeout = 5000
            s
        } catch (_: Exception) {
            return null
        }
        val f = UdpFlow(key, srcPort, dstIp, dstPort, rec, sock, isDns)
        udpFlows[key] = f
        if (!isDns) Engine.addEvent(rec, "UDP → ${rec.title()}")
        try {
            pool.execute { udpReader(f) }
        } catch (_: Exception) {
            closeUdp(f)
            return null
        }
        return f
    }

    private fun udpReader(f: UdpFlow) {
        val buf = ByteArray(65535)
        val pkt = DatagramPacket(buf, buf.size)
        val idleLimit = if (f.isDns) 5_000L else 60_000L
        try {
            while (!f.closed) {
                pkt.length = buf.size
                try {
                    f.sock.receive(pkt)
                } catch (_: SocketTimeoutException) {
                    if (System.currentTimeMillis() - f.lastActive > idleLimit) break
                    continue
                }
                f.lastActive = System.currentTimeMillis()
                val n = pkt.length
                writeTun(Net.buildUdp(f.serverIp, LOCAL_IP, f.serverPort, f.clientPort, buf, 0, n))
                f.rec.bytesDown.addAndGet(n.toLong())
                f.rec.lastSeen = f.lastActive
                if (f.isDns) {
                    Dns.parseAnswers(buf, 0, n) { name, ip -> Engine.dnsMap[ip] = name }
                    break
                }
            }
        } catch (_: Exception) {
        } finally {
            closeUdp(f)
        }
    }

    private fun closeUdp(f: UdpFlow) {
        f.closed = true
        try { f.sock.close() } catch (_: Exception) {}
        udpFlows.remove(f.key, f)
    }
}
