"""tun2socks in pure Python: reads raw IPv4 packets from the Android VPN TUN fd and turns them into proxy connections.
TCP: a tiny server-side TCP stack (the TUN is a lossless local link, so no congestion control is needed).
DNS (UDP/53): answered through DNS-over-HTTPS that travels INSIDE the tunnel (no leaks, no poisoning). AAAA -> empty.
Other UDP (QUIC etc.): ICMP port-unreachable so apps fall back to TCP immediately.
"""
import array, asyncio, os, socket, struct, sys, time
from collections import deque

MASK = 0xFFFFFFFF
MAX_CONNS, UP_WIN, OUT_MAX, IDLE_T = 700, 65535, 262144, 600
_LE = sys.byteorder == "little"
FIN, SYN, RST, PSH, ACK = 1, 2, 4, 8, 16


def csum(data):
    if len(data) & 1: data += b"\0"
    s = sum(array.array("H", data)); s = (s & 0xFFFF) + (s >> 16); s = (s & 0xFFFF) + (s >> 16)
    if _LE: s = ((s & 0xFF) << 8) | (s >> 8)
    return ~s & 0xFFFF


def lt(a, b): return ((a - b) & MASK) > 0x7FFFFFFF      # a before b (mod 2**32)


def ip_packet(src, dst, proto, payload, ident):
    h = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident & 0xFFFF, 0x4000, 64, proto, 0, src, dst)
    return h[:10] + struct.pack(">H", csum(h)) + h[12:] + payload


def tcp_segment(src, dst, sport, dport, seq, ack, flags, win, payload=b"", opts=b""):
    hl = 20 + len(opts)
    t = struct.pack(">HHIIBBHHH", sport, dport, seq & MASK, ack & MASK, (hl // 4) << 4, flags, min(win, 65535), 0, 0) + opts + payload
    c = csum(struct.pack(">4s4sBBH", src, dst, 0, 6, len(t)) + t)
    return t[:16] + struct.pack(">H", c) + t[18:]


class Conn:
    __slots__ = ("key", "cip", "cport", "dip", "dport", "irs", "iss", "rcv", "snd", "una", "cwin", "mss", "state", "r", "w",
                 "out", "unacked", "fin_sent", "fin_seq", "fin_acked", "fin_rcvd", "up_eof", "upbuf", "up_pend", "upev", "up_fin",
                 "rdev", "last", "first", "tasks", "closed")

    def __init__(s, key, cip, cport, dip, dport, irs, mss):
        s.key, s.cip, s.cport, s.dip, s.dport, s.irs, s.mss = key, cip, cport, dip, dport, irs, mss
        s.iss = int.from_bytes(os.urandom(4), "big"); s.rcv = (irs + 1) & MASK; s.snd = s.una = (s.iss + 1) & MASK
        s.cwin, s.state, s.r, s.w = 65535, "connecting", None, None
        s.out, s.unacked = bytearray(), deque()
        s.fin_sent = s.fin_acked = s.fin_rcvd = s.up_eof = s.up_fin = s.closed = False; s.fin_seq = 0
        s.upbuf, s.up_pend, s.first, s.tasks = bytearray(), 0, True, []
        s.upev, s.rdev, s.last = asyncio.Event(), asyncio.Event(), time.time(); s.rdev.set()


class Tun2Socks:
    """connect(host, port) -> awaitable of (reader, writer) | None. dns(query_bytes) -> awaitable of bytes | None."""

    def __init__(s, fd, connect, dns, log, send_frag=None, frag=lambda: False, stats=None, extreme=lambda: False):
        s.fd, s.connect, s.dns, s.log, s.send_frag, s.frag, s.stats, s.extreme = fd, connect, dns, log, send_frag, frag, stats, extreme
        s.conns, s.ident, s.loop, s.running, s.cache = {}, 1, None, False, {}
        s.pkts = s.dns_n = 0

    # ---------- lifecycle ----------
    def attach(s, loop):
        s.loop = loop; os.set_blocking(s.fd, False); loop.add_reader(s.fd, s._readable); s.running = True
        s._sweep_h = loop.call_later(0.5, s._sweep); s.log("VPN: tunnel interface attached")

    def detach(s):
        if not s.running: return
        s.running = False
        try: s.loop.remove_reader(s.fd)
        except Exception: pass
        try: s._sweep_h.cancel()
        except Exception: pass
        for c in list(s.conns.values()): s._kill(c)
        try: os.close(s.fd)
        except OSError: pass
        s.log("VPN: tunnel interface detached")

    def _write(s, pkt):
        try: os.write(s.fd, pkt)
        except BlockingIOError: pass
        except OSError: s.running and s.loop.call_soon(s.detach)

    def _id(s): s.ident = (s.ident + 1) & 0xFFFF; return s.ident

    # ---------- input ----------
    def _readable(s):
        for _ in range(128):
            try: pkt = os.read(s.fd, 65535)
            except BlockingIOError: return
            except OSError: s.loop.call_soon(s.detach); return
            if not pkt: return
            s.pkts += 1
            try: s._ip(pkt)
            except Exception as e: s.log(f"VPN packet error: {e!r}")

    def _ip(s, p):
        if len(p) < 20 or p[0] >> 4 != 4: return                       # IPv6 etc: dropped (black-holed on purpose)
        ihl = (p[0] & 15) * 4
        if struct.unpack_from(">H", p, 6)[0] & 0x3FFF: return          # fragments: unsupported
        total = struct.unpack_from(">H", p, 2)[0]; p = p[:total]; proto, src, dst = p[9], p[12:16], p[16:20]
        if proto == 6: s._tcp(src, dst, p, ihl)
        elif proto == 17: s._udp(src, dst, p, ihl)

    # ---------- TCP ----------
    def _send(s, c, flags, payload=b"", seq=None, opts=b""):
        win = max(0, UP_WIN - c.up_pend)
        s._write(ip_packet(c.dip, c.cip, 6, tcp_segment(c.dip, c.cip, c.dport, c.cport, c.snd if seq is None else seq, c.rcv, flags, win, payload, opts), s._id()))

    def _rst(s, src, sport, dst, dport, seq, ack, fl, dlen):
        if fl & ACK: pkt = tcp_segment(dst, src, dport, sport, ack, 0, RST, 0)
        else: pkt = tcp_segment(dst, src, dport, sport, 0, (seq + dlen + (1 if fl & (SYN | FIN) else 0)) & MASK, RST | ACK, 0)
        s._write(ip_packet(dst, src, 6, pkt, s._id()))

    def _tcp(s, src, dst, p, ihl):
        sport, dport, seq, ack, off, fl, win = struct.unpack_from(">HHIIBBH", p, ihl)
        hl = (off >> 4) * 4; data = p[ihl + hl:]; key = (src, sport, dst, dport); c = s.conns.get(key)
        if fl & SYN and not fl & ACK:
            if c: return
            if len(s.conns) >= MAX_CONNS: return s._rst(src, sport, dst, dport, seq, ack, fl, 0)
            mss, i, o = 1400, 20, p[ihl:ihl + hl]
            while i < len(o):                                           # parse TCP options for MSS
                k = o[i]
                if k == 0: break
                if k == 1: i += 1; continue
                if i + 1 >= len(o) or o[i + 1] < 2: break
                if k == 2 and o[i + 1] == 4: mss = min(mss, struct.unpack_from(">H", o, i + 2)[0])
                i += o[i + 1]
            c = Conn(key, src, sport, dst, dport, seq, max(536, mss)); s.conns[key] = c
            c.tasks.append(s.loop.create_task(s._open(c))); return
        if not c:
            if not fl & RST: s._rst(src, sport, dst, dport, seq, ack, fl, len(data))
            return
        if c.state != "est":
            if fl & RST: s._kill(c)
            return
        if fl & RST: return s._kill(c)
        c.last = time.time()
        if fl & ACK: s._acked(c, ack, win)
        if data or fl & FIN:
            d = (c.rcv - seq) & MASK
            if d > 0x7FFFFFFF: return s._send(c, ACK)                   # data from the future: ask again
            if d: data = data[d:]; seq = c.rcv                          # overlap (retransmission): trim
            if data:
                c.rcv = (c.rcv + len(data)) & MASK; c.upbuf += data; c.up_pend += len(data); c.upev.set()
            if fl & FIN and not c.fin_rcvd and (seq + len(data)) & MASK == c.rcv:
                c.fin_rcvd = True; c.rcv = (c.rcv + 1) & MASK; c.up_fin = True; c.upev.set()
            s._send(c, ACK)
            s._done(c)

    def _acked(s, c, ack, win):
        c.cwin = win
        if ((ack - c.una) & MASK) and not lt(c.snd, ack) and not lt(ack, c.una):
            c.una = ack
            while c.unacked:
                sq, d, _ = c.unacked[0]; end = (sq + len(d)) & MASK
                if not lt(ack, end): c.unacked.popleft()               # fully acked
                elif lt(sq, ack): c.unacked[0] = [ack, d[(ack - sq) & MASK:], time.time()]; break
                else: break
            if c.fin_sent and not lt(ack, (c.fin_seq + 1) & MASK): c.fin_acked = True
        s._flush(c); s._done(c)

    def _flush(s, c):
        if c.closed or c.state != "est": return
        while c.out:
            room = c.cwin - ((c.snd - c.una) & MASK); n = min(c.mss, len(c.out), room)
            if n <= 0: break
            seg = bytes(c.out[:n]); del c.out[:n]
            s._send(c, PSH | ACK, seg); c.unacked.append([c.snd, seg, time.time()]); c.snd = (c.snd + n) & MASK
        if c.up_eof and not c.out and not c.fin_sent:
            c.fin_sent, c.fin_seq = True, c.snd; s._send(c, FIN | ACK); c.snd = (c.snd + 1) & MASK
        if len(c.out) < OUT_MAX // 2: c.rdev.set()

    def _done(s, c):
        if c.fin_sent and c.fin_acked and c.fin_rcvd: s._kill(c)

    def _kill(s, c, rst=False):
        if c.closed: return
        c.closed = True; s.conns.pop(c.key, None)
        if rst: s._write(ip_packet(c.dip, c.cip, 6, tcp_segment(c.dip, c.cip, c.dport, c.cport, c.snd, c.rcv, RST | ACK, 0), s._id()))
        for t in c.tasks: t.cancel()
        try: c.w and c.w.close()
        except Exception: pass

    async def _open(s, c):
        host = socket.inet_ntoa(c.dip)
        try: res = await asyncio.wait_for(s.connect(host, c.dport), 25)
        except Exception: res = None
        if c.closed:
            if res:
                try: res[1].close()
                except Exception: pass
            return
        if not res:
            s.conns.pop(c.key, None); c.closed = True
            return s._write(ip_packet(c.dip, c.cip, 6, tcp_segment(c.dip, c.cip, c.dport, c.cport, 0, (c.irs + 1) & MASK, RST | ACK, 0), s._id()))
        c.r, c.w, c.state = res[0], res[1], "est"
        s._write(ip_packet(c.dip, c.cip, 6, tcp_segment(c.dip, c.cip, c.dport, c.cport, c.iss, c.rcv, SYN | ACK, UP_WIN, b"", b"\x02\x04" + struct.pack(">H", c.mss)), s._id()))
        c.tasks += [s.loop.create_task(s._uploop(c)), s.loop.create_task(s._downloop(c))]

    async def _uploop(s, c):
        try:
            while True:
                await c.upev.wait(); c.upev.clear()
                if c.upbuf:
                    d = bytes(c.upbuf); c.upbuf.clear()
                    if c.first and s.send_frag and not getattr(c.w, "nofrag", False) and s.frag(): await s.send_frag(c.w, d, True, s.extreme())
                    else: c.w.write(d); await c.w.drain()
                    c.first = False; before = c.up_pend; c.up_pend -= len(d)
                    if s.stats: s.stats.up += len(d)
                    if before > UP_WIN // 2 >= c.up_pend or before > UP_WIN - 4096: s._send(c, ACK)   # window update
                if c.up_fin and not c.upbuf:
                    try: c.w.write_eof()
                    except Exception: pass
                    c.up_fin = False
        except asyncio.CancelledError: raise
        except Exception: s._kill(c, True)

    async def _downloop(s, c):
        try:
            while True:
                if len(c.out) > OUT_MAX: c.rdev.clear(); await c.rdev.wait()
                d = await c.r.read(65536)
                if not d: break
                c.out += d; c.last = time.time()
                if s.stats: s.stats.down += len(d)
                s._flush(c)
            c.up_eof = True; s._flush(c)
        except asyncio.CancelledError: raise
        except Exception: s._kill(c, True)

    def _sweep(s):
        if not s.running: return
        now = time.time()
        for c in list(s.conns.values()):
            if c.closed: continue
            if c.state == "est" and c.unacked and now - c.unacked[0][2] > 1.0 and c.unacked[0][1]:
                sq, d, _ = c.unacked[0]; c.unacked[0][2] = now; s._send(c, PSH | ACK, d, sq)   # retransmit oldest
            if c.state == "est" and c.out and c.cwin == 0 and now - c.last > 1: s._flush(c)
            if now - c.last > (IDLE_T if not c.fin_sent else 60): s._kill(c, True)
        s._sweep_h = s.loop.call_later(0.5, s._sweep)

    # ---------- UDP / DNS ----------
    def _udp(s, src, dst, p, ihl):
        sport, dport, ln = struct.unpack_from(">HHH", p, ihl); data = p[ihl + 8:ihl + ln]
        if dport == 53 and len(data) >= 12: s.loop.create_task(s._dns(src, sport, dst, data))
        else:                                                           # ICMP port unreachable (instant QUIC -> TCP fallback)
            ic = struct.pack(">BBHI", 3, 3, 0, 0) + p[:ihl + 8]; ic = ic[:2] + struct.pack(">H", csum(ic)) + ic[4:]
            s._write(ip_packet(dst, src, 1, ic, s._id()))

    @staticmethod
    def _qinfo(q):
        i = 12
        while i < len(q) and q[i]: i += q[i] + 1
        return (struct.unpack_from(">H", q, i + 1)[0] if i + 3 <= len(q) else 0), i + 5

    async def _dns(s, cip, cport, srv, q):
        qtype, qend = s._qinfo(q); s.dns_n += 1
        if qtype == 28:                                                 # AAAA: say "no IPv6" so apps use IPv4
            resp = q[:2] + struct.pack(">HHHHH", 0x8180, 1, 0, 0, 0) + q[12:qend]
        else:
            k = q[2:]; hit = s.cache.get(k)
            if hit and hit[1] > time.time(): resp = q[:2] + hit[0]
            else:
                try: resp = await asyncio.wait_for(s.dns(q), 15)
                except Exception: resp = None
                if not resp or len(resp) < 12: return
                if (resp[3] & 15) == 0 and struct.unpack_from(">H", resp, 6)[0] > 0:
                    if len(s.cache) > 800: s.cache.clear()
                    s.cache[k] = (resp[2:], time.time() + 90)
        u = struct.pack(">HHHH", 53, cport, 8 + len(resp), 0) + resp
        s._write(ip_packet(srv, cip, 17, u, s._id()))


class DohClient:
    """DNS-over-HTTPS (RFC 8484 POST) through the tunnel with small keep-alive pool. connect(host, port) -> (r, w) | None."""
    def __init__(s, connect, ctx, hosts=("1.1.1.1", "1.0.0.1", "8.8.8.8")):
        s.connect, s.ctx, s.hosts, s.idle = connect, ctx, hosts, []

    async def _new(s, host):
        res = await s.connect(host, 443)
        if not res: return None
        r, w = res
        try: await asyncio.wait_for(w.start_tls(s.ctx(), server_hostname=host), 12)
        except Exception:
            try: w.close()
            except Exception: pass
            return None
        return host, r, w

    async def _ask(s, cn, q):
        host, r, w = cn
        w.write(f"POST /dns-query HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\n"
                f"Content-Length: {len(q)}\r\n\r\n".encode() + q)
        await w.drain()
        head = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 10); low = head.lower()
        if b" 200" not in head.split(b"\r\n")[0]: raise OSError("doh status")
        i = low.find(b"content-length:")
        if i < 0: raise OSError("doh length")
        n = int(low[i + 15:low.find(b"\r\n", i)].strip())
        return await asyncio.wait_for(r.readexactly(n), 10)

    async def __call__(s, q):
        for attempt in range(3):
            cn = s.idle.pop() if s.idle and attempt == 0 else await s._new(s.hosts[attempt % len(s.hosts)])
            if not cn: continue
            try:
                resp = await s._ask(cn, q)
                if len(s.idle) < 3: s.idle.append(cn)
                else: cn[2].close()
                return resp
            except Exception:
                try: cn[2].close()
                except Exception: pass
        return None
