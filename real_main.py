#!/usr/bin/env python3
"""NetFree v2 - Kivy / Android port.
Cloudflare IP scanner + online proxy finder + resilient SOCKS5/HTTP server + Cloudflare-IP forwarder.
Engine is unchanged from netfree_v2.py; only the UI is new (Kivy) and the scan ranges are much larger.
Removed (not possible on Android): Windows system proxy, SNI-spoof (needs WinDivert).
"""
import asyncio, ipaddress, json, os, queue, random, re, socket, ssl, statistics, struct, sys, threading, time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

# Android's python has no system CA store -> use certifi for every verified TLS connection
try:
    import certifi
    CAFILE = certifi.where(); os.environ.setdefault("SSL_CERT_FILE", CAFILE)
except Exception:
    CAFILE = None


def _vctx():
    return ssl.create_default_context(cafile=CAFILE) if CAFILE else ssl.create_default_context()


# Scan ranges. Every IP is verified (server: cloudflare / cf-ray) so stale or wrong blocks are simply skipped.
# 1) official published Cloudflare ranges (104.16.0.0/12 = whole CLOUDFLARENET block, wider than the published /13 + /14)
# 2) extra Cloudflare-owned blocks (DNS 1.x, legacy 199.27, 185.146, 45.131 ...) 3) the scattered 8.x edge blocks
CF = ["173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
      "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/12",
      "172.64.0.0/13", "131.0.72.0/22",
      "1.0.0.0/24", "1.1.1.0/24", "199.27.128.0/21", "185.146.172.0/22", "66.235.200.0/24", "45.131.4.0/22", "45.131.208.0/22",
      "8.6.144.0/24", "8.9.231.0/24", "8.10.148.0/24", "8.14.199.0/24", "8.14.202.0/24", "8.17.205.0/24", "8.17.206.0/24",
      "8.18.50.0/24", "8.18.113.0/24", "8.18.194.0/24", "8.19.8.0/24", "8.20.100.0/24", "8.20.101.0/24", "8.20.103.0/24",
      "8.20.122.0/23", "8.20.124.0/23", "8.20.126.0/24", "8.20.253.0/24", "8.21.8.0/22", "8.21.13.0/24", "8.21.110.0/23",
      "8.21.239.0/24", "8.23.139.0/24", "8.24.87.0/24", "8.26.182.0/24", "8.27.64.0/22", "8.28.20.0/24", "8.28.82.0/24",
      "8.28.126.0/24", "8.28.213.0/24", "8.29.105.0/24", "8.29.230.0/23", "8.30.234.0/24", "8.31.2.0/24", "8.31.160.0/24",
      "8.34.69.0/24", "8.34.70.0/24", "8.34.200.0/22", "8.35.57.0/24", "8.35.58.0/23", "8.35.149.0/24", "8.36.216.0/22",
      "8.37.41.0/24", "8.38.147.0/24", "8.38.148.0/23", "8.38.172.0/24", "8.39.6.0/24", "8.39.18.0/24", "8.39.124.0/23",
      "8.39.201.0/24", "8.39.202.0/23", "8.39.204.0/22", "8.39.212.0/22", "8.40.26.0/23", "8.40.29.0/24", "8.40.30.0/23",
      "8.40.107.0/24", "8.40.111.0/24", "8.40.140.0/24", "8.41.5.0/24", "8.41.6.0/23", "8.41.36.0/23", "8.42.51.0/24",
      "8.42.52.0/23", "8.42.54.0/23", "8.42.161.0/24", "8.42.164.0/24", "8.42.172.0/24", "8.42.245.0/24", "8.43.121.0/24",
      "8.43.122.0/23", "8.43.224.0/23", "8.43.226.0/24", "8.44.0.0/22", "8.44.6.0/24", "8.44.58.0/23", "8.44.60.0/22",
      "8.45.41.0/24", "8.45.42.0/23", "8.45.44.0/22", "8.45.97.0/24", "8.45.101.0/24", "8.45.102.0/23", "8.45.108.0/24",
      "8.45.111.0/24", "8.45.144.0/22", "8.46.113.0/24", "8.46.114.0/23", "8.46.117.0/24", "8.46.118.0/23", "8.47.9.0/24",
      "8.47.12.0/22", "8.47.69.0/24", "8.47.71.0/24", "8.48.130.0/23", "8.48.132.0/24", "8.48.134.0/24"]


# ---- Hardest Blackout: during a nationwide shutdown, third-party proxy lists (GitHub etc.) are usually
# blocked too. The one thing that tends to stay reachable is big CDN edge IPs (local sites/CDN-cached
# content must keep working), so Blackout mode scans a much wider set of providers, rotates the TLS SNI
# across many "front" domains hosted on each CDN (domain fronting), tries Cloudflare's alternate HTTPS
# ports (sometimes open when 443 is throttled), and fragments the TLS hello much more aggressively.
CDN_FRONT = {
    "Cloudflare": CF,
    "Google": ["8.8.4.0/24", "8.8.8.0/24", "23.236.48.0/20", "23.251.128.0/19", "34.64.0.0/10", "34.128.0.0/10",
               "35.184.0.0/13", "35.192.0.0/14", "35.196.0.0/15", "35.198.0.0/16", "35.199.0.0/17", "35.199.128.0/18",
               "35.200.0.0/13", "35.208.0.0/12", "35.224.0.0/12", "35.240.0.0/13", "64.233.160.0/19", "66.102.0.0/20",
               "66.249.64.0/19", "72.14.192.0/18", "74.125.0.0/16", "108.177.0.0/17", "142.250.0.0/15", "172.217.0.0/16",
               "172.253.0.0/16", "173.194.0.0/16", "209.85.128.0/17", "216.58.192.0/19", "216.239.32.0/19"],
    "Microsoft": ["13.64.0.0/11", "13.104.0.0/14", "20.33.0.0/16", "20.190.128.0/18", "40.74.0.0/15", "40.76.0.0/14",
                  "40.112.0.0/13", "52.96.0.0/12", "52.112.0.0/14", "104.40.0.0/13", "150.171.0.0/16", "204.79.197.0/24",
                  "13.107.6.0/24", "13.107.9.0/24", "13.107.18.0/24", "13.107.21.0/24", "13.107.42.0/24", "13.107.213.0/24"],
    "Amazon": ["13.32.0.0/15", "13.224.0.0/14", "18.64.0.0/14", "52.46.0.0/18", "52.84.0.0/15", "52.222.128.0/17",
               "54.182.0.0/16", "54.230.0.0/16", "54.239.128.0/18", "64.252.64.0/18", "99.84.0.0/16", "143.204.0.0/16",
               "205.251.192.0/19"],
    "Fastly": ["23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24", "104.156.80.0/20", "140.248.64.0/18",
               "146.75.0.0/16", "151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17", "185.31.16.0/22",
               "199.27.72.0/21", "199.232.0.0/16"],
    "Akamai": ["23.0.0.0/12", "23.32.0.0/11", "23.64.0.0/14", "23.192.0.0/11", "72.246.0.0/15", "88.221.0.0/16",
               "92.122.0.0/15", "95.100.0.0/15", "96.16.0.0/15", "104.64.0.0/10", "184.24.0.0/13"],
}
FRONT_SNIS = {
    "Cloudflare": ["security.vercel.com", "hcaptcha.com", "www.snapp.ir", "cdnjs.cloudflare.com"],
    "Google": ["www.google.com", "fonts.gstatic.com", "ajax.googleapis.com", "www.gstatic.com"],
    "Microsoft": ["www.bing.com", "ajax.aspnetcdn.com", "login.microsoftonline.com", "www.office.com"],
    "Amazon": ["www.amazon.com", "images-na.ssl-images-amazon.com", "a0.awsstatic.com"],
    "Fastly": ["www.shopify.com", "cdn.shopify.com", "www.ebay.com"],
    "Akamai": ["www.apple.com", "www.microsoft.com", "a248.e.akamai.net"],
}
ALT_PORTS = [443, 2053, 2083, 2087, 2096, 8443]  # Cloudflare also serves HTTPS on these; often open when 443 is throttled


def merge_nets(nets):
    """Drop overlaps (e.g. 104.16.0.0/13 inside 104.16.0.0/12) so nothing is counted twice."""
    out = []
    for v in (4, 6):
        out += list(ipaddress.collapse_addresses([x for x in nets if x.version == v]))
    return out


def sample_ips(nets, n):
    """Random IPs spread over ALL ranges. weighting by size**0.75 keeps the many small blocks from being drowned out by the huge /12 and /13."""
    n = min(n, sum(x.num_addresses for x in nets)); wts = [x.num_addresses ** 0.75 for x in nets]; out, tries = set(), 0
    while len(out) < n and tries < n * 30:
        x = random.choices(nets, wts)[0]; out.add(str(x[random.randrange(x.num_addresses)])); tries += 1
    return list(out)


RAW = "https://raw.githubusercontent.com/"
SRC = {"SOCKS5": [RAW + "TheSpeedX/PROXY-List/master/socks5.txt", RAW + "monosans/proxy-list/main/proxies/socks5.txt",
                  RAW + "hookzof/socks5_list/master/proxy.txt"],
       "HTTP": [RAW + "TheSpeedX/PROXY-List/master/http.txt", RAW + "monosans/proxy-list/main/proxies/http.txt"]}
SNIS = ["security.vercel.com", "hcaptcha.com", "www.snapp.ir", "snapp.ir", "auth.vercel.com",
        "www.digikala.com", "www.aparat.com", "www.speedtest.net", "cdnjs.cloudflare.com"]
APP_DIR = os.path.join(os.path.expanduser("~"), ".netfree")
CFG = os.path.join(APP_DIR, "config.json")
IDLE = 300  # seconds of silence before a relayed connection is dropped


def load_cfg():
    try:
        with open(CFG, encoding="utf8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_cfg(d):
    try:
        os.makedirs(APP_DIR, exist_ok=True)
        with open(CFG, "w", encoding="utf8") as f:
            json.dump(d, f, ensure_ascii=False, indent=1)
    except Exception:
        pass


# ---------- probes ----------
def tcp_ping(ip, port=443, t=3):
    s = time.perf_counter()
    try:
        with socket.create_connection((ip, port), t):
            return (time.perf_counter() - s) * 1000
    except OSError:
        return None


def _ctx():
    c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
    return c


def tls_ping(ip, sni, t=3, port=443):
    s = time.perf_counter()
    try:
        with socket.create_connection((ip, port), t) as c, _ctx().wrap_socket(c, server_hostname=sni):
            return (time.perf_counter() - s) * 1000
    except (OSError, ssl.SSLError):
        return None


def cf_check(ip, sni, t=4, port=443):
    """True if the IP really answers like a CDN edge for this SNI. Blackout mode fronts through several
    CDNs (not just Cloudflare), so this accepts any coherent HTTP response rather than requiring a
    Cloudflare-specific header."""
    try:
        with socket.create_connection((ip, port), t) as c, _ctx().wrap_socket(c, server_hostname=sni) as s:
            s.settimeout(t)
            s.sendall(f"HEAD / HTTP/1.1\r\nHost: {sni}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode())
            h = s.recv(2048).lower()
            return h.startswith(b"http/") and b" 400 " not in h[:20] and b" 421 " not in h[:20]
    except (OSError, ssl.SSLError):
        return False


def probe_ip(ip, sni, samples=3, verify=True, ports=(443,)):
    """Several TLS samples -> median latency, jitter, loss, optional CDN verification.
    Tries each port in `ports` in turn (Blackout mode passes ALT_PORTS) and keeps the first that answers."""
    port, lat = 443, []
    for p in ports:
        lat = [m for m in (tls_ping(ip, sni, 3, p) for _ in range(samples)) if m is not None]
        if lat and 1 - len(lat) / samples <= 0.5:
            port = p; break
    if not lat or 1 - len(lat) / samples > 0.5:
        return None
    if verify and not cf_check(ip, sni, 4, port):
        return None
    med = statistics.median(lat); jit = max(lat) - min(lat); loss = 1 - len(lat) / samples
    return {"ip": ip, "port": port, "tls": med, "tcp": tcp_ping(ip, port) or med, "jit": jit, "ok": f"{len(lat)}/{samples}",
            "score": med + 1.5 * jit + 400 * loss}


def _rn(c, n):
    b = b""
    while len(b) < n:
        x = c.recv(n - len(b))
        if not x: raise OSError("eof")
        b += x
    return b


def proxy_tunnel(kind, host, port, dh, dp, t=6):
    """Open a tunnel through a SOCKS5/HTTP proxy to dh:dp. Returns a connected socket or None."""
    c = None
    try:
        c = socket.create_connection((host, port), t); c.settimeout(t)
        if kind == "SOCKS5":
            c.sendall(b"\x05\x01\x00")
            if _rn(c, 2) != b"\x05\x00": raise OSError("auth")
            d = dh.encode()
            c.sendall(b"\x05\x01\x00\x03" + bytes([len(d)]) + d + struct.pack(">H", dp))
            h = _rn(c, 4)
            if h[1]: raise OSError("refused")
            _rn(c, {1: 6, 4: 18}.get(h[3]) or (_rn(c, 1)[0] + 2))
        else:
            c.sendall(f"CONNECT {dh}:{dp} HTTP/1.1\r\nHost: {dh}:{dp}\r\n\r\n".encode())
            buf = b""
            while b"\r\n\r\n" not in buf and len(buf) < 4096:
                x = c.recv(1024)
                if not x: raise OSError("eof")
                buf += x
            if b" 200" not in buf.split(b"\r\n")[0]: raise OSError("refused")
        return c
    except (OSError, IndexError):
        if c: c.close()
        return None


def proxy_ping(kind, host, port, t=6):
    s0 = time.perf_counter(); c = proxy_tunnel(kind, host, port, "cp.cloudflare.com", 80, t)
    if not c: return None
    try:
        c.sendall(b"GET /generate_204 HTTP/1.1\r\nHost: cp.cloudflare.com\r\nConnection: close\r\n\r\n")
        return (time.perf_counter() - s0) * 1000 if b" 204" in c.recv(256)[:20] else None
    except OSError:
        return None
    finally:
        c.close()


def proxy_probe(kind, host, port, samples=2, t=6):
    """Real latency (several samples) + TLS-integrity check (verified cert through the tunnel => not MITM)."""
    lat = [m for m in (proxy_ping(kind, host, port, t) for _ in range(samples)) if m is not None]
    if not lat: return None
    secure = False
    c = proxy_tunnel(kind, host, port, "cloudflare.com", 443, t)
    if c:
        try:
            with _vctx().wrap_socket(c, server_hostname="cloudflare.com"): secure = True
        except (OSError, ssl.SSLError):
            pass
        finally:
            c.close()
    med = statistics.median(lat); jit = max(lat) - min(lat)
    return {"kind": kind, "addr": f"{host}:{port}", "host": host, "port": port, "lat": med, "jit": jit, "secure": secure,
            "score": med + jit + (0 if secure else 600) + 300 * (1 - len(lat) / samples)}


def fetch_proxies(kind, n, log=None):
    found = set()

    def get(u):
        try:
            return set(re.findall(r"(\d+\.\d+\.\d+\.\d+):(\d+)", urllib.request.urlopen(u, timeout=12, context=_vctx()).read().decode("utf8", "ignore")))
        except Exception as e:
            if log: log(f"دریافت لیست ناموفق: {u.split('/')[4]} ({e.__class__.__name__})")
            return set()
    with ThreadPoolExecutor(4) as ex:
        for r in ex.map(get, SRC[kind]): found |= r
    found = list(found); random.shuffle(found)
    return [(h, int(p)) for h, p in found[:n]]


def lan_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as x:
            x.connect(("10.255.255.255", 1)); return x.getsockname()[0]
    except OSError:
        return "127.0.0.1"


_dns = {}


def doh(host):
    """Resolve through Cloudflare DNS-over-HTTPS (1.1.1.1) to dodge poisoned local DNS. Cached 5 min."""
    hit = _dns.get(host)
    if hit and hit[1] > time.time(): return hit[0]
    try:
        req = urllib.request.Request(f"https://1.1.1.1/dns-query?name={host}&type=A", headers={"accept": "application/dns-json"})
        data = json.load(urllib.request.urlopen(req, timeout=4, context=_vctx()))
        ips = [a["data"] for a in data.get("Answer", []) if a.get("type") == 1]
        if ips:
            _dns[host] = (ips, time.time() + 300); return ips
    except Exception:
        pass
    return None


def hello(sni):
    """Minimal TLS ClientHello carrying the fake SNI."""
    n = sni.encode()
    ext = b"\x00\x00" + struct.pack(">HHBH", len(n) + 5, len(n) + 3, 0, len(n)) + n
    ext += b"\x00\x0a\x00\x04\x00\x02\x00\x1d" + b"\x00\x0d\x00\x04\x00\x02\x04\x03"
    body = b"\x03\x03" + os.urandom(32) + b"\x00\x00\x02\x13\x01\x01\x00" + struct.pack(">H", len(ext)) + ext
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def sni_offset(d):
    """(offset, length) of the SNI hostname inside a TLS ClientHello, or None."""
    try:
        i = 5 + 4 + 2 + 32
        i += 1 + d[i]
        i += 2 + int.from_bytes(d[i:i + 2], "big")
        i += 1 + d[i]
        end = i + 2 + int.from_bytes(d[i:i + 2], "big"); i += 2
        while i + 4 <= min(end, len(d)):
            t = int.from_bytes(d[i:i + 2], "big"); l = int.from_bytes(d[i + 2:i + 4], "big")
            if t == 0: return i + 9, int.from_bytes(d[i + 7:i + 9], "big")
            i += 4 + l
    except Exception:
        pass
    return None


def frag_plan(d, extreme=False):
    """Split the first TLS record so the hostname is cut in the middle (breaks naive DPI matching).
    extreme=True (Blackout mode) adds many more, smaller, pseudo-random cuts throughout the whole
    record - closer to what GoodbyeDPI / zapret-style fragmenters do - for DPI boxes that reassemble
    only a few segments before giving up, or that match on a minimum contiguous run of the SNI string."""
    cuts = {1, 5}
    so = sni_offset(d)
    if so: cuts.add(so[0] + max(1, so[1] // 2))
    else: cuts |= {40, 90}
    if extreme:
        cuts |= set(range(2, min(len(d) - 2, 300), random.randint(3, 6)))
        if so: cuts |= {so[0] + 1, so[0] + max(1, so[1] // 3), so[0] + max(1, 2 * so[1] // 3), so[0] + so[1] - 1}
    cuts = sorted(c for c in cuts if 0 < c < len(d))
    parts, prev = [], 0
    for c in cuts: parts.append(d[prev:c]); prev = c
    parts.append(d[prev:]); return parts


async def send_frag(w, d, frag, extreme=False):
    if frag and d[:1] == b"\x16" and len(d) > 60:
        try: w.get_extra_info("socket").setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception: pass
        for part in frag_plan(d, extreme):
            w.write(part); await w.drain()
            await asyncio.sleep(random.uniform(0.02, 0.09) if extreme else random.uniform(0.005, 0.03))
    else:
        w.write(d); await w.drain()


# ---------- pools ----------
class Pool:
    """Thread-safe list of upstream endpoints with health tracking (fail count + exponential cool-down)."""
    def __init__(s): s.items, s.lock = [], threading.Lock()

    def __len__(s): return len(s.items)

    def add(s, kind, host, port, lat=0.0):
        with s.lock:
            for e in s.items:
                if (e["kind"], e["host"], e["port"]) == (kind, host, port):
                    e["lat"] = lat or e["lat"]; return e
            e = {"kind": kind, "host": host, "port": port, "lat": lat, "fails": 0, "until": 0.0}
            s.items.append(e); return e

    def remove(s, e):
        with s.lock:
            if e in s.items: s.items.remove(e)

    def clear(s):
        with s.lock: s.items.clear()

    def snapshot(s):
        with s.lock: return list(s.items)

    def ordered(s):
        now, items = time.time(), s.snapshot()
        live = [e for e in items if e["until"] <= now] or sorted(items, key=lambda e: e["until"])[:1]
        return sorted(live, key=lambda e: (min(e["fails"], 3), e["lat"] or 9e9))

    def good(s, e): e["fails"] = 0; e["until"] = 0.0

    def bad(s, e): e["fails"] += 1; e["until"] = time.time() + min(300, 10 * 2 ** min(e["fails"], 5))

    def mark(s, e, ms):
        if ms: e["lat"] = ms; s.good(e)
        else: s.bad(e)


class Stats:
    def __init__(s): s.up = s.down = s.conns = s.active = s.fail = 0; s.t0 = time.time()


# ---------- relay + servers ----------
async def pipe(r, w, st=None, key="down"):
    try:
        while True:
            d = await asyncio.wait_for(r.read(65536), IDLE)
            if not d: break
            w.write(d); await w.drain()
            if st: setattr(st, key, getattr(st, key) + len(d))
    except Exception:
        pass
    finally:
        try: w.close()
        except Exception: pass


async def open_tcp(host, port, t=8):
    return await asyncio.wait_for(asyncio.open_connection(host, port), t)


async def via_proxy(kind, uh, up, h, p, t=10):
    rr, rw = await open_tcp(uh, up, t)
    try:
        hb = h.encode()
        if kind == "SOCKS5":
            rw.write(b"\x05\x01\x00")
            if await asyncio.wait_for(rr.readexactly(2), t) != b"\x05\x00": raise OSError("auth")
            rw.write(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack(">H", p))
            rep = await asyncio.wait_for(rr.readexactly(4), t)
            if rep[1]: raise OSError("refused")
            n = {1: 4, 4: 16}.get(rep[3])
            if n is None: n = (await rr.readexactly(1))[0]
            await asyncio.wait_for(rr.readexactly(n + 2), t)
        else:
            rw.write(f"CONNECT {h}:{p} HTTP/1.1\r\nHost: {h}:{p}\r\n\r\n".encode())
            head = await asyncio.wait_for(rr.readuntil(b"\r\n\r\n"), t)
            if b" 200" not in head.split(b"\r\n")[0]: raise OSError("refused")
        return rr, rw
    except BaseException:
        rw.close(); raise


class Srv:
    def __init__(s, host, port, log, frag=True):
        s.host, s.port, s.log, s.frag, s.extreme = host, port, log, frag, False
        s.stats, s.state, s.loop, s.stopping = Stats(), "starting", None, False

    def run(s):
        try: asyncio.run(s.main())
        except Exception as e: s.log(f"خطا: {e}")
        finally: s.state = "stopped"

    async def main(s):
        s.ev = asyncio.Event(); s.sem = asyncio.Semaphore(350); s.loop = asyncio.get_running_loop()
        try:
            srv = await asyncio.start_server(s.handle, s.host, s.port, backlog=256)
        except OSError as e:
            s.log(f"پورت {s.port} قابل استفاده نیست: {e}"); return
        s.state = "running"; s.log(f"{s.__class__.__name__} روی {s.host}:{s.port} فعال شد")
        task = asyncio.create_task(s.extra())
        await s.ev.wait()
        task.cancel(); srv.close()

    async def extra(s): pass

    def stop(s):
        s.stopping = True
        if s.loop: s.loop.call_soon_threadsafe(s.ev.set)

    async def up(s, r, w):
        """client -> remote; fragments the very first TLS hello when enabled."""
        try:
            d = await asyncio.wait_for(r.read(65536), IDLE)
            if d: await send_frag(w, d, s.frag, s.extreme); s.stats.up += len(d)
        except Exception:
            w.close(); return
        await pipe(r, w, s.stats, "up")

    async def relay(s, r, w, rr, rw):
        await asyncio.gather(s.up(r, rw), pipe(rr, w, s.stats, "down"))


class Socks(Srv):
    """One port, three protocols (SOCKS5 / SOCKS4(a) / HTTP proxy): upstream pool with automatic failover, DoH, TLS fragmentation, timeouts, connection cap."""
    def __init__(s, host, port, log, pool, frag=True, use_doh=True):
        super().__init__(host, port, log, frag); s.pool, s.doh = pool, use_doh

    async def resolve(s, h):
        if not s.doh or ":" in h or re.fullmatch(r"[\d.]+", h): return [h]
        ips = await asyncio.get_running_loop().run_in_executor(None, doh, h)
        return (ips or []) + [h]

    async def connect(s, h, p):
        if len(s.pool):
            for e in s.pool.ordered()[:3]:
                try:
                    res = await via_proxy(e["kind"], e["host"], e["port"], h, p)
                    s.pool.good(e); return res
                except Exception:
                    s.pool.bad(e)
            s.log(f"همه آپ‌استریم‌ها برای {h} ناموفق بودند؛ مورد بعدی نوبت می‌گیرد")
            return None
        for ip in (await s.resolve(h))[:3]:
            try: return await open_tcp(ip, p)
            except Exception: pass
        return None

    async def _socks5(s, r, w):
        n = (await asyncio.wait_for(r.readexactly(1), 10))[0]
        await asyncio.wait_for(r.readexactly(n), 10); w.write(b"\x05\x00")
        _, cmd, _, at = await asyncio.wait_for(r.readexactly(4), 10)
        if at == 1: h = socket.inet_ntoa(await r.readexactly(4))
        elif at == 3: h = (await r.readexactly((await r.readexactly(1))[0])).decode("utf8", "ignore")
        else: h = socket.inet_ntop(socket.AF_INET6, await r.readexactly(16))
        p = struct.unpack(">H", await r.readexactly(2))[0]
        if cmd != 1:
            w.write(b"\x05\x07\x00\x01" + b"\0" * 6); return None
        return h, p, b"\x05\x00\x00\x01" + b"\0" * 6, b"\x05\x04\x00\x01" + b"\0" * 6, b""

    async def _socks4(s, r, w):  # SOCKS4 and SOCKS4a (Chrome/Edge use this for "socks=" system proxies)
        hd = await asyncio.wait_for(r.readexactly(7), 10)
        if hd[0] != 1:
            w.write(b"\x00\x5b" + b"\0" * 6); return None
        p = struct.unpack(">H", hd[1:3])[0]; h = socket.inet_ntoa(hd[3:7])
        await asyncio.wait_for(r.readuntil(b"\x00"), 10)  # user id
        if hd[3:6] == b"\0\0\0" and hd[6] != 0:
            h = (await asyncio.wait_for(r.readuntil(b"\x00"), 10))[:-1].decode("utf8", "ignore")
        return h, p, b"\x00\x5a" + b"\0" * 6, b"\x00\x5b" + b"\0" * 6, b""

    async def _http(s, first, r, w):  # HTTP proxy: CONNECT tunnels (https) and absolute-URI requests (http)
        head = first + await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 15)
        line, _, rest = head.partition(b"\r\n")
        parts = line.decode("latin1").split()
        bad = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"
        if len(parts) < 3:
            return None
        m, tgt, ver = parts[0], parts[1], parts[2]
        if m.upper() == "CONNECT":
            h, _, p = tgt.rpartition(":")
            if not h: h, p = tgt, "443"
            return h.strip("[]"), int(p), b"HTTP/1.1 200 Connection Established\r\n\r\n", bad, b""
        mm = re.match(r"(?i)https?://(\[[^\]]+\]|[^/:]+)(?::(\d+))?(/.*)?$", tgt)
        if not mm:
            w.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"); return None
        hdrs = [l for l in rest.split(b"\r\n") if l and not l.lower().startswith((b"proxy-connection", b"connection", b"proxy-authorization"))]
        req = f"{m} {mm.group(3) or '/'} {ver}\r\n".encode("latin1") + b"\r\n".join(hdrs) + b"\r\nConnection: close\r\n\r\n"
        return mm.group(1).strip("[]"), int(mm.group(2) or 80), b"", bad, req

    async def handle(s, r, w):
        rw, counted = None, False
        async with s.sem:
            try:
                first = await asyncio.wait_for(r.readexactly(1), 10)
                info = await (s._socks5(r, w) if first == b"\x05" else s._socks4(r, w) if first == b"\x04" else s._http(first, r, w))
                if not info: return
                h, p, ok, fail, early = info
                s.stats.conns += 1; s.stats.active += 1; counted = True
                res = await s.connect(h, p)
                if not res:
                    s.stats.fail += 1; w.write(fail); return
                rr, rw = res
                if ok: w.write(ok); await w.drain()
                if early: rw.write(early); await rw.drain()
                await s.relay(r, w, rr, rw)
            except Exception:
                pass
            finally:
                if counted: s.stats.active -= 1
                w.close()
                if rw: rw.close()

class Forwarder(Srv):
    """Local port -> best Cloudflare IP:443 from the pool. Failover at connect time + background health checks."""
    def __init__(s, host, port, log, pool, frag=True, sni="security.vercel.com"):
        super().__init__(host, port, log, frag); s.pool, s.sni = pool, sni

    async def extra(s):
        loop = asyncio.get_running_loop()
        while True:
            await asyncio.sleep(40)
            for e in s.pool.snapshot():
                s.pool.mark(e, await loop.run_in_executor(None, tls_ping, e["host"], s.sni, 4, e.get("port", 443)))

    async def handle(s, r, w):
        rw, counted = None, False
        async with s.sem:
            try:
                s.stats.conns += 1; s.stats.active += 1; counted = True
                rr = None
                for e in s.pool.ordered()[:4]:
                    try:
                        rr, rw = await open_tcp(e["host"], e["port"], 6); s.pool.good(e); break
                    except Exception:
                        s.pool.bad(e); rr = rw = None
                if not rw:
                    s.stats.fail += 1; s.log("هیچ IP سالمی در استخر پاسخ نداد"); return
                await s.relay(r, w, rr, rw)
            except Exception:
                pass
            finally:
                if counted: s.stats.active -= 1
                w.close()
                if rw: rw.close()




# ---------- one-click real connection ----------
def tunnel_https(kind, host, port, dest, t=6, path="/generate_204", n=300):
    """Verified-TLS GET to dest through a proxy tunnel; returns the first n response bytes, or None."""
    c = proxy_tunnel(kind, host, port, dest, 443, t)
    if not c: return None
    try:
        with _vctx().wrap_socket(c, server_hostname=dest) as s:
            s.settimeout(t)
            s.sendall(f"GET {path} HTTP/1.1\r\nHost: {dest}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode())
            data = b""
            try:
                while len(data) < n:
                    x = s.recv(n - len(data))
                    if not x: break
                    data += x
            except OSError:
                pass
            return data or None
    except (OSError, ssl.SSLError):
        return None
    finally:
        c.close()


def speed_test(kind, host, port, t=8, nbytes=300000):
    """KB/s while downloading nbytes from Cloudflare through the proxy (0 if it fails or stalls)."""
    c = proxy_tunnel(kind, host, port, "speed.cloudflare.com", 443, t)
    if not c: return 0
    try:
        with _vctx().wrap_socket(c, server_hostname="speed.cloudflare.com") as s:
            s.settimeout(t); s0 = time.perf_counter()
            s.sendall(f"GET /__down?bytes={nbytes} HTTP/1.1\r\nHost: speed.cloudflare.com\r\nConnection: close\r\n\r\n".encode())
            got = 0
            try:
                while time.perf_counter() - s0 < t:
                    x = s.recv(65536)
                    if not x: break
                    got += len(x)
            except OSError:
                pass
            return got / 1024 / max(0.05, time.perf_counter() - s0) if got >= nbytes * 0.8 else 0
    except (OSError, ssl.SSLError):
        return 0
    finally:
        c.close()


def strict_probe(kind, host, port, strict=True):
    """A route only counts if it really reaches YouTube (and Google) over verified TLS and moves data at a usable speed."""
    t0 = time.perf_counter(); r = tunnel_https(kind, host, port, "www.youtube.com", 6)
    if not r or b" 204" not in r[:20]: return None
    lat, kb = (time.perf_counter() - t0) * 1000, 0
    if strict:
        g = tunnel_https(kind, host, port, "www.google.com", 6)
        if not g or b" 204" not in g[:20]: return None
        kb = speed_test(kind, host, port)
        if kb < 40: return None
    return {"kind": kind, "addr": f"{host}:{port}", "host": host, "port": port, "lat": lat, "jit": 0, "secure": True,
            "kbps": kb, "score": lat + 20000 / max(kb, 40)}


def real_check(port, t=8):
    """End-to-end test THROUGH the local server: YouTube must answer over verified TLS.
    Returns (ms, exit_ip, country) or None. Green in the UI means YouTube is actually reachable."""
    s0 = time.perf_counter(); r = tunnel_https("SOCKS5", "127.0.0.1", port, "www.youtube.com", t)
    if not r or b" 204" not in r[:20]: return None
    ms, ip, loc = (time.perf_counter() - s0) * 1000, "?", "?"
    tr = tunnel_https("SOCKS5", "127.0.0.1", port, "1.1.1.1", t, "/cdn-cgi/trace", 1500)
    if tr:
        m = dict(l.split("=", 1) for l in tr.decode("utf8", "ignore").splitlines() if "=" in l)
        ip, loc = m.get("ip", "?"), m.get("loc", "?")
    return ms, ip, loc


def find_best(n, workers, ev, status, only_secure=True, want=8):
    """Fetch public SOCKS5+HTTP proxy lists, test them in parallel, return the best `want` (lowest score)."""
    status("دریافت لیست پروکسی‌ها ...")
    cands = [(k, h, p) for k in ("SOCKS5", "HTTP") for h, p in fetch_proxies(k, n)]
    random.shuffle(cands)
    if not cands or ev.is_set(): return []
    status(f"تست {len(cands)} پروکسی ...")
    res, done = [], 0

    def one(c): return None if ev.is_set() else strict_probe(c[0], c[1], c[2], only_secure)
    with ThreadPoolExecutor(workers) as ex:
        futs = [ex.submit(one, c) for c in cands]
        for f in as_completed(futs):
            done += 1
            try: r = f.result()
            except Exception: r = None
            if r: res.append(r)
            if done % 10 == 0: status(f"تست {done}/{len(cands)} — {len(res)} مسیر سالم")
            if len(res) >= want * 2 or ev.is_set():
                for g in futs: g.cancel()
                break
    return sorted(res, key=lambda r: r["score"])[:want]


class QuickLink:
    """One click: local SOCKS up -> find best proxies -> verify real end-to-end connectivity -> watchdog
    that re-verifies every few seconds and automatically picks fresh routes when the link dies."""
    ok_wait, bad_wait = 15, 4

    def __init__(s, pool, status, state, on_server):
        s.pool, s.status, s.state, s.on_server = pool, status, state, on_server
        s.stop = threading.Event()

    def start(s, lan, secure):
        s.stop.set(); s.stop = ev = threading.Event()
        threading.Thread(target=s._run, args=(ev, lan, secure), daemon=True).start()

    def cancel(s): s.stop.set()

    def _dead(s):
        items = s.pool.snapshot(); return bool(items) and all(e["fails"] >= 3 for e in items)

    def _refresh(s, ev, port, secure, attempts, sa):
        for i in range(attempts):
            sa(f"جستجوی بهترین مسیر (تلاش {i + 1}/{attempts}) ...")
            best = find_best(300, 150, ev, sa, secure and i < attempts - 1, 8)  # last attempt relaxes the TLS filter
            if ev.is_set(): return False
            if not best: continue
            s.pool.clear()
            for r in best: s.pool.add(r["kind"], r["host"], r["port"], r["lat"])
            sa("بررسی اتصال واقعی ...")
            if any(real_check(port) for _ in range(3)): return True
        return False

    def _run(s, ev, lan, secure):
        st = lambda *a: None if ev.is_set() else s.state(*a)
        sa = lambda m: None if ev.is_set() else s.status(m)
        try:
            srv = s.on_server(lan)
            if not srv: return st("failed", "راه‌اندازی سرور محلی ناموفق بود (پورت اشغال است؟)")
            port, first, fails = srv.port, True, 0
            while not ev.is_set():
                if srv.state == "stopped": return st("idle", None)
                if first or fails >= 2 or s._dead():
                    if not first: st("connecting", None)
                    if not s._refresh(ev, port, secure, 3 if first else 2, sa):
                        if ev.is_set(): break
                        if first: return st("failed", "مسیر سالمی پیدا نشد؛ دوباره تلاش کنید")
                        ev.wait(s.bad_wait); continue
                    first, fails = False, 0
                res = real_check(port)
                if res: fails = 0; st("connected", {"ms": res[0], "ip": res[1], "loc": res[2]})
                else: fails += 1; sa("اتصال ضعیف است؛ در حال بررسی ...")
                ev.wait(s.ok_wait if res else s.bad_wait)
        except Exception as e:
            st("failed", f"خطا: {e}")



# ======================= Kivy UI (Android) =======================
from kivy.app import App
from kivy.clock import Clock
from kivy.core.clipboard import Clipboard
from kivy.core.text import Label as CoreLabel, LabelBase
from kivy.core.window import Window
from kivy.graphics import Color, Rectangle, RoundedRectangle
from kivy.metrics import dp, sp
from kivy.properties import BooleanProperty, ListProperty, NumericProperty, ObjectProperty
from kivy.uix.anchorlayout import AnchorLayout
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.progressbar import ProgressBar
from kivy.uix.recycleboxlayout import RecycleBoxLayout
from kivy.uix.recycleview import RecycleView
from kivy.uix.screenmanager import NoTransition, Screen, ScreenManager
from kivy.uix.scrollview import ScrollView
from kivy.uix.spinner import Spinner
from kivy.uix.switch import Switch
from kivy.uix.textinput import TextInput
from kivy.utils import platform

BG, CARD, TXT, MUT = (.05, .07, .13, 1), (.09, .125, .2, 1), (.9, .91, .92, 1), (.58, .64, .72, 1)
ACC, GRN, RED, GRY, AMB = (.145, .388, .922, 1), (.063, .725, .506, 1), (.937, .267, .267, 1), (.392, .455, .545, 1), (.96, .62, .04, 1)
NAV = [("quick", "سریع"), ("dash", "داشبورد"), ("scan", "اسکن IP"), ("online", "پروکسی"), ("pool", "استخر"),
       ("blackout", "قطعی شدید"), ("log", "لاگ")]

# ---- Persian text: Kivy has no RTL shaping on Android -> reshape + bidi each line ourselves
_AR = re.compile(r"[\u0600-\u06FF]")
try:
    import arabic_reshaper
    from bidi.algorithm import get_display

    def fa(s):
        return "\n".join(get_display(arabic_reshaper.reshape(l)) if _AR.search(l) else l for l in str(s).split("\n"))
except Exception:
    def fa(s): return str(s)


FONT_OK = False  # set True once a Persian-capable font is actually registered; the UI warns in the log if not


def setup_font():
    """Register a font that has Persian/Arabic glyphs as Kivy's default ('Roboto' is the name Kivy's own
    widgets look up, so overriding it here switches every Label - including every WL/RBtn/Row in this app -
    app-wide, with no per-widget font_name needed).

    The previous version of this file only listed fallback paths and never actually shipped a font, so on a
    real phone NONE of those paths existed and every Persian label silently fell back to Kivy's bundled
    'Roboto', which has no Arabic/Persian glyphs at all -> every character renders as a hollow tofu box.
    Fix: ship real font files in fonts/ (added to this build; buildozer.spec's source.include_exts already
    has 'ttf' so they are packaged into the APK) and also widen the on-device fallback search."""
    global FONT_OK
    here = os.path.dirname(os.path.abspath(__file__))
    bundled_reg = os.path.join(here, "fonts", "NetFreeFont.ttf")
    bundled_bold = os.path.join(here, "fonts", "NetFreeFont-Bold.ttf")
    cands = [bundled_reg]
    # common Android system Arabic-script fonts across OEM/API-level variations, in rough order of quality
    cands += [f"/system/fonts/{n}" for n in (
        "NotoNaskhArabic-Regular.ttf", "NotoNaskhArabicUI-Regular.ttf", "NotoSansArabic-Regular.ttf",
        "NotoSansArabicUI-Regular.ttf", "DroidNaskh-Regular.ttf", "DroidSansArabic.ttf", "NotoSans.ttf")]
    cands += ["C:/Windows/Fonts/tahoma.ttf", "C:/Windows/Fonts/segoeui.ttf",
              "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"]
    for p in cands:
        if os.path.exists(p):
            kw = {"fn_regular": p}
            if p == bundled_reg and os.path.exists(bundled_bold): kw["fn_bold"] = bundled_bold
            try:
                LabelBase.register(name="Roboto", **kw); FONT_OK = True
                return p
            except Exception:
                continue
    return None


def fmt(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB": return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024


# ---- real Android VPN (the phone's key/shield icon). On non-Android platforms VPNManager.supported() is
# False and Quick Connect silently falls back to "just the local proxy", exactly like before.
try:
    from jnius import autoclass
except Exception:
    autoclass = None
from tun2socks import Tun2Socks, DohClient

VPN_REQUEST_CODE = 7824


class VPNManager:
    """Wires the Java NetFreeVpnService (creates the real system TUN device, which is what makes Android
    show the key/shield 'VPN connected' icon) to tun2socks.py (turns the raw IP packets from that TUN into
    connections through this app's own proxy pool). Previously the app only ever bound a local SOCKS5 port;
    unless something on the phone was manually configured to use 127.0.0.1:<port> as its proxy (most apps
    never are), the phone's actual connection never changed - hence 'no key icon, nothing really connects'."""
    def __init__(s, pool, log):
        s.pool, s.log, s.stats = pool, log, Stats()
        s.loop = s.thread = s.t2s = s.fd = None
        s.up_flag = False

    @staticmethod
    def supported():
        return platform == "android" and autoclass is not None

    def consent(s, activity, on_result):
        """The one-time Android 'NetFree wants to set up a VPN connection' dialog; on_result(bool) fires with the outcome."""
        Vpn = autoclass("org.netfree.netfree.NetFreeVpnService")
        if not Vpn.needsConsent(activity):
            return on_result(True)
        try:
            from android import activity as aact
        except Exception:
            return on_result(False)

        def cb(request_code, result_code, data=None):
            if request_code == VPN_REQUEST_CODE:
                try: aact.unbind(on_activity_result=cb)
                except Exception: pass
                on_result(result_code == -1)  # Activity.RESULT_OK == -1
        aact.bind(on_activity_result=cb)
        Vpn.askConsent(activity, VPN_REQUEST_CODE)

    async def _connect(s, host, port):
        """Same failover-through-the-pool logic as Socks.connect; falls back to a direct connection if the
        pool is empty or every upstream fails, so whitelisted/unblocked sites keep working either way."""
        for e in s.pool.ordered()[:3]:
            try:
                res = await via_proxy(e["kind"], e["host"], e["port"], host, port)
                s.pool.good(e); return res
            except Exception:
                s.pool.bad(e)
        try:
            return await open_tcp(host, port, 8)
        except Exception:
            return None

    def _runner(s, extreme_fn):
        loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop); s.loop = loop
        doh = DohClient(s._connect, _vctx)
        s.t2s = Tun2Socks(s.fd, s._connect, doh, s.log, send_frag, lambda: True, s.stats, extreme_fn)
        s.t2s.attach(loop)
        try: loop.run_forever()
        finally:
            try: s.t2s.detach()
            except Exception: pass

    def start(s, activity, extreme_fn, on_state):
        """consent -> start the Java VpnService -> wait for the TUN fd -> run tun2socks in its own thread/loop."""
        Vpn = autoclass("org.netfree.netfree.NetFreeVpnService")

        def after_consent(ok):
            if not ok:
                s.log("اجازه VPN داده نشد؛ اتصال واقعی سیستمی (آیکون کلید) فعال نشد"); on_state(False); return
            Vpn.start(activity)

            def wait_fd(tries=60):
                if Vpn.up and Vpn.fd >= 0:
                    s.fd = Vpn.fd; s.up_flag = True
                    s.thread = threading.Thread(target=s._runner, args=(extreme_fn,), daemon=True); s.thread.start()
                    s.log("VPN سیستمی فعال شد؛ آیکون کلید باید روی نوار وضعیت گوشی ظاهر شده باشد"); on_state(True)
                elif Vpn.error:
                    s.log(f"خطای VPN: {Vpn.error}"); on_state(False)
                elif tries > 0:
                    Clock.schedule_once(lambda dt: wait_fd(tries - 1), 0.1)
                else:
                    s.log("راه‌اندازی VPN بیش از حد طول کشید؛ دوباره تلاش کنید"); on_state(False)
            wait_fd()
        s.consent(activity, after_consent)

    def stop(s):
        if autoclass:
            try: autoclass("org.netfree.netfree.NetFreeVpnService").stop()
            except Exception: pass
        if s.loop:
            try: s.loop.call_soon_threadsafe(s.loop.stop)
            except Exception: pass
        s.loop = s.thread = s.t2s = s.fd = None; s.up_flag = False


# ---- widgets
class RBtn(Button):
    bg = ListProperty(ACC)
    circle = BooleanProperty(False)

    def __init__(s, **k):
        k.setdefault("background_normal", ""); k.setdefault("background_down", ""); k["background_color"] = (0, 0, 0, 0)
        super().__init__(**k)
        with s.canvas.before:
            s._c = Color(*s.bg); s._r = RoundedRectangle(pos=s.pos, size=s.size, radius=[dp(12)])
        s.bind(pos=s._u, size=s._u, bg=s._u, state=s._u, circle=s._u); s._u()

    def _u(s, *a):
        k, b = (.75 if s.state == "down" else 1), s.bg
        s._c.rgba = (b[0] * k, b[1] * k, b[2] * k, b[3] if len(b) > 3 else 1)
        s._r.pos, s._r.size = s.pos, s.size
        s._r.radius = [min(s.width, s.height) / 2 if s.circle else dp(12)]


def B(text, cb, color=ACC, h=44, size=13):
    return RBtn(text=fa(text), on_release=lambda *_: cb(), bg=color, font_size=sp(size), size_hint_y=None, height=dp(h))


class WL(Label):
    """Wrapping label. Persian paragraphs are word-wrapped in logical order BEFORE reshaping, so lines read correctly."""
    def __init__(s, text="", size=13, color=TXT, bold=False, center=False, smart=True, **k):
        super().__init__(font_size=sp(size), color=color, bold=bold, size_hint_y=None,
                         halign="center" if center else "right", valign="middle", **k)
        s.smart, s.raw, s._ready = smart, "", False
        s.bind(width=s._on_w, texture_size=s._on_h); s.set(text)

    def _on_w(s, *a): s._ready = True; s.text_size = (s.width, None); s._layout()
    def _on_h(s, *a): s.height = max(dp(22), s.texture_size[1] + dp(6))
    def set(s, t): s.raw = str(t); s._layout()

    def _layout(s):
        if not (s.smart and s._ready and _AR.search(s.raw)):
            s.text = fa(s.raw); return
        cl, mw, out = CoreLabel(font_name=s.font_name, font_size=s.font_size), s.width - dp(4), []
        for para in s.raw.split("\n"):
            cur = ""
            for w in para.split(" "):
                t = (cur + " " + w) if cur else w
                if cur and cl.get_extents(fa(t))[0] > mw: out.append(cur); cur = w
                else: cur = t
            out.append(cur)
        s.text = "\n".join(fa(l) for l in out)


class Card(BoxLayout):
    def __init__(s, **k):
        k.setdefault("orientation", "vertical"); k.setdefault("padding", dp(12)); k.setdefault("spacing", dp(8)); k.setdefault("size_hint_y", None)
        super().__init__(**k)
        s.bind(minimum_height=s.setter("height"))
        with s.canvas.before:
            Color(*CARD); s._r = RoundedRectangle(pos=s.pos, size=s.size, radius=[dp(14)])
        s.bind(pos=s._u, size=s._u)

    def _u(s, *a): s._r.pos, s._r.size = s.pos, s.size


class Row(Button):
    idx, sel, cb = NumericProperty(0), BooleanProperty(False), ObjectProperty(None, allownone=True)

    def __init__(s, **k):
        k.setdefault("background_normal", ""); k.setdefault("background_down", "")
        super().__init__(**k)
        s.halign, s.valign, s.font_size = "left", "middle", sp(12)
        s.bind(size=lambda *_: setattr(s, "text_size", (s.width - dp(16), s.height)), sel=s._c); s._c()

    def _c(s, *a): s.background_color = ACC if s.sel else (.12, .16, .25, 1)

    def on_release(s):
        if s.cb: s.cb(s.idx)


class Table(BoxLayout):
    """Scrollable, tap-to-select list. Each row: {key, title, sub, score, color}."""
    def __init__(s, h=340):
        super().__init__(orientation="vertical", size_hint_y=None, height=dp(h))
        s.rows, s.sel_key = [], None
        s.rv = RecycleView(bar_width=dp(4), viewclass=Row)
        s.lay = RecycleBoxLayout(default_size=(None, dp(58)), default_size_hint=(1, None), size_hint_y=None, orientation="vertical", spacing=dp(3))
        s.lay.bind(minimum_height=s.lay.setter("height"))
        s.rv.add_widget(s.lay); s.add_widget(s.rv)

    def set_rows(s, rows): s.rows = rows; s._data()

    def _tap(s, i):
        if i < len(s.rows): s.sel_key = s.rows[i]["key"]; s._data()

    def _data(s):
        s.rv.data = [{"text": fa(r["title"] + "\n" + r["sub"]), "idx": i, "sel": r["key"] == s.sel_key, "cb": s._tap,
                      "color": r.get("color", TXT)} for i, r in enumerate(s.rows)]

    def selected(s): return next((r for r in s.rows if r["key"] == s.sel_key), None)


# ---- main screen
class UI(BoxLayout):
    def __init__(self, **k):
        super().__init__(orientation="vertical", **k)
        with self.canvas.before:
            Color(*BG); self._bg = Rectangle(pos=self.pos, size=self.size)
        self.bind(pos=lambda *_: setattr(self._bg, "pos", self.pos), size=lambda *_: setattr(self._bg, "size", self.size))
        self.cfg = load_cfg()
        self.q, self.stop = queue.Queue(), threading.Event()
        self.up_pool, self.ip_pool = Pool(), Pool()
        for rec in self.cfg.get("ip_pool", []):
            h, p, lat = (rec[0], rec[1], rec[2]) if len(rec) == 3 else (rec[0], 443, rec[1])  # old 2-field configs still load
            self.ip_pool.add("IP", h, p, lat)
        for kind, h, p, lat in self.cfg.get("up_pool", []): self.up_pool.add(kind, h, p, lat)  # survives across blackouts
        self.srv = self.fwd = self.wl = None; self.qst, self.cur, self.blk_active = "idle", "quick", False
        self.tbl, self.data, self.dirty, self.prog, self.pool_views, self.logs = {}, {}, set(), {}, [], []
        self._lan, self._lan_t, self.prev, self._pt = "127.0.0.1", 0, (0, 0, time.time()), 0
        self.qlog = lambda m: self.q.put(("log", m))
        self.quick = QuickLink(self.up_pool, lambda m: self.q.put(("qstat", m)),
                               lambda st, info=None: self.q.put(("qstate", st, info)), self.quick_server)
        self.vpn = VPNManager(self.up_pool, self.qlog)
        if not FONT_OK: self.qlog("هشدار: فونت فارسی پیدا/بارگذاری نشد؛ احتمالاً متن‌ها به‌صورت مربع نمایش داده می‌شوند")
        self.sm = ScreenManager(transition=NoTransition()); self.add_widget(self.sm)
        for key, fn in (("quick", self.page_quick), ("dash", self.page_dash), ("scan", self.page_scan),
                        ("online", self.page_online), ("pool", self.page_pool), ("blackout", self.page_blackout),
                        ("log", self.page_log)):
            self.page(key, fn)
        nav = BoxLayout(size_hint_y=None, height=dp(52), spacing=dp(3), padding=dp(3)); self.nav = {}
        for key, t in NAV:
            b = RBtn(text=fa(t), font_size=sp(12), bg=CARD, on_release=lambda b, key=key: self.show(key)); nav.add_widget(b); self.nav[key] = b
        self.add_widget(nav); self.show("quick")
        Clock.schedule_interval(self.poll, 0.5); Clock.schedule_interval(self.tick, 0.4)

    # ----- layout helpers -----
    def page(self, key, fn):
        sv = ScrollView(do_scroll_x=False, bar_width=dp(3))
        col = BoxLayout(orientation="vertical", size_hint_y=None, padding=dp(10), spacing=dp(10))
        col.bind(minimum_height=col.setter("height")); sv.add_widget(col)
        s = Screen(name=key); s.add_widget(sv); self.sm.add_widget(s); fn(col)

    @staticmethod
    def r(*ws, h=46):
        b = BoxLayout(size_hint_y=None, height=dp(h), spacing=dp(6))
        for w in ws: w.size_hint_y = 1; b.add_widget(w)
        return b

    def ent(self, val="", w=110, num=True):
        return TextInput(text=str(val), multiline=False, input_filter="int" if num else None, size_hint_x=None, width=dp(w),
                         background_color=(.14, .19, .29, 1), foreground_color=TXT, cursor_color=TXT, padding=[dp(8), dp(12)], font_size=sp(14))

    def fld(self, parent, text, val):
        t = self.ent(val); parent.add_widget(self.r(WL(text, 13), t)); return t

    def sw(self, parent, text, key, default=True):
        s = Switch(active=bool(self.cfg.get(key, default)), size_hint_x=None, width=dp(90)); parent.add_widget(self.r(WL(text, 13), s)); return s

    def spin(self, parent, text, val, values):
        s = Spinner(text=val, values=values, size_hint_x=None, width=dp(210), background_normal="", background_color=(.14, .19, .29, 1))
        parent.add_widget(self.r(WL(text, 13), s)); return s

    def head(self, c, title, sub):
        c.add_widget(WL(title, 22, bold=True)); c.add_widget(WL(sub, 12, MUT))

    def table(self, parent, key):
        t = Table(); self.tbl[key], self.data[key] = t, []; parent.add_widget(t); return t

    def show(self, k):
        self.cur = k; self.sm.current = k
        for n, b in self.nav.items(): b.bg = ACC if n == k else CARD

    def log(self, m):
        self.logs.append(time.strftime("%H:%M:%S  ") + str(m)); del self.logs[:-150]
        if hasattr(self, "log_lbl"): self.log_lbl.set("\n".join(self.logs))

    def copy(self, v):
        if v: Clipboard.copy(str(v)); self.log(f"کپی شد: {v}")

    # ----- pages -----
    def page_quick(self, c):
        c.add_widget(WL("NetFree", 26, ACC, True, center=True)); c.add_widget(WL("اتصال هوشمند و پایدار", 12, MUT, center=True))
        a = AnchorLayout(size_hint_y=None, height=dp(220))
        self.q_btn = RBtn(text=fa("اتصال"), font_size=sp(28), bg=GRY, size_hint=(None, None), size=(dp(190), dp(190)), circle=True,
                          on_release=lambda *_: self.quick_toggle())
        a.add_widget(self.q_btn); c.add_widget(a)
        self.q_status, self.q_info, self.q_speed = WL("آماده اتصال", 16, TXT, True, center=True), WL("", 12, MUT, center=True), WL("", 12, MUT, center=True)
        for w in (self.q_status, self.q_info, self.q_speed): c.add_widget(w)
        self.q_vpn_status = WL("", 12, AMB, center=True); c.add_widget(self.q_vpn_status)
        k = Card(); self.qlan = self.sw(k, "اشتراک با دستگاه‌های دیگر (هات‌اسپات)", "qlan", False)
        self.qsec = self.sw(k, "فقط مسیرهای تاییدشده (یوتیوب + سرعت)", "qsec", True)
        self.qvpn = self.sw(k, "اتصال واقعی سیستمی (VPN) - آیکون کلید روی گوشی", "qvpn", True)
        if not VPNManager.supported():
            self.qvpn.active, self.qvpn.disabled = False, True
            k.add_widget(WL("VPN سیستمی فقط روی اندروید فعال می‌شود؛ روی این پلتفرم فقط پروکسی محلی کار می‌کند.", 10, MUT))
        c.add_widget(k)
        self.q_addr = WL("", 17, ACC, True, center=True); c.add_widget(self.q_addr)
        c.add_widget(B("کپی آدرس", lambda: self.copy(self.q_addr.raw), GRY))
        c.add_widget(WL("این پورت هم HTTP و هم SOCKS5 می‌فهمد.\nتنظیمات Wi-Fi گوشی > Proxy > Manual > آدرس 127.0.0.1 و همین پورت.\n"
                        "در برنامه‌هایی مثل تلگرام یا Firefox هم می‌توانید همین آدرس را دستی بدهید.", 11, MUT, center=True))

    def page_dash(self, c):
        self.head(c, "داشبورد اتصال", "سرویس را روشن کنید، سپس آدرس را در برنامه وارد کنید")
        k = Card(); self.v_state, self.v_speed, self.v_conn = WL("", 15, bold=True), WL("", 13), WL("", 13)
        self.s_socks, self.s_fwd = WL("", 12, MUT), WL("", 12, MUT)
        for w in (self.v_state, self.v_speed, self.v_conn, self.s_socks, self.s_fwd): k.add_widget(w)
        c.add_widget(k)

        k = Card(); k.add_widget(WL("SOCKS5 / HTTP Server", 16, bold=True))
        self.port = self.fld(k, "پورت", self.cfg.get("port", 1080)); self.lan = self.sw(k, "اشتراک روی شبکه (هات‌اسپات)", "lan", False)
        self.frag = self.sw(k, "TLS fragment", "frag"); self.doh = self.sw(k, "DNS امن (DoH)", "doh")
        self.lbl_up = WL("", 12, MUT); k.add_widget(self.lbl_up)
        self.b_socks = B("روشن کردن سرور", self.toggle_socks); k.add_widget(self.b_socks)
        k.add_widget(self.r(B("تست اتصال", self.test_socks, GRY), B("کپی آدرس", lambda: self.copy(self.addr.raw), GRY)))
        k.add_widget(B("حذف آپ‌استریم‌ها", lambda: (self.up_pool.clear(), self.log("استخر آپ‌استریم خالی شد")), GRY))
        self.addr = WL("", 17, ACC, True, center=True); k.add_widget(self.addr); c.add_widget(k)

        k = Card(); k.add_widget(WL("Cloudflare IP Forwarder", 16, bold=True))
        self.fport = self.fld(k, "پورت", self.cfg.get("fport", 10443)); self.flan = self.sw(k, "اشتراک روی شبکه", "flan", False)
        self.ffrag = self.sw(k, "TLS fragment", "ffrag"); self.fsni = self.spin(k, "SNI", self.cfg.get("fsni", SNIS[0]), SNIS)
        self.lbl_ip = WL("", 12, MUT); k.add_widget(self.lbl_ip)
        self.b_fwd = B("روشن کردن فوروارد", self.toggle_fwd); k.add_widget(self.b_fwd)
        k.add_widget(self.r(B("کپی آدرس", lambda: self.copy(self.faddr.raw), GRY),
                            B("حذف IPها", lambda: (self.ip_pool.clear(), self.log("استخر IP خالی شد")), GRY)))
        self.faddr = WL("", 17, ACC, True, center=True); k.add_widget(self.faddr)
        k.add_widget(WL("کانفیگ V2Ray/Xray (آدرس سرور) را روی این آدرس بگذارید؛ برنامه خودش سالم‌ترین IP را انتخاب و در صورت خرابی عوض می‌کند.", 11, MUT))
        c.add_widget(k)

    def page_scan(self, c):
        self.head(c, "اسکن IP کلودفلر", "اسکن رنج‌های بزرگ با چند نمونه، جیتر و تایید واقعی کلودفلر")
        k = Card(); self.sni1 = self.spin(k, "SNI", self.cfg.get("sni1", SNIS[0]), SNIS)
        self.n1 = self.fld(k, "تعداد IP برای تست", self.cfg.get("n1", 2000)); self.smp = self.fld(k, "نمونه برای هر IP", 3)
        self.w1 = self.fld(k, "هم‌زمان", 100); self.ver = self.sw(k, "تایید کلودفلر", "ver")
        k.add_widget(WL("رنج‌ها (هر خط یک CIDR):", 12, MUT))
        self.rng = TextInput(text="\n".join(self.cfg.get("ranges", CF)), size_hint_y=None, height=dp(150), font_size=sp(11),
                             background_color=(.14, .19, .29, 1), foreground_color=TXT, cursor_color=TXT)
        k.add_widget(self.rng)
        k.add_widget(self.r(B("شروع اسکن", self.scan, ACC), B("توقف", self.stop.set, RED)))
        k.add_widget(B("بازنشانی رنج‌ها به لیست بزرگ پیش‌فرض", self.reset_ranges, GRY))
        self.prog["scan"] = ProgressBar(max=1, size_hint_y=None, height=dp(10)); k.add_widget(self.prog["scan"]); c.add_widget(k)
        k = Card()
        k.add_widget(self.r(B("اتصال به IP انتخابی", lambda: self.connect_ip(False), GRN, size=12), B("اتصال خودکار (۵ بهترین)", lambda: self.connect_ip(True), GRN, size=12)))
        k.add_widget(self.r(B("افزودن به استخر", self.add_ip), B("کپی IP", lambda: self.copy((self.sel("scan") or {}).get("ip")), GRY)))
        self.table(k, "scan"); c.add_widget(k)

    def page_online(self, c):
        self.head(c, "پروکسی آنلاین", "دریافت لیست‌های عمومی و تست واقعی (تونل، تاخیر، سلامت TLS)")
        k = Card(); self.kind = self.spin(k, "نوع", "SOCKS5", ("SOCKS5", "HTTP"))
        self.n2 = self.fld(k, "تعداد", self.cfg.get("n2", 400)); self.w2 = self.fld(k, "هم‌زمان", 120); self.sec = self.sw(k, "فقط TLS امن", "sec", False)
        k.add_widget(self.r(B("دریافت و تست", self.online), B("توقف", self.stop.set, RED)))
        self.prog["online"] = ProgressBar(max=1, size_hint_y=None, height=dp(10)); k.add_widget(self.prog["online"]); c.add_widget(k)
        k = Card()
        k.add_widget(self.r(B("اتصال (انتخابی)", lambda: self.connect_proxy(False), GRN, size=12), B("اتصال خودکار (۵ بهترین)", lambda: self.connect_proxy(True), GRN, size=12)))
        k.add_widget(self.r(B("افزودن به استخر", self.add_proxy), B("کپی", lambda: self.copy((self.sel("online") or {}).get("addr")), GRY)))
        self.table(k, "online"); c.add_widget(k)

    def page_pool(self, c):
        self.head(c, "استخر اتصال", "هر مورد سالم‌تر و سریع‌تر باشد اولویت دارد؛ موارد خراب موقتاً کنار گذاشته می‌شوند")
        for i, (title, pool) in enumerate((("IPهای کلودفلر (برای Forwarder)", self.ip_pool), ("پروکسی‌های آپ‌استریم (برای SOCKS5)", self.up_pool))):
            k = Card(); k.add_widget(WL(title, 14, bold=True)); t = self.table(k, "pool_%d" % i); self.pool_views.append((t, pool))
            k.add_widget(self.r(B("حذف انتخابی", lambda t=t, pl=pool: self.pool_rm(t, pl), GRY), B("پاک کردن همه", pool.clear, RED))); c.add_widget(k)

    def page_blackout(self, c):
        self.head(c, "قطعی شدید (Hardest Blackout)", "قوی‌ترین روش‌ها برای اتصال وقتی اینترنت کشور به‌طور گسترده مسدود است")
        k = Card()
        k.add_widget(WL(
            "در قطعی گسترده، لیست‌های عمومی پروکسی (GitHub و مشابه) معمولاً خودشان مسدودند؛ چیزی که اغلب باز می‌ماند "
            "IPهای CDNهای بزرگ است (چون سایت‌های داخلی هم روی آن‌ها هستند). این حالت:\n\n"
            "۱) اسکن را از کلودفلر به چند CDN بزرگ دیگر هم گسترش می‌دهد (Google, Microsoft, Amazon, Fastly, Akamai)\n"
            "۲) SNI را بین چند دامنهٔ معتبر روی هر CDN می‌چرخاند (Domain Fronting)\n"
            "۳) پورت‌های جایگزین HTTPS کلودفلر را هم امتحان می‌کند (2053, 2083, 2087, 2096, 8443) برای وقتی 443 محدود شده\n"
            "۴) بستهٔ TLS Hello را بسیار شدیدتر تکه‌تکه می‌کند تا فیلترهای مبتنی بر تطبیق رشتهٔ SNI رد شوند\n"
            "۵) مسیرهای سالم قبلی را روی خود گوشی نگه می‌دارد، پس حتی بدون اینترنت برای گرفتن لیست تازه هم می‌توان دوباره وصل شد\n"
            "۶) امکان اشتراک‌گذاری آفلاین مسیر سالم با دیگران (کپی متن و ارسال با پیامک/بلوتوث/هر روش دیگر)\n\n"
            "اگر کل اینترنت کشور (سیمی و موبایل) قطع باشد، هیچ نرم‌افزاری نمی‌تواند از آن عبور کند؛ در آن حالت فقط راه‌های "
            "فیزیکی کمک می‌کنند: رومینگ با سیم‌کارت/eSIM خارجی، اینترنت ماهواره‌ای (مثل Starlink)، یا رادیو/شبکهٔ محلی.",
            11, MUT))
        c.add_widget(k)

        k = Card()
        self.blk = Switch(active=False, size_hint_x=None, width=dp(90))
        self.blk.bind(active=lambda w, v: self._set_blk(v))
        k.add_widget(self.r(WL("فعال‌سازی حالت قطعی گسترده (اسکن/پورت/فرگمنت شدیدتر)", 13), self.blk))
        k.add_widget(B("آماده‌سازی رنج‌ها و SNIها برای قطعی گسترده", self.prepare_blackout_ranges, ACC))
        k.add_widget(WL("پس از آماده‌سازی به تب «اسکن IP» بروید و اسکن را بزنید؛ بهترین نتایج را به استخر/Forwarder اضافه کنید.", 10, MUT))
        c.add_widget(k)

        k = Card(); k.add_widget(WL("اشتراک‌گذاری آفلاین استخر", 14, bold=True))
        k.add_widget(WL("مسیرهای سالم فعلی را به‌صورت متن کپی کنید و از هر راه آفلاین (پیامک، بلوتوث، شیر فایل) برای دیگران بفرستید؛ "
                        "طرف مقابل همان متن را در کلیپ‌بورد خودش می‌گذارد و «وارد کردن» را می‌زند.", 11, MUT))
        k.add_widget(self.r(B("خروجی گرفتن از استخر (کپی)", self.export_pool, GRN), B("وارد کردن از کلیپ‌بورد", self.import_pool, GRY)))
        c.add_widget(k)

    def page_log(self, c):
        self.head(c, "لاگ", "رویدادهای برنامه")
        self.log_lbl = WL("", 11, MUT, smart=False); self.log_lbl.halign = "left"; c.add_widget(self.log_lbl)

    # ----- hardest blackout -----
    def _set_blk(self, v):
        self.blk_active = bool(v)
        self.log("حالت قطعی گسترده: " + ("فعال" if v else "غیرفعال"))

    def prepare_blackout_ranges(self):
        nets = []
        for lst in CDN_FRONT.values(): nets += lst
        self.rng.text = "\n".join(nets)
        snis = []
        for lst in FRONT_SNIS.values(): snis += [x for x in lst if x not in snis]
        self.sni1.values = snis; self.sni1.text = snis[0]
        if not self.blk.active: self.blk.active = True
        self.log(f"رنج‌های {len(CDN_FRONT)} شبکهٔ CDN ({len(nets)} بلوک) و {len(snis)} دامنهٔ SNI آماده شد")

    def export_pool(self):
        items = [{"t": "ip", "host": e["host"], "port": e["port"], "lat": e["lat"]} for e in self.ip_pool.snapshot()]
        items += [{"t": "up", "kind": e["kind"], "host": e["host"], "port": e["port"], "lat": e["lat"]} for e in self.up_pool.snapshot()]
        if not items: return self.log("استخر خالی است؛ چیزی برای اشتراک‌گذاری نیست")
        try:
            Clipboard.copy("NETFREE1:" + json.dumps(items, ensure_ascii=False))
            self.log(f"{len(items)} مسیر کپی شد؛ برای دیگران ارسال کنید")
        except Exception as e:
            self.log(f"کپی ناموفق: {e}")

    def import_pool(self):
        try: txt = Clipboard.paste()
        except Exception: txt = ""
        if not txt or not txt.startswith("NETFREE1:"): return self.log("چیزی برای وارد کردن در کلیپ‌بورد نیست")
        try: items = json.loads(txt[len("NETFREE1:"):])
        except Exception: return self.log("فرمت کلیپ‌بورد نامعتبر است")
        n = 0
        for it in items:
            try:
                if it.get("t") == "ip": self.ip_pool.add("IP", it["host"], int(it.get("port", 443)), float(it.get("lat", 0))); n += 1
                elif it.get("t") == "up": self.up_pool.add(it.get("kind", "SOCKS5"), it["host"], int(it["port"]), float(it.get("lat", 0))); n += 1
            except Exception: pass
        self.log(f"{n} مسیر از ورودی آفلاین اضافه شد")

    # ----- quick connect -----
    def set_quick(self, st, info=None):
        self.qst = st
        t, col = {"idle": ("اتصال", GRY), "connecting": ("لغو", AMB), "connected": ("قطع", GRN), "failed": ("تلاش مجدد", RED)}[st]
        self.q_btn.text, self.q_btn.bg = fa(t), col
        if st == "connecting": self.q_status.set("در حال اتصال ..."); self.q_status.color = AMB
        elif st == "connected" and info:
            self.q_status.set("متصل - دسترسی یوتیوب تایید شد"); self.q_status.color = GRN
            self.q_info.set(f"IP خروجی: {info['ip']} ({info['loc']})   تاخیر: {info['ms']:.0f} ms")
        elif st == "failed": self.q_status.set(info or "ناموفق"); self.q_status.color = RED; self.q_info.set("")
        elif st == "idle": self.q_status.set("آماده اتصال"); self.q_status.color = TXT; self.q_info.set("")

    def quick_toggle(self):
        if self.qst in ("connecting", "connected"):
            self.quick.cancel(); self.stop_socks()
            if self.vpn.up_flag: self.vpn.stop(); self.q_vpn_status.set("")
            self.set_quick("idle")
        else:
            self.set_quick("connecting"); self.quick.start(self.qlan.active, self.qsec.active)
            if VPNManager.supported() and self.qvpn.active:
                self.q_vpn_status.set("در حال درخواست اجازه VPN ..."); self.q_vpn_status.color = AMB
                try:
                    act = autoclass("org.kivy.android.PythonActivity").mActivity
                    self.vpn.start(act, lambda: self.blk_active, lambda ok: self.q.put(("vpnstate", ok)))
                except Exception as e:
                    self.qlog(f"VPN شروع نشد: {e}")

    def quick_server(self, lan):
        """Called from the worker thread: reuse a running server or start one (waits out a server that is stopping)."""
        for _ in range(40):
            if not (self.srv and self.srv.stopping): break
            time.sleep(0.1)
        if self.srv and self.srv.state == "running" and not self.srv.stopping: return self.srv
        if self.srv: return None
        srv = Socks("0.0.0.0" if lan else "127.0.0.1", self.port_of(self.port, 1080), self.qlog, self.up_pool, True, True)
        self.srv = srv; threading.Thread(target=srv.run, daemon=True).start()
        for _ in range(30):
            if srv.state != "starting": break
            time.sleep(0.1)
        return srv if srv.state == "running" else None

    # ----- table / jobs -----
    def sel(self, key): return self.tbl[key].selected()

    def refresh_tree(self, key):
        rows = sorted(self.data[key], key=lambda r: r["score"])[:600]
        for r in rows: r["color"] = GRN if r["score"] < 300 else AMB if r["score"] < 700 else RED
        self.tbl[key].set_rows(rows)

    def start_job(self, key, jobs, fn, workers):
        self.stop.clear(); self.data[key] = []; self.refresh_tree(key); self.prog[key].value = 0
        self.log(f"تست {len(jobs)} هدف با {workers} رشته ...")

        def wrap(j): return None if self.stop.is_set() else fn(j)

        def go():
            done = 0
            with ThreadPoolExecutor(workers) as ex:
                for f in as_completed([ex.submit(wrap, j) for j in jobs]):
                    done += 1
                    try: r = f.result()
                    except Exception: r = None
                    if r: self.q.put(("row", key, r))
                    if done % 5 == 0 or done == len(jobs): self.q.put(("prog", key, done / len(jobs)))
            self.q.put(("done", key))
        threading.Thread(target=go, daemon=True).start()

    def poll(self, dt=0):
        try:
            while True:
                k, *a = self.q.get_nowait()
                if k == "row": self.data[a[0]].append(a[1]); self.dirty.add(a[0])
                elif k == "call": a[0]()
                elif k == "qstat":
                    if self.qst != "idle": self.q_status.set(a[0])
                elif k == "qstate": self.set_quick(*a)
                elif k == "vpnstate":
                    ok = a[0]
                    self.q_vpn_status.set("VPN سیستمی: فعال (آیکون کلید)" if ok else "VPN سیستمی فعال نشد؛ فقط پروکسی محلی")
                    self.q_vpn_status.color = GRN if ok else RED
                elif k == "prog": self.prog[a[0]].value = a[1]
                elif k == "done":
                    self.dirty.add(a[0]); self.prog[a[0]].value = 1
                    self.log(f"پایان: {len(self.data[a[0]])} مورد سالم" + (" (متوقف شد)" if self.stop.is_set() else ""))
                else: self.log(a[0])
        except queue.Empty:
            pass
        for k in list(self.dirty): self.refresh_tree(k)
        self.dirty.clear()

    # ----- scan / online -----
    def reset_ranges(self): self.rng.text = "\n".join(CF); self.log(f"رنج‌ها بازنشانی شد ({len(CF)} بلوک)")

    def scan(self):
        try: n, smp, w = int(self.n1.text), max(1, int(self.smp.text)), max(1, int(self.w1.text))
        except ValueError: return self.log("مقادیر عددی نامعتبر است")
        nets = []
        for l in self.rng.text.splitlines():
            l = l.split("#")[0].strip()
            if not l: continue
            try: nets.append(ipaddress.ip_network(l, strict=False))
            except ValueError: self.log(f"رنج نامعتبر: {l}")
        nets = merge_nets(nets)
        if not nets: return self.log("رنج معتبری وارد نشده")
        out = sample_ips(nets, n)
        self.log(f"{len(nets)} رنج، {sum(x.num_addresses for x in nets):,} آدرس؛ نمونه‌برداری {len(out)} IP")
        sni, ver = self.sni1.text, self.ver.active
        ports = tuple(ALT_PORTS) if getattr(self, "blk_active", False) else (443,)

        def fn(ip):
            r = probe_ip(ip, sni, smp, ver, ports)
            if r: return {"key": ip, "ip": ip, "port": r["port"], "lat": r["tls"], "score": r["score"], "title": ip,
                          "sub": f"پورت {r['port']} | TLS {r['tls']:.0f} | TCP {r['tcp']:.0f} | jit {r['jit']:.0f} | {r['ok']} | score {r['score']:.0f}"}
        self.start_job("scan", out, fn, w)

    def online(self):
        k = self.kind.text
        try: n, w = int(self.n2.text), max(1, int(self.w2.text))
        except ValueError: return self.log("مقادیر عددی نامعتبر است")
        only = self.sec.active
        self.log("دریافت لیست پروکسی‌ها ...")

        def go():
            jobs = fetch_proxies(k, n, self.qlog)
            if not jobs: self.q.put(("log", "لیستی دریافت نشد؛ اینترنت/دسترسی به GitHub را بررسی کنید")); return
            self.q.put(("call", lambda: self.start_job("online", jobs, fn, w)))

        def fn(hp):
            r = proxy_probe(k, *hp)
            if not r or (only and not r["secure"]): return None
            return {"key": r["addr"], "kind": k, "addr": r["addr"], "host": r["host"], "port": r["port"], "lat": r["lat"], "score": r["score"],
                    "title": f"{k}  {r['addr']}", "sub": f"ping {r['lat']:.0f} | TLS {'ok' if r['secure'] else 'x'} | jit {r['jit']:.0f} | score {r['score']:.0f}"}
        threading.Thread(target=go, daemon=True).start()

    # ----- connect actions -----
    def top(self, key, n=5): return sorted(self.data[key], key=lambda r: r["score"])[:n]

    def connect_ip(self, auto):
        rows = [r for r in (self.top("scan") if auto else [self.sel("scan")]) if r]
        if not rows: return self.log("ابتدا اسکن کنید و یک IP انتخاب کنید")
        self.ip_pool.clear()
        for r in rows: self.ip_pool.add("IP", r["ip"], r.get("port", 443), r["lat"])
        self.log(f"{len(rows)} IP در استخر قرار گرفت"); self.start_fwd(); self.show("dash")

    def add_ip(self):
        r = self.sel("scan")
        if r: self.ip_pool.add("IP", r["ip"], r.get("port", 443), r["lat"]); self.log(f"{r['ip']} به استخر IP اضافه شد")

    def connect_proxy(self, auto):
        rows = [r for r in (self.top("online") if auto else [self.sel("online")]) if r]
        if not rows: return self.log("ابتدا تست کنید و یک پروکسی انتخاب کنید")
        self.up_pool.clear()
        for r in rows: self.up_pool.add(r["kind"], r["host"], r["port"], r["lat"])
        self.log(f"{len(rows)} پروکسی آپ‌استریم تنظیم شد"); self.start_socks(); self.show("dash")

    def add_proxy(self):
        r = self.sel("online")
        if r: self.up_pool.add(r["kind"], r["host"], r["port"], r["lat"]); self.log(f"{r['addr']} به استخر آپ‌استریم اضافه شد")

    def pool_rm(self, t, pool):
        r = t.selected()
        if r: pool.remove(r["ent"]); t.sel_key = None

    # ----- servers -----
    def port_of(self, e, d):
        try: return int(e.text)
        except ValueError: return d

    def toggle_socks(self): self.stop_socks() if self.srv else self.start_socks()

    def start_socks(self):
        if self.srv: return
        host = "0.0.0.0" if self.lan.active else "127.0.0.1"
        self.srv = Socks(host, self.port_of(self.port, 1080), self.qlog, self.up_pool, self.frag.active, self.doh.active)
        threading.Thread(target=self.srv.run, daemon=True).start()

    def stop_socks(self):
        if self.srv: self.srv.stop()

    def toggle_fwd(self): self.stop_fwd() if self.fwd else self.start_fwd()

    def start_fwd(self):
        if self.fwd: return
        if not len(self.ip_pool): return self.log("استخر IP خالی است؛ ابتدا از تب اسکن IP اضافه کنید")
        host = "0.0.0.0" if self.flan.active else "127.0.0.1"
        self.fwd = Forwarder(host, self.port_of(self.fport, 10443), self.qlog, self.ip_pool, self.ffrag.active, self.fsni.text)
        threading.Thread(target=self.fwd.run, daemon=True).start()

    def stop_fwd(self):
        if self.fwd: self.fwd.stop()

    def test_socks(self):
        if not self.srv or self.srv.state != "running": return self.log("ابتدا سرور SOCKS5 را روشن کنید")
        port = self.srv.port; self.log("در حال تست اتصال از مسیر سرور ...")
        threading.Thread(target=lambda: self.q.put(("log", (lambda m: f"تست موفق: {m:.0f} ms" if m else "تست ناموفق (آپ‌استریم یا شبکه مشکل دارد)")(proxy_ping("SOCKS5", "127.0.0.1", port, 15)))), daemon=True).start()

    def awake(self, on):
        """Keep the CPU alive while a server runs (needs WAKE_LOCK permission)."""
        if platform != "android": return
        try:
            if on and not self.wl:
                from jnius import autoclass
                act = autoclass("org.kivy.android.PythonActivity").mActivity
                self.wl = act.getSystemService(autoclass("android.content.Context").POWER_SERVICE).newWakeLock(1, "netfree:srv"); self.wl.acquire()
            elif not on and self.wl: self.wl.release(); self.wl = None
        except Exception:
            pass

    # ----- periodic UI refresh -----
    def tick(self, dt=0):
        now = time.time()
        if self.srv and self.srv.state == "stopped": self.srv = None
        if self.fwd and self.fwd.state == "stopped": self.fwd = None
        if self.srv: self.srv.frag, self.srv.doh, self.srv.extreme = self.frag.active, self.doh.active, self.blk_active
        if self.fwd: self.fwd.frag, self.fwd.sni, self.fwd.extreme = self.ffrag.active, self.fsni.text, self.blk_active
        if now - self._lan_t > 30: self._lan, self._lan_t = lan_ip(), now
        self.awake(bool(self.srv or self.fwd))

        run = lambda x: bool(x) and x.state == "running"
        for lbl, name, x in ((self.s_socks, "SOCKS5", self.srv), (self.s_fwd, "Forwarder", self.fwd)):
            lbl.set(f"{name}: {'روشن' if run(x) else 'خاموش'}"); lbl.color = GRN if run(x) else MUT
        self.b_socks.text, self.b_socks.bg = fa("خاموش کردن" if self.srv else "روشن کردن سرور"), RED if self.srv else ACC
        self.b_fwd.text, self.b_fwd.bg = fa("خاموش کردن" if self.fwd else "روشن کردن فوروارد"), RED if self.fwd else ACC
        self.addr.set(f"socks5://{self._lan if self.srv.host == '0.0.0.0' else '127.0.0.1'}:{self.srv.port}" if self.srv else "")
        self.faddr.set(f"{self._lan if self.fwd.host == '0.0.0.0' else '127.0.0.1'}:{self.fwd.port}" if self.fwd else "")
        self.lbl_up.set(f"آپ‌استریم: {len(self.up_pool)} پروکسی (با failover خودکار)" if len(self.up_pool) else "آپ‌استریم: مستقیم (بدون پروکسی)")
        self.lbl_ip.set(f"استخر: {len(self.ip_pool)} IP" + (" - بهترین: " + self.ip_pool.ordered()[0]["host"] if len(self.ip_pool) else ""))

        srvs = [x for x in (self.srv, self.fwd) if x]
        up, dn = sum(x.stats.up for x in srvs), sum(x.stats.down for x in srvs)
        pu, pd, pt = self.prev; dt = max(0.05, now - pt)
        self.v_speed.set(f"Down {fmt(max(0, dn - pd) / dt)}/s    Up {fmt(max(0, up - pu) / dt)}/s"); self.prev = (up, dn, now)
        self.v_conn.set(f"{sum(x.stats.active for x in srvs)} فعال | {sum(x.stats.conns for x in srvs)} کل | {sum(x.stats.fail for x in srvs)} خطا")
        on = any(run(x) for x in srvs)
        self.v_state.set("متصل" if on else "خاموش"); self.v_state.color = GRN if on else MUT
        self.q_speed.set(self.v_speed.raw); self.q_addr.set(self.addr.raw)

        if self.cur == "pool" and now - self._pt > 1.5:
            self._pt = now
            for t, pool in self.pool_views:
                rows = []
                for e in pool.snapshot():
                    cd = e["until"] - now
                    st = "سالم" if e["fails"] == 0 else (f"استراحت {cd:.0f}s" if cd > 0 else "ناپایدار")
                    ad = f"{e['host']}:{e['port']}"
                    rows.append({"key": ad, "title": ad, "ent": e, "score": 0, "color": GRN if e["fails"] == 0 else AMB if cd <= 0 else RED,
                                 "sub": f"{e['kind']} | ping {(format(e['lat'], '.0f') if e['lat'] else '-')} | err {e['fails']} | {st}"})
                t.set_rows(rows)

    def on_key(self, win, key, *a):
        """Back button = send to background (keeps the proxy running) instead of killing the app."""
        if key == 27:
            try:
                from jnius import autoclass
                autoclass("org.kivy.android.PythonActivity").mActivity.moveTaskToBack(True); return True
            except Exception:
                return False
        return False

    def close(self):
        self.cfg.update(port=self.port.text, lan=self.lan.active, frag=self.frag.active, doh=self.doh.active, fport=self.fport.text,
                        flan=self.flan.active, ffrag=self.ffrag.active, fsni=self.fsni.text, sni1=self.sni1.text, n1=self.n1.text,
                        n2=self.n2.text, ver=self.ver.active, sec=self.sec.active,
                        ranges=[l for l in self.rng.text.splitlines() if l.strip()],
                        ip_pool=[[e["host"], e["port"], e["lat"]] for e in self.ip_pool.snapshot()],
                        up_pool=[[e["kind"], e["host"], e["port"], e["lat"]] for e in self.up_pool.snapshot()],
                        qlan=self.qlan.active, qsec=self.qsec.active)
        save_cfg(self.cfg); self.quick.cancel()
        for x in (self.srv, self.fwd):
            try: x and x.stop()
            except Exception: pass
        try: self.vpn.stop()
        except Exception: pass
        self.awake(False)


class NetFreeApp(App):
    title = "NetFree"

    def build(self):
        global APP_DIR, CFG
        APP_DIR = self.user_data_dir; CFG = os.path.join(APP_DIR, "config.json")
        setup_font(); Window.clearcolor = BG; Window.softinput_mode = "below_target"
        self.ui = UI(); Window.bind(on_keyboard=self.ui.on_key); return self.ui

    def on_pause(self): return True  # keep servers alive in background

    def on_stop(self): self.ui.close()


if __name__ == "__main__":
    NetFreeApp().run()
