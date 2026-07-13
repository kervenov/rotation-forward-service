#!/usr/bin/env python3
"""Rotation forward-service agent — one tiny, crash-proof daemon (stdlib only).

Two jobs in one process:

1. CONTROL LISTENER (always on, ~0 CPU/RAM when idle): a minimal HTTP server
   on CONTROL_PORT that the PANEL calls to turn traffic reporting on/off:
       POST /control {"command": "activate"}    -> start reporting
       POST /control {"command": "deactivate"}  -> stop reporting
   Accepted ONLY from the panel's IP (resolved from PANEL_URL). No token, no
   operator input. Forwarding (iptables DNAT/FORWARD) is NEVER touched here —
   "deactivate" only stops the reporting loop; the box keeps forwarding.

2. TRAFFIC REPORTER (gated by the active flag): while ACTIVE, every INTERVAL
   seconds it reads conntrack, finds the client IPs that actually moved bytes
   since the last poll, and POSTs them to the panel. While STANDBY it does
   nothing — a reserved server sits idle until the panel activates it. This is
   why reserved boxes burn no CPU/RAM.

The role (active/standby) is persisted to STATE_FILE, so a restart resumes the
last role and a lost/queued activate isn't forgotten across a crash. Every
loop body is wrapped so a transient error can never kill the process (which,
combined with systemd StartLimitIntervalSec=0, is what makes it universal —
no more "start request repeated too quickly" self-stop).
"""
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PANEL_URL = os.environ.get("PANEL_URL", "")            # .../api/auto-rotation/traffic
CONTROL_PORT = int(os.environ.get("CONTROL_PORT", "8765"))
INTERVAL = int(os.environ.get("INTERVAL", "60"))       # seconds between reports (active)
STATE_FILE = os.environ.get("STATE_FILE", "/var/lib/rotation-agent/state")
PANEL_IP_ENV = os.environ.get("PANEL_IP", "")          # optional extra allowed IP(s), comma-sep
CONNTRACK = "/proc/net/nf_conntrack"

SERVER_IP = ""

# active_event set  -> reporter should POST every INTERVAL
# standby_signal is pulsed on deactivate to break the interval sleep at once
active_event = threading.Event()
standby_signal = threading.Event()

# Cached panel-IP allowlist so a flood of control requests can't force a DNS
# lookup per request (and so a transient DNS blip keeps the last-good set).
PANEL_IP_TTL = 60
_panel_ip_lock = threading.Lock()
_panel_ip_cache = {"ips": set(), "ts": -1e9}


def log(*a):
    print(*a, file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# Role state (persisted so a restart resumes where we were)
# ---------------------------------------------------------------------------
def persist_state(active):
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with open(STATE_FILE, "w") as f:
            f.write("active" if active else "standby")
    except Exception as e:
        log("state persist failed:", e)


def load_state():
    try:
        with open(STATE_FILE) as f:
            return f.read().strip() == "active"
    except Exception:
        return False


def set_active(active):
    if active:
        standby_signal.clear()
        active_event.set()
    else:
        active_event.clear()
        standby_signal.set()   # wake the sleeping reporter so it stops now
    persist_state(active)


# ---------------------------------------------------------------------------
# IP helpers
# ---------------------------------------------------------------------------
def detect_ip(retries=20, delay=3):
    """Public egress IP; retried so a not-yet-ready network at boot doesn't
    leave SERVER_IP empty (which would break the forwarded-flow filter)."""
    for _ in range(retries):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("1.1.1.1", 80))
            ip = s.getsockname()[0]
            s.close()
            if ip:
                return ip
        except Exception:
            pass
        time.sleep(delay)
    return ""


def is_public_v4(ip):
    o = ip.split(".")
    if len(o) != 4:
        return False
    try:
        a, b = int(o[0]), int(o[1])
    except ValueError:
        return False
    if a in (10, 127, 0) or a >= 224:
        return False
    if a == 192 and b == 168:
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 169 and b == 254:
        return False
    if a == 100 and 64 <= b <= 127:   # CGNAT
        return False
    return True


def is_public(ip):
    if ":" in ip:
        return not (ip == "::1" or ip.lower().startswith("fe80"))
    return is_public_v4(ip)


def _panel_host():
    try:
        return urllib.parse.urlparse(PANEL_URL).hostname or ""
    except Exception:
        return ""


def panel_allowed_ips():
    """The set of IPs allowed to send control commands: the panel host's DNS
    resolution + any PANEL_IP override. Cached for PANEL_IP_TTL seconds so a
    burst of requests can't force a DNS lookup each time; a transient resolve
    failure falls back to the last-good set (never widens access). No token,
    no operator input."""
    now = time.monotonic()
    with _panel_ip_lock:
        cached = _panel_ip_cache["ips"]
        if cached and (now - _panel_ip_cache["ts"]) < PANEL_IP_TTL:
            return cached

    allowed = set()
    for extra in PANEL_IP_ENV.replace(",", " ").split():
        extra = extra.strip()
        if extra:
            allowed.add(extra)
    host = _panel_host()
    if host:
        try:
            for res in socket.getaddrinfo(host, None):
                allowed.add(res[4][0])
        except Exception as e:
            log("panel DNS resolve failed for %s: %s" % (host, e))

    if allowed:
        with _panel_ip_lock:
            _panel_ip_cache["ips"] = allowed
            _panel_ip_cache["ts"] = now
        return allowed
    # Resolve failed and no static override — keep trusting the last-good set.
    return cached


# ---------------------------------------------------------------------------
# conntrack — count ONLY forwarded (DNAT'd) VPN flows, active-by-byte-delta
# ---------------------------------------------------------------------------
def _conntrack_lines():
    """Yield conntrack table lines. Prefer /proc/net/nf_conntrack (lightest);
    on kernels with CONFIG_NF_CONNTRACK_PROCFS disabled that file is absent,
    so stream `conntrack -L` (conntrack-tools) line by line — streaming keeps
    memory flat even when the table has hundreds of thousands of flows."""
    try:
        with open(CONNTRACK, "r") as f:
            for line in f:
                yield line
        return
    except FileNotFoundError:
        pass
    p = None
    try:
        p = subprocess.Popen(
            ["conntrack", "-L"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
        for raw in p.stdout:
            yield raw.decode("utf-8", "replace")
    except FileNotFoundError:
        log("conntrack command missing — install conntrack-tools "
            "(apt install -y conntrack)")
    except Exception as e:
        log("conntrack -L failed:", e)
    finally:
        if p is not None:
            try:
                p.stdout.close()
            except Exception:
                pass
            try:
                p.wait(timeout=5)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass


def read_conntrack():
    """Return (totals{client_ip: bytes}, acct_seen), counting ONLY forwarded
    (DNAT'd) flows: those where neither conntrack src= is this server. The
    client is the FIRST src (original tuple source)."""
    totals = {}
    acct_seen = False
    for line in _conntrack_lines():
        srcs = []
        tot = 0
        for p in line.split():
            if p.startswith("src="):
                srcs.append(p[4:])
            elif p.startswith("bytes="):
                acct_seen = True
                try:
                    tot += int(p[6:])
                except ValueError:
                    pass
        if len(srcs) < 2:
            continue
        orig_src, reply_src = srcs[0], srcs[1]
        # Forwarded iff NEITHER endpoint is this server:
        #  - SSH into box:     reply_src == SERVER_IP  (terminates here)
        #  - reporter/DNS out: orig_src == SERVER_IP   (originates here)
        #  - VPN client:       orig_src=client, reply_src=node  (both != us)
        if orig_src == SERVER_IP or reply_src == SERVER_IP:
            continue
        if not is_public(orig_src):
            continue
        totals[orig_src] = totals.get(orig_src, 0) + tot
    return totals, acct_seen


def post(active_ips):
    body = json.dumps({
        "server_ip": SERVER_IP,
        "warming_up": False,
        "active_connections": len(active_ips),
        "active_ips": active_ips,
    }).encode()
    # Retry once with a generous timeout — the path to the panel occasionally
    # drops a TLS-handshake packet, so a single retry recovers most transient
    # "handshake timed out" failures.
    last = None
    for attempt in (1, 2):
        try:
            req = urllib.request.Request(
                PANEL_URL, data=body, method="POST",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=20) as r:
                r.read()
            return True
        except Exception as e:
            last = e
            if attempt == 1:
                time.sleep(1)
    log("POST failed (2 tries):", last)
    return False


# ---------------------------------------------------------------------------
# Reporter loop — only runs while ACTIVE; near-zero cost while STANDBY
# ---------------------------------------------------------------------------
def reporter_loop():
    while True:
        try:
            active_event.wait()          # STANDBY: blocks, ~0 CPU, until activated
            standby_signal.clear()
            prev = None
            log("ACTIVE — reporting active client IPs every %ds" % INTERVAL)
            while active_event.is_set():
                try:
                    cur, acct = read_conntrack()
                    if not acct:
                        log("nf_conntrack_acct OFF (no bytes=) — enable: "
                            "sysctl -w net.netfilter.nf_conntrack_acct=1")
                    elif prev is None:
                        # first tick after activation: establish the byte
                        # baseline, don't POST yet (no delta to compare).
                        log("baseline established — first report in %ds" % INTERVAL)
                    else:
                        active = []
                        for ip, b in cur.items():
                            pb = prev.get(ip)
                            if (pb is None and b > 0) or (pb is not None and b > pb):
                                active.append(ip)
                        active = sorted(set(active))
                        ok = post(active)
                        log("POST -> %d active client IP(s)%s"
                            % (len(active), "" if ok else " [FAILED]"))
                    if acct:
                        prev = cur
                except Exception as e:
                    log("reporter tick error (continuing):", e)
                # Sleep INTERVAL, but wake immediately if deactivated.
                if standby_signal.wait(INTERVAL):
                    break
            log("STANDBY — traffic reports stopped (forwarding untouched)")
        except Exception as e:
            log("reporter loop error (restarting loop):", e)
            time.sleep(2)


# ---------------------------------------------------------------------------
# Control HTTP listener — activate / deactivate from the panel only
# ---------------------------------------------------------------------------
class ControlHandler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def do_GET(self):
        # Health/debug. It exposes server_ip + panel_ips, so restrict it to
        # localhost (the install prints a 127.0.0.1 curl) and the panel — an
        # internet scanner hitting :8765 must not map the infrastructure.
        if self.path.rstrip("/") in ("/health", "/status", ""):
            peer = self.client_address[0]
            if peer not in ("127.0.0.1", "::1") and peer not in panel_allowed_ips():
                return self._send(403, {"detail": "forbidden", "peer": peer})
            return self._send(200, {
                "server_ip": SERVER_IP,
                "active": active_event.is_set(),
                "interval": INTERVAL,
                "control_port": CONTROL_PORT,
                "panel_ips": sorted(panel_allowed_ips()),
            })
        return self._send(404, {"detail": "not found"})

    def do_POST(self):
        if self.path.rstrip("/") != "/control":
            return self._send(404, {"detail": "not found"})
        peer = self.client_address[0]
        if peer not in panel_allowed_ips():
            log("control REJECTED from %s (not the panel)" % peer)
            return self._send(403, {"detail": "forbidden", "peer": peer})
        try:
            length = int(self.headers.get("Content-Length", "0") or 0)
            raw = self.rfile.read(length) if length else b""
            cmd = json.loads(raw or b"{}").get("command", "")
        except Exception:
            cmd = ""
        if cmd == "activate":
            set_active(True)
            log("control: ACTIVATE from %s" % peer)
            return self._send(200, {"detail": "activated", "server_ip": SERVER_IP})
        if cmd == "deactivate":
            set_active(False)
            log("control: DEACTIVATE from %s" % peer)
            return self._send(200, {"detail": "deactivated", "server_ip": SERVER_IP})
        return self._send(400, {"detail": "unknown command", "command": cmd})

    def log_message(self, *a):   # silence stderr access-log spam
        pass


def main():
    global SERVER_IP
    SERVER_IP = os.environ.get("SERVER_IP") or detect_ip()
    if not SERVER_IP:
        log("could not detect server IP — exiting so systemd restarts us")
        sys.exit(1)
    log("agent start: server_ip=%s panel=%s control_port=%d interval=%ds"
        % (SERVER_IP, PANEL_URL, CONTROL_PORT, INTERVAL))

    # Resume the last role across restarts.
    if load_state():
        active_event.set()
        log("resumed role: ACTIVE")
    else:
        log("resumed role: STANDBY (waiting for panel activate)")

    threading.Thread(target=reporter_loop, daemon=True).start()

    while True:
        try:
            srv = ThreadingHTTPServer(("0.0.0.0", CONTROL_PORT), ControlHandler)
            log("control listener on 0.0.0.0:%d (accepts only panel IPs)"
                % CONTROL_PORT)
            srv.serve_forever()
        except Exception as e:
            log("control listener error (restarting in 3s):", e)
            time.sleep(3)


if __name__ == "__main__":
    main()
