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
import http.client
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PANEL_URL = os.environ.get("PANEL_URL", "")            # .../api/auto-rotation/traffic
CONTROL_PORT = int(os.environ.get("CONTROL_PORT", "8765"))
INTERVAL = int(os.environ.get("INTERVAL", "10"))       # seconds between POSTs to the panel
# Sampling is DECOUPLED from reporting: conntrack is read every SAMPLE seconds
# so the byte-delta stays fine-grained (a blocked flow freezes and is detected
# within ~SAMPLE). An IP counts as active if it transferred within the last
# ACTIVE_WINDOW seconds; we POST that set every INTERVAL. Keeping SAMPLE small
# is what keeps the count honest — a coarse delta would wrongly count a flow
# that grew EARLIER in the window (before a mid-window block) as still active.
SAMPLE = int(os.environ.get("SAMPLE_INTERVAL", "10"))  # conntrack sampling seconds
ACTIVE_WINDOW = int(os.environ.get("ACTIVE_WINDOW", "20"))  # "active" freshness seconds
STATE_FILE = os.environ.get("STATE_FILE", "/var/lib/rotation-agent/state")
PANEL_IP_ENV = os.environ.get("PANEL_IP", "")          # optional extra allowed IP(s), comma-sep
CONNTRACK = "/proc/net/nf_conntrack"

SERVER_IP = ""

# The IP the panel last ACTIVATED this box for — learned from the LOCAL address
# of the activate control connection. One physical box may host many public IPs
# (the operator rotates among IPs on the SAME server), so reports are sent FROM
# this IP (source-bound) and labelled with it; that keeps the panel's
# "peer == current entry IP" auth valid even when the box's default egress IP
# differs from the current IP.
_active_lock = threading.Lock()
active_ip = ""

# All public IPs bound on THIS box (hostname -I) — used to exclude the box's OWN
# flows (SSH, DNS, the agent's own POST) from the client count. A single
# SERVER_IP is not enough on a multi-IP box: a flow to a SECONDARY local IP
# would otherwise be miscounted as a client. Reassigned wholesale (never mutated
# in place) so the reporter thread can read it lock-free.
LOCAL_IPS = set()

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
def persist_state(active, ip=""):
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with open(STATE_FILE, "w") as f:
            f.write(("active %s" % ip).strip() if active else "standby")
    except Exception as e:
        log("state persist failed:", e)


def load_state():
    """Return (is_active, active_ip). active_ip is '' for legacy/standby."""
    try:
        with open(STATE_FILE) as f:
            parts = f.read().strip().split()
        if parts and parts[0] == "active":
            return True, (parts[1] if len(parts) > 1 else "")
        return False, ""
    except Exception:
        return False, ""


def set_active_ip(ip):
    global active_ip
    with _active_lock:
        active_ip = ip or ""


def get_active_ip():
    with _active_lock:
        return active_ip


def _apply_events(active):
    if active:
        standby_signal.clear()
        active_event.set()
    else:
        active_event.clear()
        standby_signal.set()   # wake the sleeping reporter so it stops now


def activate_as(local_ip):
    """Atomically go ACTIVE serving ``local_ip``. Returns the served IP. The
    read+decide+mutate is under one lock so a concurrent deactivate for the OLD
    IP (a rotate hits the same agent) can't clobber this activation."""
    global active_ip
    with _active_lock:
        active_ip = local_ip or SERVER_IP
        _apply_events(True)
        ip = active_ip
    persist_state(True, ip)   # file IO outside the lock
    return ip


def deactivate_for(local_ip):
    """Atomically stop reporting IFF ``local_ip`` is the IP we're currently
    active as (or we track none). Returns True if we deactivated, False if the
    request was for a different (old) IP and so ignored. The whole check+mutate
    is under one lock so it can't race an activate for the NEW IP."""
    global active_ip
    with _active_lock:
        cur = active_ip
        if cur and local_ip and local_ip != cur:
            return False          # not the active IP — ignore, no mutation
        active_ip = ""
        _apply_events(False)
    persist_state(False, "")
    return True


def gather_local_ips():
    """Every IPv4/IPv6 address configured on this box (`hostname -I`) plus the
    detected egress IP. Cheap; called at startup and each time the reporter
    goes ACTIVE so a freshly-added IP is recognised as local."""
    ips = set()
    try:
        out = subprocess.run(
            ["hostname", "-I"], stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=5,
        )
        for tok in out.stdout.decode("utf-8", "replace").split():
            tok = tok.strip()
            if tok:
                ips.add(tok)
    except Exception as e:
        log("hostname -I failed (%s) — excluding detected egress only" % e)
    if SERVER_IP:
        ips.add(SERVER_IP)
    return ips


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


def read_conntrack(entry_ip=""):
    """Return (totals{client_ip: bytes}, acct_seen), counting ONLY forwarded
    (DNAT'd) flows that dialed the CURRENT entry IP.

    The client is the FIRST src (original tuple source) and the entry IP is the
    FIRST dst (original tuple destination — the box IP the client actually
    dialed, pre-DNAT). Filtering by ``entry_ip`` is ESSENTIAL on a box that
    hosts many public IPs: the DNAT rules are per-PORT (``--dport 443``), so the
    VPN is forwarded on EVERY box IP. Without this filter, clients still flowing
    on OTHER entry IPs make a blocked current IP look alive (TM=yes forever ->
    no rotation). With it, a blocked entry IP correctly reads ZERO."""
    totals = {}
    acct_seen = False
    for line in _conntrack_lines():
        srcs = []
        dsts = []
        tot = 0
        for p in line.split():
            if p.startswith("src="):
                srcs.append(p[4:])
            elif p.startswith("dst="):
                dsts.append(p[4:])
            elif p.startswith("bytes="):
                acct_seen = True
                try:
                    tot += int(p[6:])
                except ValueError:
                    pass
        if len(srcs) < 2:
            continue
        orig_src, reply_src = srcs[0], srcs[1]
        orig_dst = dsts[0] if dsts else ""
        # Only clients that dialed the CURRENT entry IP (original dst). A box
        # hosting many entry IPs forwards the VPN on ALL of them (per-port DNAT),
        # so a blocked entry IP must not look alive because OTHER entry IPs still
        # carry clients.
        if entry_ip and orig_dst and orig_dst != entry_ip:
            continue
        # Forwarded iff NEITHER endpoint is one of THIS box's local IPs:
        #  - SSH into any box IP:  reply_src in LOCAL_IPS  (terminates here)
        #  - reporter/DNS out:     orig_src in LOCAL_IPS   (originates here)
        #  - VPN client:           orig_src=client, reply_src=node  (both remote)
        # LOCAL_IPS (not a single SERVER_IP) so a multi-IP box doesn't count its
        # own secondary-IP traffic as clients.
        if orig_src in LOCAL_IPS or reply_src in LOCAL_IPS:
            continue
        if not is_public(orig_src):
            continue
        totals[orig_src] = totals.get(orig_src, 0) + tot
    return totals, acct_seen


def post(active_ips, source_ip=""):
    """POST the report to the panel, source-bound to ``source_ip`` (the current
    entry IP) when given, so the panel sees this box's report arriving FROM the
    current IP — its "peer == current entry IP" auth then holds even on a box
    that hosts many IPs. ``server_ip`` in the body is labelled with the same IP.

    If binding fails (e.g. the IP isn't actually local) the retry falls back to
    the default egress so a report is still attempted (it may be ignored by the
    panel, but a loud POST-failure is worse)."""
    body = json.dumps({
        "server_ip": source_ip or SERVER_IP,
        "warming_up": False,
        "active_connections": len(active_ips),
        "active_ips": active_ips,
    }).encode()
    u = urllib.parse.urlparse(PANEL_URL)
    is_https = (u.scheme == "https")
    port = u.port or (443 if is_https else 80)
    path = u.path or "/"
    src = source_ip
    last = None
    # attempt 1: source-bound; attempt 2: transient retry (drop the binding so a
    # bad/non-local source can't wedge the report entirely).
    for attempt in (1, 2):
        conn = None
        try:
            kwargs = {"timeout": 20}
            if src:
                kwargs["source_address"] = (src, 0)
            if is_https:
                kwargs["context"] = ssl.create_default_context()
                conn = http.client.HTTPSConnection(u.hostname, port, **kwargs)
            else:
                conn = http.client.HTTPConnection(u.hostname, port, **kwargs)
            conn.request("POST", path, body=body,
                         headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            data = resp.read()
            if not (200 <= resp.status < 300):
                # Not a transport failure but the panel refused it — surface it.
                log("POST rejected: HTTP %d (as %s)" % (resp.status, src or SERVER_IP))
                return False
            # Panel returns 200 with detail:"ignored" when the report's source
            # IP isn't the current entry (e.g. binding didn't take) — log it so
            # a silent auth mismatch is visible in the journal.
            try:
                detail = json.loads(data or b"{}").get("detail", "")
            except Exception:
                detail = ""
            if detail and detail != "ok":
                log("POST ignored by panel: %s (as %s)" % (detail, src or SERVER_IP))
                return False
            return True
        except Exception as e:
            last = e
            if attempt == 1:
                if src:
                    log("POST bind to %s failed (%s) — retrying unbound" % (src, e))
                    src = ""          # fall back to default egress
                else:
                    time.sleep(1)
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
    log("POST failed (2 tries):", last)
    return False


# ---------------------------------------------------------------------------
# Reporter loop — only runs while ACTIVE; near-zero cost while STANDBY
# ---------------------------------------------------------------------------
def reporter_loop():
    global LOCAL_IPS
    while True:
        try:
            active_event.wait()          # STANDBY: blocks, ~0 CPU, until activated
            standby_signal.clear()
            LOCAL_IPS = gather_local_ips()   # refresh in case IPs changed
            prev = None
            # client_ip -> monotonic time it was last seen TRANSFERRING (byte
            # counter grew over a SHORT SAMPLE window). This is the freshness
            # ledger; an IP is reported active only while it stays inside
            # ACTIVE_WINDOW, so a blocked flow (frozen bytes) ages out fast.
            last_seen = {}
            cur_entry = get_active_ip()   # the entry IP we count/report for
            last_post = time.monotonic()
            log("ACTIVE as %s — sampling conntrack every %ds, active-window %ds, "
                "reporting every %ds" % (cur_entry or SERVER_IP, SAMPLE,
                                         ACTIVE_WINDOW, INTERVAL))
            while active_event.is_set():
                try:
                    now = time.monotonic()
                    entry = get_active_ip()
                    if entry != cur_entry:
                        # Re-activated for a DIFFERENT entry IP (rotate landed on
                        # this same multi-IP box) — reset the delta baseline so
                        # we don't mix two entry IPs' flow sets.
                        cur_entry = entry
                        prev = None
                        last_seen = {}
                        log("entry IP changed -> %s (baseline reset)"
                            % (entry or SERVER_IP))
                    # Count ONLY flows that dialed the current entry IP.
                    cur, acct = read_conntrack(entry)
                    if not acct:
                        log("nf_conntrack_acct OFF (no bytes=) — enable: "
                            "sysctl -w net.netfilter.nf_conntrack_acct=1")
                    elif prev is None:
                        # first sample: establish the byte baseline (no delta
                        # to compare yet).
                        log("baseline established")
                    else:
                        # Fine-grained delta over the LAST SAMPLE only — a flow
                        # that froze (blocked) shows no growth here even if it
                        # grew earlier, so it stops refreshing last_seen.
                        for ip, b in cur.items():
                            pb = prev.get(ip)
                            if (pb is None and b > 0) or (pb is not None and b > pb):
                                last_seen[ip] = now
                    if acct:
                        prev = cur
                    # Age out anyone not seen transferring within ACTIVE_WINDOW.
                    last_seen = {ip: t for ip, t in last_seen.items()
                                 if now - t <= ACTIVE_WINDOW}
                    # POST the recently-active set on the report cadence.
                    if now - last_post >= INTERVAL:
                        active = sorted(last_seen.keys())
                        ok = post(active, entry)
                        log("POST(as %s) -> %d active client IP(s)%s"
                            % (entry or SERVER_IP, len(active),
                               "" if ok else " [FAILED]"))
                        last_post = now
                except Exception as e:
                    log("reporter tick error (continuing):", e)
                # Sleep the SHORT sampling interval, wake at once if deactivated.
                if standby_signal.wait(SAMPLE):
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
                "active_ip": get_active_ip(),
                "active": active_event.is_set(),
                "interval": INTERVAL,
                "control_port": CONTROL_PORT,
                "local_ips": sorted(LOCAL_IPS),
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
        # Which of THIS box's IPs did the panel dial? The local address of the
        # control connection IS the current entry IP (the panel POSTs to
        # http://<that_ip>:PORT/control). This is how one agent on a multi-IP
        # box knows which IP it is currently serving.
        try:
            local_ip = self.connection.getsockname()[0]
        except Exception:
            local_ip = ""

        if cmd == "activate":
            ip = activate_as(local_ip)
            log("control: ACTIVATE as %s (from %s)" % (ip, peer))
            return self._send(200, {"detail": "activated", "server_ip": ip})
        if cmd == "deactivate":
            # A rotate fires deactivate(old_ip)+activate(new_ip); on a multi-IP
            # box both land on the SAME agent, so deactivate_for() only stops
            # when this IS the currently-active IP — a late deactivate for the
            # OLD ip must NOT kill the freshly-activated new one.
            if deactivate_for(local_ip):
                log("control: DEACTIVATE %s (from %s)" % (local_ip, peer))
                return self._send(200, {"detail": "deactivated"})
            cur = get_active_ip()
            log("control: DEACTIVATE for %s IGNORED (active as %s)"
                % (local_ip, cur))
            return self._send(200, {"detail": "ignored",
                                    "reason": "not the active IP",
                                    "active_ip": cur})
        return self._send(400, {"detail": "unknown command", "command": cmd})

    def log_message(self, *a):   # silence stderr access-log spam
        pass


def main():
    global SERVER_IP, LOCAL_IPS
    SERVER_IP = os.environ.get("SERVER_IP") or detect_ip()
    if not SERVER_IP:
        log("could not detect server IP — exiting so systemd restarts us")
        sys.exit(1)
    LOCAL_IPS = gather_local_ips()
    log("agent start: server_ip=%s local_ips=%s panel=%s control_port=%d "
        "interval=%ds sample=%ds window=%ds"
        % (SERVER_IP, sorted(LOCAL_IPS), PANEL_URL, CONTROL_PORT,
           INTERVAL, SAMPLE, ACTIVE_WINDOW))

    # Resume the last role (and which IP we were serving) across restarts.
    resumed_active, resumed_ip = load_state()
    if resumed_active and resumed_ip:
        set_active_ip(resumed_ip)
        active_event.set()
        log("resumed role: ACTIVE as %s" % resumed_ip)
    elif resumed_active:
        # Legacy state file with no IP recorded — do NOT guess (reporting from
        # the wrong source IP would be rejected by the panel). Start STANDBY;
        # the panel's self-heal re-activates us with the correct current IP.
        log("resumed ACTIVE but no IP recorded — STANDBY until panel re-activates")
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
