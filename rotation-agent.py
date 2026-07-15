#!/usr/bin/env python3
"""Rotation forward-service agent — one tiny, crash-proof daemon (stdlib only).

Two jobs in one process:

1. CONTROL LISTENER (always on, ~0 CPU/RAM when idle): a minimal HTTP server
   on CONTROL_PORT that the PANEL calls to turn probing on/off:
       POST /control {"command": "activate"}    -> start probing
       POST /control {"command": "deactivate"}  -> stop probing
   Accepted ONLY from the panel's IP (resolved from PANEL_URL). No token, no
   operator input. Forwarding (iptables DNAT/FORWARD) is NEVER touched here —
   "deactivate" only stops the probe loop; the box keeps forwarding.

2. REACHABILITY PROBE (gated by the active flag): while ACTIVE, every
   PROBE_INTERVAL seconds it ICMP-pings 4 static Turkmenistan hosts FROM the
   current entry IP (source-bound) and POSTs a ping-result report to the panel:
   reachable=True if ANY host answered, reachable=False only when EVERY host is
   silent (the entry IP is TM-blocked -> panel rotates). While STANDBY it does
   nothing — a reserved server sits idle until the panel activates it. This is
   why reserved boxes burn no CPU/RAM.

The role (active/standby) is persisted to STATE_FILE, so a restart resumes the
last role and a lost/queued activate isn't forgotten across a crash. Every
loop body is wrapped so a transient error can never kill the process (which,
combined with systemd StartLimitIntervalSec=0, is what makes it universal —
no more "start request repeated too quickly" self-stop).
"""
import http.client
import ipaddress
import json
import os
import shutil
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

# ── Probe (reachability) model ─────────────────────────────────────────────
# The agent no longer inspects VPN traffic. Instead it periodically ICMP-pings
# well-known Turkmenistan hosts FROM the current entry IP and asks: can this IP
# still reach TM? If the entry IP is TM-blocked the echoes never come back. When
# EVERY host is unreachable the IP is considered blocked and the panel is told
# to rotate. Probing 4 independent hosts means one host merely being down can't
# trigger a rotation — a block is only declared when ALL 4 go silent.
#
# Kept low-profile on purpose (operator: don't let telecom.tm notice and close
# ICMP): a short burst of a few echoes per round, default packet size, no
# flooding — it reads like an ordinary reachability check, not a scan. The entry
# IP also rotates, so no single source pings a host forever.
#
# The probe hosts are STATIC (not operator-configurable). The ONLY reliable test
# of a good probe host is EMPIRICAL: it must go DARK (0 replies) when pinged from
# a KNOWN-BLOCKED entry IP, yet answer from a working IP. Verified 2026-07-16 on
# the live box (working 85.198.81.167 vs blocked 104.171.133.75):
#   100haryt.com               216.250.12.107  working 5/5, blocked 0/5  ✓
#   turkmendemiryollary.gov.tm 95.85.108.117   working 5/5, blocked 0/5  ✓
#   tmcars.info                95.85.122.6     working 5/5, blocked 0/5  ✓
#   e.gov.tm                   217.174.238.99  working 5/5, blocked 0/5  ✓  (distinct /20)
# Vetted spares (all working 5/5, blocked 0/5): minjust.gov.tm 216.250.10.199,
#   bilim.gov.tm 216.250.8.131, science.gov.tm 216.250.11.55, belet.tm (119.235.x).
# DROPPED:
#   turkmenportal.com (95.85.126.182), sanly.tm (95.85.126.30),
#   customs.gov.tm — TM IPs but INTERNATIONALLY reachable (answered 5/5 even from
#     the blocked IP), so they would MASK a block. A TM IP is necessary but NOT
#     sufficient — the host must be domestic-only (dark when the entry IP is blocked).
#   ynamdar.com (93.171.223.25) — 0 echoes even from a healthy IP (firewalls ICMP).
#
# GUARD: each round the agent re-resolves these and DROPS any host that no longer
# points at a Turkmenistan IP (see resolve_probe_hosts / _is_tm_ip) — e.g. one
# that moves behind Cloudflare. That catches CDN moves; the domestic-only vetting
# above is what catches TM-IP-but-globally-reachable sites like turkmenportal.
PROBE_HOSTS = ["100haryt.com", "turkmendemiryollary.gov.tm", "tmcars.info",
               "e.gov.tm"]
PROBE_INTERVAL = int(os.environ.get("PROBE_INTERVAL", "10"))  # seconds between probe rounds
PROBE_COUNT = int(os.environ.get("PROBE_COUNT", "5"))         # echoes per host per round (ping -c)
PROBE_TIMEOUT = int(os.environ.get("PROBE_TIMEOUT", "2"))     # per-echo reply wait (ping -W, seconds)
# Overall per-host wall-clock cap (ping -w). BOTH limits apply: send up to
# PROBE_COUNT echoes BUT never spend more than PROBE_DEADLINE seconds on a host.
# Critical for a BLOCKED IP: its echoes never come back, so without a deadline
# ping could wait far too long — this caps each host at PROBE_DEADLINE seconds.
PROBE_DEADLINE = int(os.environ.get("PROBE_DEADLINE", "5"))   # per-host deadline (ping -w, seconds)

STATE_FILE = os.environ.get("STATE_FILE", "/var/lib/rotation-agent/state")
PANEL_IP_ENV = os.environ.get("PANEL_IP", "")          # optional extra allowed IP(s), comma-sep

SERVER_IP = ""

# Resolved probe-host IPs, refreshed off the panel-independent default resolver
# (DNS is NOT source-bound, so it works even when the entry IP is blocked). We
# connect to the cached IPs so a transient DNS blip can't look like a block.
_probe_ips_lock = threading.Lock()
_probe_ips = {}          # host -> ip (last good)

# The IP the panel last ACTIVATED this box for — learned from the LOCAL address
# of the activate control connection. One physical box may host many public IPs
# (the operator rotates among IPs on the SAME server), so reports are sent FROM
# this IP (source-bound) and labelled with it; that keeps the panel's
# "peer == current entry IP" auth valid even when the box's default egress IP
# differs from the current IP.
_active_lock = threading.Lock()
active_ip = ""

# active_event set  -> probe loop should run every PROBE_INTERVAL
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
# Probe — is the CURRENT entry IP still able to reach Turkmenistan?
# ---------------------------------------------------------------------------
# Turkmenistan IPv4 blocks — MIRRORS the panel's app/utils/tm_ip.py
# (ipdeny tm-aggregated.zone). A probe host is only trusted if it resolves
# INTO one of these: a host that has moved behind a global CDN (Cloudflare's
# orange cloud etc.) would resolve to an anycast edge reachable from anywhere,
# so it would answer even when the entry IP is TM-blocked and MASK the block.
# Keep in sync with the panel list.
_TM_CIDRS = [
    "77.83.59.0/24", "95.85.96.0/19", "103.220.0.0/22", "119.235.112.0/20",
    "177.93.143.0/24", "185.69.184.0/22", "185.246.72.0/22",
    "194.117.52.192/26", "216.250.8.0/21", "217.65.78.0/24", "217.174.224.0/20",
]
_TM_NETS = []
for _c in _TM_CIDRS:
    try:
        _TM_NETS.append(ipaddress.ip_network(_c))
    except ValueError:
        pass


def _is_tm_ip(ip):
    """True iff ``ip`` falls inside a Turkmenistan block. Non-IP -> False."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _TM_NETS)


def resolve_probe_hosts():
    """Resolve the 4 static TM probe hosts to IPv4 and cache them. DNS is NOT
    source-bound (it goes out the default resolver, which we keep working even
    when the entry IP is blocked), so resolution keeps succeeding regardless of
    the entry IP's reachability. On a resolve failure we keep the last-good IP
    so a DNS blip can't masquerade as a block. Returns {host: ip}."""
    global _probe_ips
    resolved = {}
    with _probe_ips_lock:
        last_good = dict(_probe_ips)
    for host in PROBE_HOSTS:
        ip = ""
        try:
            for res in socket.getaddrinfo(host, None, socket.AF_INET):
                ip = res[4][0]
                break
        except Exception as e:
            log("probe DNS resolve failed for %s: %s" % (host, e))
        if ip and not _is_tm_ip(ip):
            # Host no longer resolves to a Turkmenistan IP — most likely moved
            # behind a global CDN (Cloudflare). Such a host is anycast/global and
            # would answer even from a TM-blocked entry IP, MASKING the block, so
            # it is DROPPED (not cached, not reused). The other hosts still probe;
            # if EVERY host drops, resolve returns empty -> probe_reachable
            # fail-safes to reachable (never a false rotate).
            log("probe host %s -> non-TM IP %s (CDN/Cloudflare?) — SKIPPING so it "
                "can't mask a block; replace this host" % (host, ip))
            continue
        if not ip:
            ip = last_good.get(host, "")   # DNS blip: reuse last validated TM IP
        if ip:
            resolved[host] = ip
    if resolved:
        with _probe_ips_lock:
            _probe_ips = resolved
    return resolved


def ping_host(target_ip, source_ip=""):
    """Send ICMP echoes to ``target_ip`` and return True if ANY reply comes
    back. We ask for up to PROBE_COUNT packets (``ping -c``) and treat even a
    single reply as "reachable" — one packet returning proves the entry IP can
    still get to Turkmenistan, and asking for several makes a couple of random
    drops harmless (no false "blocked"). Bound to ``source_ip`` (``ping -I``) so
    it tests the CURRENT entry IP specifically, not the box's default egress.

    Kept deliberately low-profile: a short burst of a few echoes every round,
    default packet size — it reads like an ordinary reachability check, not a
    scan, so a monitored host (telecom.tm) is unlikely to treat it as hostile."""
    # -c: up to PROBE_COUNT echoes; -W: per-echo reply wait; -w: OVERALL deadline
    # so a black-holed (blocked) host — echoes sent, nothing ever returns — exits
    # at PROBE_DEADLINE instead of dragging on. Both the packet count AND the
    # time cap apply, whichever is hit first.
    cmd = ["ping", "-n", "-c", str(PROBE_COUNT),
           "-W", str(PROBE_TIMEOUT), "-w", str(PROBE_DEADLINE)]
    if source_ip:
        cmd += ["-I", source_ip]
    cmd.append(target_ip)
    # Belt-and-suspenders: kill the subprocess a few seconds past ping's own -w
    # deadline in case ping ignores it (e.g. stuck in DNS — we pass a numeric IP
    # and -n to avoid that, but never hang the probe loop regardless).
    try:
        r = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=PROBE_DEADLINE + 3,
        )
        # ping exits 0 iff at least one echo was answered.
        return r.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except FileNotFoundError:
        log("ping binary missing — install iputils-ping (apt install -y iputils-ping)")
        return False
    except Exception as e:
        log("ping error for %s: %s" % (target_ip, e))
        return False


def probe_reachable(source_ip=""):
    """Probe all 4 TM hosts (in parallel) from ``source_ip`` and return
    (reachable, detail). reachable is True if ANY host answered; it is False
    ONLY when EVERY host is unreachable — the signal that the current entry IP
    is TM-blocked. Probing 4 independent hosts means one host being down (not a
    block) can't trigger a rotation: the others still answer."""
    if shutil.which("ping") is None:
        # No ping binary — treat as reachable (fail-safe): a missing tool is a
        # LOCAL fault, not a TM block, and must never rotate-storm the whole
        # pool. Self-heals the moment iputils-ping is installed.
        log("probe: ping binary not found — assuming reachable (fail-safe); "
            "install iputils-ping")
        return True, {}
    hosts = resolve_probe_hosts()
    if not hosts:
        # Couldn't resolve ANY probe host — treat as reachable (fail-safe): a
        # total DNS outage must not be mistaken for a TM block and rotate a
        # working IP. This is rare and self-heals on the next round.
        log("probe: no host resolved — assuming reachable (fail-safe)")
        return True, {}
    results = {}
    threads = []

    def _run(h, ip):
        results[h] = ping_host(ip, source_ip)

    for host, ip in hosts.items():
        t = threading.Thread(target=_run, args=(host, ip), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join(PROBE_DEADLINE + 6)   # a little past the subprocess timeout
    reachable = any(results.values())
    return reachable, results


def post(reachable, source_ip="", detail=None):
    """POST the PING-RESULT report to the panel, source-bound to ``source_ip``
    (the current entry IP) when given, so the panel sees the report arriving
    FROM the current IP — its "peer == current entry IP" auth then holds even on
    a box that hosts many IPs. ``server_ip`` in the body is labelled with the
    same IP.

    ``reachable`` is the whole signal: True = the current entry IP can still
    reach at least one TM host; False = every TM host was silent (blocked) ->
    the panel should rotate. ``per_host`` is included for the panel log only.

    If binding fails (e.g. the IP isn't actually local) the retry falls back to
    the default egress so a report is still attempted (it may be ignored by the
    panel, but a loud POST-failure is worse)."""
    body = json.dumps({
        "server_ip": source_ip or SERVER_IP,
        "reachable": bool(reachable),
        "per_host": detail or {},
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
# Probe loop — only runs while ACTIVE; near-zero cost while STANDBY
# ---------------------------------------------------------------------------
def probe_loop():
    while True:
        try:
            active_event.wait()          # STANDBY: blocks, ~0 CPU, until activated
            standby_signal.clear()
            entry = get_active_ip()
            log("ACTIVE as %s — probing %d TM hosts every ~%ds "
                "(%d echoes/host, %ds reply wait, %ds deadline), "
                "source-bound to the entry IP"
                % (entry or SERVER_IP, len(PROBE_HOSTS), PROBE_INTERVAL,
                   PROBE_COUNT, PROBE_TIMEOUT, PROBE_DEADLINE))
            resolve_probe_hosts()        # warm the DNS cache before the first probe
            # Probe IMMEDIATELY on activation (no initial sleep) so a freshly
            # activated IP is verified at once; then hold a ~PROBE_INTERVAL
            # start-to-start cadence (the probe itself takes a few seconds).
            while active_event.is_set():
                t0 = time.monotonic()
                try:
                    entry = get_active_ip()
                    reachable, detail = probe_reachable(entry)
                    ok = post(reachable, entry, detail)
                    summary = ", ".join(
                        "%s=%s" % (h, "up" if v else "DOWN")
                        for h, v in detail.items()) or "no-hosts-resolved"
                    log("PROBE(as %s) reachable=%s [%s] -> POST%s"
                        % (entry or SERVER_IP, reachable, summary,
                           "" if ok else " [FAILED]"))
                except Exception as e:
                    log("probe tick error (continuing):", e)
                # Hold the cadence: sleep whatever's left of PROBE_INTERVAL after
                # the probe's own duration (floor 1s), waking at once on deactivate.
                wait = PROBE_INTERVAL - (time.monotonic() - t0)
                if wait < 1:
                    wait = 1
                if standby_signal.wait(wait):
                    break
            log("STANDBY — probing stopped (forwarding untouched)")
        except Exception as e:
            log("probe loop error (restarting loop):", e)
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
                "probe_interval": PROBE_INTERVAL,
                "probe_hosts": PROBE_HOSTS,
                "probe_ips": _probe_ips,
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
    global SERVER_IP
    SERVER_IP = os.environ.get("SERVER_IP") or detect_ip()
    if not SERVER_IP:
        log("could not detect server IP — exiting so systemd restarts us")
        sys.exit(1)
    log("agent start: server_ip=%s panel=%s control_port=%d "
        "probe_interval=%ds probe_count=%d probe_timeout=%ds hosts=%s"
        % (SERVER_IP, PANEL_URL, CONTROL_PORT, PROBE_INTERVAL,
           PROBE_COUNT, PROBE_TIMEOUT, PROBE_HOSTS))

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

    threading.Thread(target=probe_loop, daemon=True).start()

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
