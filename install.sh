#!/bin/bash
# ============================================================================
# rotation-forward-service installer — turnkey, NO input / NO token.
#
# ONE-LINER (nothing else needed on the box):
#   curl -fsSL https://raw.githubusercontent.com/kervenov/rotation-forward-service/main/install.sh | sudo bash
#
# Or from a clone:  sudo bash install.sh
#
# Installs:
#   • Port forwarding (rotation-portfwd.sh) + portfwd.service (re-applies at boot)
#   • rotation-agent.py + rotation-agent.service (control listener + reporter)
#
# The agent sits idle (STANDBY, ~0 CPU/RAM) until the panel POSTs "activate";
# then it reports active client IPs every INTERVAL. "deactivate" stops only the
# reporting loop — forwarding keeps running. Survives reboot AND crashes
# (StartLimitIntervalSec=0 -> systemd never gives up restarting it).
# ============================================================================
set -e

# ===== Config (edit here; no interactive prompts) =====
PANEL_URL="https://ze.cyber-x.online:10086/api/auto-rotation/traffic"
PANEL_IP="37.228.117.207"  # panel egress IP — control-auth works even if agent DNS is flaky
CONTROL_PORT="8765"   # panel -> this box control endpoint (activate/deactivate)
INTERVAL="10"         # seconds between POSTs to the panel
SAMPLE_INTERVAL="10"  # conntrack sampling seconds — fresh byte-delta (block detection)
ACTIVE_WINDOW="20"    # an IP counts active only if it transferred within this many seconds
ACTIVE_MIN_BYTES="8192"  # min bytes/window to count as active — excludes idle/asleep (keepalive-only) clients

# When run from a clone SRC_DIR holds the sibling files; when piped through
# `curl … | bash` there is no script dir, so the payload files are fetched
# from the repo instead (see provide()).
SRC_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd || echo /nonexistent)"

AGENT_DST="/usr/local/bin/rotation-agent.py"
PORTFWD_DST="/usr/local/sbin/rotation-portfwd.sh"
PORTFWD_SERVICE="/etc/systemd/system/portfwd.service"
AGENT_SERVICE="/etc/systemd/system/rotation-agent.service"

# Single source of truth for the two payload files: local copy if present
# (clone), otherwise download from the repo (one-liner install). No embedded
# duplicates to keep in sync.
RAW_BASE="https://raw.githubusercontent.com/kervenov/rotation-forward-service/main"
provide() {   # provide <filename> <dest> <mode>
  local name="$1" dst="$2" mode="$3"
  if [ -f "$SRC_DIR/$name" ]; then
    install -m "$mode" "$SRC_DIR/$name" "$dst"
  else
    echo "[*] $name indiriliyor (repo raw)..."
    curl -fsSL "$RAW_BASE/$name" -o "$dst" \
      || { echo "[ERR] $name indirilemedi (ağ/DNS?). Sonra tekrar deneyin."; exit 1; }
    chmod "$mode" "$dst"
  fi
}

# ---------------------------------------------------------------------------
# 1) Dependencies — robust to a locked dpkg (unattended-upgrades at boot) and
#    to DNS/mirror failures. NEVER aborts the install: python3 is virtually
#    always preinstalled, and conntrack-tools is only a fallback used when
#    /proc/net/nf_conntrack is absent.
# ---------------------------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
PANEL_HOST="$(echo "$PANEL_URL" | sed -E 's#^[a-z]+://##; s#[:/].*$##')"

apt_locked() {
  # fuser is authoritative — it names the PID actually HOLDING the lock file.
  # The always-present 'unattended-upgrade-shutdown --wait-for-signal' daemon
  # holds NO lock, so fuser ignores it; matching it by process name (as before)
  # false-positived forever. Only fall through to pgrep when fuser is missing.
  if command -v fuser >/dev/null 2>&1; then
    fuser /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock >/dev/null 2>&1 \
      && return 0
    return 1
  fi
  # No fuser: spot an ACTIVE apt/dpkg run only — never the idle shutdown waiter.
  for p in dpkg apt apt-get; do
    pgrep -x "$p" >/dev/null 2>&1 && return 0
  done
  pgrep -f '/unattended-upgrade$' >/dev/null 2>&1 && return 0
  return 1
}
wait_for_apt() {
  local i=0 max=60
  apt_locked || return 0
  echo "[i] apt/dpkg başka bir işlemce kilitli (genelde boot sonrası unattended-upgrades)."
  echo "    En fazla $((max*2))sn beklenip yine de denenecek (apt kendi de kilidi bekler)."
  echo "    HIZLANDIRMAK için BAŞKA bir terminalde:"
  echo "      sudo systemctl stop unattended-upgrades apt-daily.service apt-daily-upgrade.service"
  while apt_locked; do
    i=$((i+1))
    [ "$i" -gt "$max" ] && { echo "[!] hâlâ kilitli — yine de deniyorum"; return 0; }
    echo "[*] kilit bekleniyor... ($i/$max)"
    sleep 2
  done
  echo "[OK] kilit açıldı."
}
apt_install() {   # best-effort; returns non-zero on failure so caller can fall back
  wait_for_apt
  # -o DPkg::Lock::Timeout: apt WAITS for the lock instead of erroring out.
  apt-get -o DPkg::Lock::Timeout=180 update -qq 2>/dev/null \
    || echo "[!] apt update başarısız (DNS/mirror) — cache ile deneniyor"
  apt-get -o DPkg::Lock::Timeout=180 install -y -qq "$@" 2>/dev/null
}
ensure_dns() {    # so BOTH apt and the agent can resolve the panel host
  getent hosts "$1" >/dev/null 2>&1 && return 0
  echo "[!] DNS '$1' çözülemiyor — public resolver ekleniyor (1.1.1.1 / 8.8.8.8)"
  if command -v resolvectl >/dev/null 2>&1; then
    IFACE="$(ip route show default 2>/dev/null | awk '{print $5; exit}')"
    [ -n "$IFACE" ] && resolvectl dns "$IFACE" 1.1.1.1 8.8.8.8 2>/dev/null || true
  fi
  if [ ! -L /etc/resolv.conf ]; then
    grep -q '^nameserver 1.1.1.1' /etc/resolv.conf 2>/dev/null || echo "nameserver 1.1.1.1" >> /etc/resolv.conf
    grep -q '^nameserver 8.8.8.8' /etc/resolv.conf 2>/dev/null || echo "nameserver 8.8.8.8" >> /etc/resolv.conf
  fi
  getent hosts "$1" >/dev/null 2>&1
}

ensure_dns "$PANEL_HOST" \
  || echo "[!] DNS hâlâ sorunlu — agent panel host'u çözemezse install.sh içinde PANEL_IP ayarlayın"

# curl — needed by provide() to fetch the payload files when piped. Almost
# always present (the one-liner is fetched with it), but make sure.
command -v curl >/dev/null 2>&1 || { echo "[*] curl kuruluyor..."; apt_install curl || true; }

# python3 — fatal only if truly absent AND uninstallable.
if ! command -v python3 >/dev/null 2>&1; then
  echo "[*] python3 yok — kuruluyor..."
  apt_install python3 || true
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "[ERR] python3 yok ve kurulamadı. Ağ/DNS düzelince: apt-get install -y python3"
  exit 1
fi

# conntrack-tools — ONLY a fallback for kernels without /proc/net/nf_conntrack.
modprobe nf_conntrack 2>/dev/null || true
if [ ! -r /proc/net/nf_conntrack ] && ! command -v conntrack >/dev/null 2>&1; then
  echo "[*] conntrack yok ve /proc/net/nf_conntrack yok — kurmayı deniyorum..."
  apt_install conntrack || true
fi
if [ ! -r /proc/net/nf_conntrack ] && ! command -v conntrack >/dev/null 2>&1; then
  echo "[!] UYARI: conntrack okunamıyor (ne /proc dosyası ne de binary)."
  echo "    Ağ/DNS düzelince:  apt-get install -y conntrack"
  echo "    Agent yine de kurulacak; conntrack gelene kadar rapor gönderemez ama"
  echo "    ASLA yanlış sinyal vermez ve ASLA çökmez (sessiz bekler)."
fi

# conntrack byte accounting — REQUIRED for the bytes= deltas the agent uses.
echo "[*] Enabling nf_conntrack_acct (persistent)..."
echo "net.netfilter.nf_conntrack_acct = 1" > /etc/sysctl.d/99-conntrack-acct.conf
sysctl -w net.netfilter.nf_conntrack_acct=1 >/dev/null 2>&1 || true
modprobe nf_conntrack_netlink 2>/dev/null || true

# ---------------------------------------------------------------------------
# 2) Fetch BOTH payloads FIRST (while DNS is pristine), THEN apply forwarding.
#    Applying the iptables/MASQUERADE rules briefly disrupts the box's OWN
#    outbound DNS (conntrack flush), so every network download MUST happen
#    before this point — otherwise the agent download fails with
#    "Could not resolve host".
# ---------------------------------------------------------------------------
echo "[*] Fetching payloads (before touching iptables)..."
provide rotation-portfwd.sh "$PORTFWD_DST" 0755
provide rotation-agent.py "$AGENT_DST" 0755

echo "[*] Applying port forwarding -> $PORTFWD_DST"
bash "$PORTFWD_DST"

cat > "$PORTFWD_SERVICE" <<EOF
[Unit]
Description=Port forwarding (routing VPS) iptables rules
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$PORTFWD_DST
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# ---------------------------------------------------------------------------
# 3) Rotation agent + service
# ---------------------------------------------------------------------------
echo "[*] Configuring agent service..."
mkdir -p /var/lib/rotation-agent

# Retire the previous single-script reporter if present — the agent supersedes
# it. Leaving it running would double-report every 10s and spam the panel.
if systemctl list-unit-files 2>/dev/null | grep -q '^traffic-reporter\.service'; then
  echo "[*] Eski traffic-reporter.service kaldırılıyor (agent onun yerine geçti)..."
  systemctl disable --now traffic-reporter.service >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/traffic-reporter.service /root/traffic_reporter.py 2>/dev/null || true
fi

cat > "$AGENT_SERVICE" <<EOF
[Unit]
Description=Rotation forward-service agent (control listener + traffic reporter)
# Start after forwarding+DNS-net so the agent can resolve the panel at boot.
After=network-online.target portfwd.service
Wants=network-online.target
# Never give up restarting — this is what makes it universal across VPS.
StartLimitIntervalSec=0

[Service]
Type=simple
Environment=PANEL_URL=$PANEL_URL
Environment=PANEL_IP=$PANEL_IP
Environment=CONTROL_PORT=$CONTROL_PORT
Environment=INTERVAL=$INTERVAL
Environment=SAMPLE_INTERVAL=$SAMPLE_INTERVAL
Environment=ACTIVE_WINDOW=$ACTIVE_WINDOW
Environment=ACTIVE_MIN_BYTES=$ACTIVE_MIN_BYTES
ExecStart=/usr/bin/python3 $AGENT_DST
Restart=always
RestartSec=5
Nice=10
# Light resource guardrails so a runaway can never take the box down.
MemoryMax=128M
CPUQuota=25%

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable portfwd.service       >/dev/null 2>&1
systemctl enable rotation-agent.service >/dev/null 2>&1
systemctl restart rotation-agent.service

echo ""
echo "[OK] rotation-forward-service kuruldu:"
echo "     • Forwarding    -> portfwd.service (boot'ta re-apply, kurallar değişmedi)"
echo "     • Agent         -> rotation-agent.service (STANDBY, ~0 CPU/RAM)"
echo "     • Control port  -> ${CONTROL_PORT} (sadece panel IP'sinden activate/deactivate)"
echo "     • Interval      -> ${INTERVAL}s (yalnızca ACTIVE iken)"
echo ""
echo "[OK] Log:     journalctl -u rotation-agent -f"
echo "[OK] Durum:   curl -s http://127.0.0.1:${CONTROL_PORT}/health"
echo "[i]  Agent panelden 'activate' gelene kadar sessiz bekler. Panel current"
echo "     IP'yi bu sunucuya çevirince otomatik activate POST'u gelir ve başlar."
