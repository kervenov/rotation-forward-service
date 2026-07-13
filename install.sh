#!/bin/bash
# ============================================================================
# rotation-forward-service installer — turnkey, NO input / NO token.
# Run from the repo dir on a forward VPS:  sudo bash install.sh
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
PANEL_IP=""           # optional: pin the panel's IP for control auth if DNS is unreliable
CONTROL_PORT="8765"   # panel -> this box control endpoint (activate/deactivate)
INTERVAL="60"         # seconds between reports while ACTIVE

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
AGENT_SRC="$SRC_DIR/rotation-agent.py"
PORTFWD_SRC="$SRC_DIR/rotation-portfwd.sh"

AGENT_DST="/usr/local/bin/rotation-agent.py"
PORTFWD_DST="/usr/local/sbin/rotation-portfwd.sh"
PORTFWD_SERVICE="/etc/systemd/system/portfwd.service"
AGENT_SERVICE="/etc/systemd/system/rotation-agent.service"

[ -f "$AGENT_SRC" ]   || { echo "[ERR] $AGENT_SRC yok"; exit 1; }
[ -f "$PORTFWD_SRC" ] || { echo "[ERR] $PORTFWD_SRC yok"; exit 1; }

# ---------------------------------------------------------------------------
# 1) Dependencies — robust to a locked dpkg (unattended-upgrades at boot) and
#    to DNS/mirror failures. NEVER aborts the install: python3 is virtually
#    always preinstalled, and conntrack-tools is only a fallback used when
#    /proc/net/nf_conntrack is absent.
# ---------------------------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
PANEL_HOST="$(echo "$PANEL_URL" | sed -E 's#^[a-z]+://##; s#[:/].*$##')"

apt_locked() {
  if command -v fuser >/dev/null 2>&1; then
    fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 && return 0
    fuser /var/lib/apt/lists/lock    >/dev/null 2>&1 && return 0
  fi
  pgrep -x unattended-upgr >/dev/null 2>&1 && return 0
  return 1
}
wait_for_apt() {
  local i=0
  while apt_locked; do
    i=$((i+1))
    [ "$i" -gt 90 ] && { echo "[!] dpkg 180s+ kilitli — yine de deniyorum"; return 0; }
    echo "[*] apt/dpkg kilitli (unattended-upgrades?) bekleniyor... ($i)"
    sleep 2
  done
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
# 2) Port forwarding + boot service (rules unchanged)
# ---------------------------------------------------------------------------
echo "[*] Installing forwarding -> $PORTFWD_DST"
install -m 0755 "$PORTFWD_SRC" "$PORTFWD_DST"
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
echo "[*] Installing agent -> $AGENT_DST"
install -m 0755 "$AGENT_SRC" "$AGENT_DST"
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
After=network-online.target
Wants=network-online.target
# Never give up restarting — this is what makes it universal across VPS.
StartLimitIntervalSec=0

[Service]
Type=simple
Environment=PANEL_URL=$PANEL_URL
Environment=PANEL_IP=$PANEL_IP
Environment=CONTROL_PORT=$CONTROL_PORT
Environment=INTERVAL=$INTERVAL
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
