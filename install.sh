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
# 1) Dependencies (python3 stdlib only + conntrack-tools for the -L fallback)
# ---------------------------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
_need=""
command -v python3 >/dev/null 2>&1 || _need="$_need python3"
command -v conntrack >/dev/null 2>&1 || _need="$_need conntrack"
if [ -n "$_need" ]; then
  echo "[*] Installing:$_need"
  apt-get update -qq && apt-get install -y -qq $_need
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
