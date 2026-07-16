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
INTERVAL="10"         # seconds between reads/POSTs. ACTIVE = COMPLETE round trip per interval: request (client->IP) AND response (internet->IP) BOTH grew. One-way (dead/retry-only) clients are not counted.

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
    # Bounded + retried: WITHOUT these curl can hang FOREVER on a stalled
    # connection (observed live — the installer froze at this line). Cap the
    # connect and the whole transfer, and retry transient failures/timeouts.
    curl -fsSL --connect-timeout 15 --max-time 60 \
         --retry 4 --retry-delay 3 --retry-connrefused \
         "$RAW_BASE/$name" -o "$dst" \
      || { echo "[ERR] $name indirilemedi (ağ/DNS/GitHub erişimi?)."
           echo "      Tekrar deneyin; sürerse: curl -v $RAW_BASE/$name"
           exit 1; }
    chmod "$mode" "$dst"
  fi
}

# ---------------------------------------------------------------------------
# 1) Dependencies — FULLY FLEXIBLE, meant to survive ANY VPS image.
#    * Detects the package manager (apt/dnf/yum/apk/pacman/zypper) and maps
#      per-distro package names — a minimal image often ships NO iptables.
#    * Installs only what is MISSING.
#    * Survives a locked dpkg (unattended-upgrades at boot), DNS/mirror
#      failures and a stalled mirror.
#    * ABORTS only when a structurally essential piece is missing and cannot be
#      installed (systemd / python3 / iptables). Everything else degrades with a
#      loud, actionable warning instead of a half-broken install.
# ---------------------------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
PANEL_HOST="$(echo "$PANEL_URL" | sed -E 's#^[a-z]+://##; s#[:/].*$##')"

# systemd is structural (both units are systemd services). Fail EARLY and
# clearly instead of installing half of everything and dying at `systemctl`.
if ! command -v systemctl >/dev/null 2>&1; then
  echo "[ERR] systemd yok (systemctl bulunamadı) — bu installer systemd gerektirir."
  echo "      OpenRC/Alpine gibi init'lerde servisleri elle tanımlamanız gerekir."
  exit 1
fi

# 'sudo: unable to resolve host <name>' — the box's own hostname is missing from
# /etc/hosts. Cosmetic, but it prints on EVERY sudo call. Fix it once.
_HN="$(hostname 2>/dev/null || true)"
if [ -n "$_HN" ] && ! grep -qE "(^|[[:space:]])${_HN}([[:space:]]|$)" /etc/hosts 2>/dev/null; then
  echo "127.0.1.1 $_HN" >> /etc/hosts 2>/dev/null \
    && echo "[OK] /etc/hosts: '$_HN' eklendi (sudo host uyarısı susar)"
fi

# --- package-manager abstraction -------------------------------------------
PKG=""
for _p in apt-get dnf yum apk pacman zypper; do
  command -v "$_p" >/dev/null 2>&1 && { PKG="$_p"; break; }
done
if [ -n "$PKG" ]; then
  echo "[i] Paket yöneticisi: $PKG"
else
  echo "[!] Paket yöneticisi bulunamadı — eksik araçlar elle kurulmalı."
fi

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
pkg_install() {   # best-effort; never aborts. usage: pkg_install <pkg>...
  case "$PKG" in
    apt-get)
      wait_for_apt
      # -o DPkg::Lock::Timeout: apt WAITS for the lock instead of erroring out.
      apt-get -o DPkg::Lock::Timeout=180 update -qq 2>/dev/null \
        || echo "[!] apt update başarısız (DNS/mirror) — cache ile deneniyor"
      apt-get -o DPkg::Lock::Timeout=180 install -y -qq "$@" 2>/dev/null
      ;;
    dnf)    dnf install -y -q "$@" 2>/dev/null ;;
    yum)    yum install -y -q "$@" 2>/dev/null ;;
    apk)    apk add --no-cache "$@" 2>/dev/null ;;
    pacman) pacman -Sy --noconfirm --needed "$@" 2>/dev/null ;;
    zypper) zypper --non-interactive install "$@" 2>/dev/null ;;
    *)      return 1 ;;
  esac
}

pkg_name() {   # per-distro package name for a generic tool
  case "$1" in
    conntrack)
      case "$PKG" in apt-get) echo conntrack ;; *) echo conntrack-tools ;; esac ;;
    python3)
      case "$PKG" in pacman) echo python ;; *) echo python3 ;; esac ;;
    hostname)
      case "$PKG" in pacman) echo inetutils ;; apk) echo busybox ;; *) echo hostname ;; esac ;;
    iproute2)
      case "$PKG" in dnf|yum|zypper) echo iproute ;; *) echo iproute2 ;; esac ;;
    *) echo "$1" ;;
  esac
}

ensure_tool() {   # ensure_tool <command> <generic-pkg> [required]
  local cmd="$1" generic="$2" req="${3:-}" pkg
  command -v "$cmd" >/dev/null 2>&1 && return 0
  pkg="$(pkg_name "$generic")"
  echo "[*] '$cmd' yok — kuruluyor ($pkg)..."
  pkg_install "$pkg" || true
  if command -v "$cmd" >/dev/null 2>&1; then
    echo "[OK] '$cmd' kuruldu."
    return 0
  fi
  if [ "$req" = "required" ]; then
    echo "[ERR] '$cmd' kurulamadı ve ZORUNLU — kurulum durduruldu."
    echo "      Ağ/depo düzelince elle kurup tekrar çalıştırın:  $PKG install $pkg"
    exit 1
  fi
  echo "[!] '$cmd' kurulamadı (opsiyonel) — devam ediliyor."
  return 1
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

# --- ESSENTIAL: abort only if these truly cannot be installed ---------------
# curl is only needed when the payloads must be DOWNLOADED (the piped one-liner).
# A local clone already has them, so don't hard-require curl in that case.
if [ ! -f "$SRC_DIR/rotation-agent.py" ] || [ ! -f "$SRC_DIR/rotation-portfwd.sh" ]; then
  ensure_tool curl curl required
fi
ensure_tool python3 python3 required     # the agent itself (stdlib only)
# iptables: the WHOLE point of this box (DNAT/MASQUERADE). Minimal images ship
# without it, and portfwd would fail line-by-line with no clear cause.
ensure_tool iptables iptables required

# --- OPTIONAL: the agent degrades gracefully without these ------------------
ensure_tool ip       iproute2 || true    # default route / local IP discovery
ensure_tool hostname hostname || true    # agent's `hostname -I` (has an ip fallback)

# conntrack-tools — needed ONLY when the kernel has no /proc/net/nf_conntrack
# (CONFIG_NF_CONNTRACK_PROCFS off — common on modern kernels).
modprobe nf_conntrack 2>/dev/null || true
if [ ! -r /proc/net/nf_conntrack ]; then
  ensure_tool conntrack conntrack || true
fi
if [ ! -r /proc/net/nf_conntrack ] && ! command -v conntrack >/dev/null 2>&1; then
  echo "[!] UYARI: conntrack okunamıyor (ne /proc dosyası ne de binary)."
  echo "    Agent yine de kurulacak; conntrack gelene kadar rapor GÖNDEREMEZ ama"
  echo "    ASLA yanlış sinyal vermez ve ASLA çökmez (sessiz bekler)."
fi

# --- conntrack byte accounting — the agent CANNOT measure without it --------
# Without bytes= the agent stays silent forever (fail-safe) and Auto Rotation
# never runs — so enable it, PERSIST it, and VERIFY it actually took (a silent
# failure here cost a long debugging session).
echo "[*] nf_conntrack_acct açılıyor (kalıcı)..."
mkdir -p /etc/sysctl.d 2>/dev/null || true
echo "net.netfilter.nf_conntrack_acct = 1" > /etc/sysctl.d/99-conntrack-acct.conf 2>/dev/null || true
# sysctl may be absent on a minimal image -> write the /proc knob directly.
sysctl -w net.netfilter.nf_conntrack_acct=1 >/dev/null 2>&1 \
  || echo 1 > /proc/sys/net/netfilter/nf_conntrack_acct 2>/dev/null || true
modprobe nf_conntrack_netlink 2>/dev/null || true
if [ "$(cat /proc/sys/net/netfilter/nf_conntrack_acct 2>/dev/null)" = "1" ]; then
  echo "[OK] nf_conntrack_acct = 1"
  echo "[i]  Not: acct yalnızca YENİ conntrack kayıtlarına sayaç ekler — mevcut"
  echo "     akışlar yenilenene kadar sayılmaz, o yüzden aktif sayısı yavaş"
  echo "     tırmanır. Hemen oturması için (anlık kopma):  conntrack -F"
else
  echo "[!] nf_conntrack_acct AÇILAMADI — agent byte sayamaz, rapor GÖNDEREMEZ"
  echo "    (panelde 'NO FRESH REPORT' kalır). Elle deneyin:"
  echo "      sysctl -w net.netfilter.nf_conntrack_acct=1"
fi

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

# --- Control port reachability (panel -> :CONTROL_PORT) ---------------------
# The panel ACTIVATES this agent by POSTing to http://<this_ip>:CONTROL_PORT.
# This installer never rewrites the INPUT chain (SSH safety) — but on a box with
# an active firewall that means the panel's POST is silently DROPPED: the panel
# logs "activate ... timed out", the agent stays STANDBY forever, no reports are
# ever sent and Auto Rotation NEVER runs, with no obvious clue. Hit live on a ufw
# box whose only rule was 22/tcp. So punch ONE targeted hole: panel IP ->
# CONTROL_PORT/tcp. Nothing else is opened; existing SSH rules are untouched.
# (VPN traffic is unaffected either way — it is FORWARDed, never INPUT.)
echo "[*] Control port ($CONTROL_PORT) panel IP'sine açılıyor..."
CTRL_IPS="$PANEL_IP $(getent ahostsv4 "$PANEL_HOST" 2>/dev/null | awk '{print $1}')"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^Status: active'; then
  for pip in $(echo "$CTRL_IPS" | tr ' ' '\n' | sort -u); do
    [ -n "$pip" ] || continue
    if ufw allow from "$pip" to any port "$CONTROL_PORT" proto tcp >/dev/null 2>&1; then
      echo "[OK] ufw: $pip -> :$CONTROL_PORT açıldı"
    else
      echo "[!] ufw kuralı eklenemedi. ELLE: ufw allow from $pip to any port $CONTROL_PORT proto tcp"
    fi
  done
elif iptables -L INPUT -n 2>/dev/null | head -1 | grep -q 'policy DROP'; then
  # No ufw, but the INPUT chain still defaults to DROP -> add + persist.
  for pip in $(echo "$CTRL_IPS" | tr ' ' '\n' | sort -u); do
    [ -n "$pip" ] || continue
    if iptables -C INPUT -p tcp -s "$pip" --dport "$CONTROL_PORT" -j ACCEPT 2>/dev/null; then
      echo "[OK] iptables: $pip -> :$CONTROL_PORT zaten açık"
    else
      iptables -I INPUT -p tcp -s "$pip" --dport "$CONTROL_PORT" -j ACCEPT \
        && echo "[OK] iptables: $pip -> :$CONTROL_PORT açıldı"
    fi
  done
  mkdir -p /etc/iptables && iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
else
  echo "[i] Aktif firewall yok (INPUT ACCEPT) — $CONTROL_PORT zaten erişilebilir."
fi
echo "[i] Sağlayıcı firewall'u (cloud security group) varsa $CONTROL_PORT/tcp'yi"
echo "    panel IP'sine oradan da açmalısın — aksi halde panel activate edemez."

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
