#!/bin/bash
# ============================================================================
# Port forwarding (routing/forward VPS) — iptables DNAT/MASQUERADE.
# BYTE-FOR-BYTE the same rules that were proven working (portfwd_final.sh).
# Idempotent: safe to re-run. Only touches nat + FORWARD + mangle OUTPUT —
# the INPUT chain is left ALONE so the SSH firewall is never affected.
#
# Installed to /usr/local/sbin/rotation-portfwd.sh and run at boot by
# portfwd.service. Edit the `rules` array for this deployment's mappings.
# ============================================================================
set -e

# ===== Port -> Main VPS IP mapping =====
rules=(
  "8080 51.77.32.235"
  "4086 46.62.233.178"
  "42817 188.126.76.229"
  "8443 167.233.90.133"
  "59596 167.233.90.133"
  "47292 51.77.32.235"
  "33376 46.62.233.178"
  "34645 193.57.9.202"
  "37050 74.48.114.9"
  "53635 45.8.249.213"
)

echo "[*] Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward
sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Idempotent reset: only nat + FORWARD (INPUT untouched -> SSH firewall safe).
echo "[*] Flushing old nat + FORWARD rules..."
iptables -t nat -F
iptables -F FORWARD

echo "[*] NAT MASQUERADE for outgoing traffic..."
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

for rule in "${rules[@]}"; do
  PORT=$(echo "$rule" | awk '{print $1}')
  MAIN_VPS_IP=$(echo "$rule" | awk '{print $2}')
  echo "[*] Forwarding port $PORT -> $MAIN_VPS_IP"
  iptables -t nat -A PREROUTING -p tcp --dport "$PORT" -j DNAT --to-destination "$MAIN_VPS_IP:$PORT"
  iptables -t nat -A PREROUTING -p udp --dport "$PORT" -j DNAT --to-destination "$MAIN_VPS_IP:$PORT"
  iptables -A FORWARD -d "$MAIN_VPS_IP" -j ACCEPT
  iptables -A FORWARD -s "$MAIN_VPS_IP" -j ACCEPT
done

echo "[*] SNAT (MASQUERADE) so responses return via routing VPS..."
iptables -t nat -A POSTROUTING -j MASQUERADE

# MSS clamp for THIS box's OWN outbound TCP. The path to the panel has a lower
# MTU than 1500, so without capping the advertised MSS the TLS handshake to the
# panel (large Certificate flight) intermittently times out. Affects only
# locally-originated connections (OUTPUT) — the forwarded VPN traffic (FORWARD
# chain) is untouched. Idempotent.
iptables -t mangle -D OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360 2>/dev/null || true
iptables -t mangle -A OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360

mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4

# --- DNS safety net --------------------------------------------------------
# The catch-all MASQUERADE above masquerades LOOPBACK too, which breaks the
# systemd-resolved stub (127.0.0.53) — so DNS via the stub dies once forwarding
# is on, and the agent can no longer resolve the panel (activation + reports
# fail). Fix: BYPASS the stub. Point resolv.conf DIRECTLY at public resolvers,
# whose queries egress via the external NIC and are masqueraded normally.
# Runs at BOOT too (portfwd.service re-applies forwarding), so it survives
# reboots. Acts when the stub is in use OR resolution is already failing.
if [ -L /etc/resolv.conf ] || grep -q '127\.0\.0\.53' /etc/resolv.conf 2>/dev/null \
   || ! getent hosts one.one.one.one >/dev/null 2>&1; then
  echo "[*] Pinning direct public resolvers (bypassing the broken resolver stub)..."
  rm -f /etc/resolv.conf
  printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > /etc/resolv.conf
  getent hosts one.one.one.one >/dev/null 2>&1 \
    && echo "[OK] DNS restored (direct resolver)." \
    || echo "[!] DNS still failing — check manually."
fi

echo "[OK] Forwarding applied."
