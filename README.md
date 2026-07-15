# rotation-forward-service

Lightweight forward-server agent for Marzban **Auto Rotation**. One tiny,
crash-proof Python daemon (stdlib only) plus the port-forwarding rules.

- **Port forwarding** (iptables DNAT/MASQUERADE) — unchanged, re-applied at boot.
- **Control listener** — a minimal HTTP endpoint the panel calls to
  `activate` / `deactivate` this box. Accepted **only from the panel's IP**
  (no token, no operator input).
- **Reachability probe** — while **ACTIVE**, every `PROBE_INTERVAL` seconds it
  ICMP-pings **4 static, domestic-only Turkmenistan hosts** (`100haryt.com`,
  `turkmendemiryollary.gov.tm`, `tmcars.info`, `e.gov.tm`) **from the current
  entry IP** (source-bound, so it tests *that* IP even on a box hosting many) and
  POSTs the verdict to the panel: `reachable=true` if **any** host answered,
  `reachable=false` only when **every** host is silent — i.e. the entry IP is
  TM-blocked, so the panel rotates. Hosts are vetted to go DARK when the entry IP
  is blocked (an internationally-reachable TM site like `turkmenportal.com` would
  mask a block and is excluded); a host that later resolves to a non-TM IP
  (Cloudflare) is dropped automatically. Probing 4 independent hosts × up to
  `PROBE_COUNT` echoes (each capped at `PROBE_DEADLINE`s) means transient loss or
  one host being down can't force a rotation. Kept low-profile (a short echo
  burst, no flooding) so a monitored host doesn't treat it as a scan. While
  **STANDBY** it does nothing → reserved boxes burn ~0 CPU/RAM.

`deactivate` stops **only** the probe loop — forwarding keeps running.

## How the panel drives it

```
panel sets current_ip = <this box>  ->  POST http://<this>:8765/control {"command":"activate"}
rotate / edit away from this box     ->  POST http://<old>:8765/control  {"command":"deactivate"}
```

The role (active/standby) is persisted to `/var/lib/rotation-agent/state`, so a
restart resumes it. Every loop is wrapped and the systemd unit sets
`StartLimitIntervalSec=0`, so the agent can never crash-loop itself into the
"start request repeated too quickly" dead state — it's universal across VPS.

## Install (one line — nothing else needed on the box)

```bash
curl -fsSL https://raw.githubusercontent.com/kervenov/rotation-forward-service/main/install.sh | sudo bash
```

That's it. The installer downloads the agent + forwarding payloads itself,
handles a locked dpkg / broken DNS, retires any old reporter, and brings the
agent up **STANDBY** — no prompts, no token. It waits for the panel to
`activate` it.

<details>
<summary>Alternative: from a clone (to edit the port map / config first)</summary>

```bash
git clone https://github.com/kervenov/rotation-forward-service.git
cd rotation-forward-service
# optional: edit the port->main-VPS map in rotation-portfwd.sh and the config
# block (PANEL_URL / CONTROL_PORT / PROBE_INTERVAL) at the top of install.sh
sudo bash install.sh
```
</details>

## Config (env, set in install.sh)

| Var | Default | Meaning |
|-----|---------|---------|
| `PANEL_URL` | `https://ze.cyber-x.online:10086/api/auto-rotation/traffic` | Where ping-result reports are POSTed. Its host also defines the only IP allowed to send control commands. |
| `CONTROL_PORT` | `8765` | Inbound activate/deactivate endpoint. Not in the DNAT map, so it's delivered locally. |
| `PROBE_INTERVAL` | `10` | Seconds between probe rounds while ACTIVE. |
| `PROBE_COUNT` | `5` | ICMP echoes per host per round (`ping -c`); reachable if ANY returns. |
| `PROBE_TIMEOUT` | `2` | Per-echo reply wait (`ping -W`, seconds). |
| `PROBE_DEADLINE` | `5` | Per-host overall deadline (`ping -w`, seconds) so a blocked host never hangs. |
| `PANEL_IP` | *(empty)* | Optional extra allowed control-source IP(s), comma-separated (e.g. if the panel egresses from a different IP than its DNS). |

## Operate

```bash
journalctl -u rotation-agent -f                 # live log (PROBE lines: reachable=… per-host up/DOWN)
curl -s http://127.0.0.1:8765/health            # {active, probe_interval, probe_hosts, probe_ips, ...}
systemctl status rotation-agent portfwd         # service state
```

## Files

| File | Role |
|------|------|
| `rotation-agent.py` | The daemon: control listener + gated reachability probe. |
| `rotation-portfwd.sh` | Port forwarding rules (edit `rules` for this box). Boot-persistent via `portfwd.service`. |
| `install.sh` | Turnkey installer — deps, both services, no input. |
