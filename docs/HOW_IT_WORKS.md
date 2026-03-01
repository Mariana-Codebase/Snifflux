# How Snifflux Works (Detailed)

This document explains the full runtime behavior from app startup to UI rendering.

## 1) Runtime Initialization

When `app.py` starts, Snifflux performs these steps:

1. Chooses Socket.IO async mode:
   - tries `eventlet` first (if installed and import succeeds)
   - otherwise falls back to `threading`
2. Loads environment-based configuration (packet thresholds, safelists, CIDRs, cache sizes, etc.).
3. Initializes SQLite tables (`alert_history`, `block_actions`) if missing.
4. Starts two background tasks:
   - packet capture task (`start_sniffer`)
   - per-second metrics emitter (`emit_packet_counts`)
5. Serves the dashboard on `http://127.0.0.1:5000`.

## 2) Interface Selection and Packet Capture

Packet capture uses Scapy and a prioritized interface strategy:

- If `SNIFFY_IFACE` is set, Snifflux uses it directly.
- Otherwise it builds candidate interfaces from:
  - Scapy default interface
  - default route interface
  - remaining non-loopback/non-virtual interfaces
- It tries to start `AsyncSniffer` on each candidate.
- If no L2 interface can start, it falls back to L3 sniffing with `conf.L3socket`.

Capture filters:

- only packets with an IP layer are processed
- packets are not stored by Scapy (`store=False`) to reduce overhead

## 3) Packet Processing Pipeline

Every captured packet goes through `packet_handler(packet)`:

1. **Basic extraction** (`extract_packet_info`)
   - timestamp (`human`, `ISO`, `unix`)
   - source/destination IPs
   - protocol (TCP/UDP/IP/*)
   - source/destination ports (if available)
   - packet length
2. **Traffic classification**
   - `web` if known web ports are present
   - `video` if known media ports are present
   - `unknown` otherwise
3. **Suspicion evaluation** (`evaluate_suspicion`)
   - first checks safelist CIDR matches
   - then evaluates policy triggers:
     - packet length > `MAX_PACKET_SIZE`
     - source/destination sensitive ports: `22`, `23`, `445`, `3389`
   - assigns severity (`info`, `low`, `medium`, `high`)
4. **State updates**
   - assigns incremental packet ID
   - updates global counters
   - appends packet to in-memory ring log (`deque(maxlen=5000)`)
5. **Realtime emission**
   - emits one of:
     - `regular_packet`
     - `suspicious_packet`
     - `safelisted_packet`
   - emits aggregate updates:
     - `packet_stats`
     - `traffic_mix_update`
6. **Persistence**
   - suspicious packets are inserted into SQLite `alert_history`
   - country and Microsoft-related tags are computed during storage

## 4) Realtime Channel Contract (Socket.IO)

The frontend subscribes to these events:

- `sniffer_status`: capture lifecycle state and message
- `packet_stats`: totals for regular/suspicious/safelisted + current second count
- `traffic_mix_update`: composition values for pie chart (`web`, `video`, `unknown`)
- `packet_count_update`: per-second count for timeline
- `regular_packet`, `suspicious_packet`, `safelisted_packet`: row-level live feed updates

On initial connect (`connect` event), backend pushes current status and counters so the dashboard hydrates without waiting for a new packet.

## 5) Frontend State and Rendering Flow

`templates/index.html` contains a single-page dashboard with in-memory state:

- `packets` array (client memory cap: 1200 packets)
- selected packet ID for detail panel
- chart datasets for timeline/pie
- i18n dictionary (`es` / `en`)
- theme state (`dark` / `light`)

Rendering strategy:

- table and side lists are rerendered from in-memory state
- filters are applied client-side for fast interaction
- CSV export sends current filters to `/download-report`, where backend re-applies the same filter logic to server-side packet memory

## 6) Threat Intelligence and Blocking Workflow

### WHOIS Lookup

- UI calls `GET /api/whois?ip=<ip>`
- backend checks local cache first
- if not cached:
  - performs RDAP lookup (`https://rdap.org/ip/<ip>`)
  - falls back to reverse DNS when RDAP fails
- returns owner, ASN, country, and IP

### Panic Command Generation

- UI calls `GET /api/panic-command?ip=<ip>`
- backend validates IP
- returns generated:
  - `netsh` command
  - PowerShell `New-NetFirewallRule` command

### Auto-Block Execution

- UI calls `POST /api/auto-block` with explicit confirmation
- backend protections:
  - validates IP format
  - refuses private/local IPs
  - allows execution only on Windows
  - parses confirmation robustly (`true/false`, `1/0`, etc.)
- executes `netsh` using argument list (`shell=False`)
- stores action output in `block_actions`

## 7) Analytics and Historical Model

`GET /api/alert-history?days=<n>` returns a bundled analytics payload:

- recent alerts list (up to 300)
- hourly pattern aggregation
- day/hour heatmap matrix
- top countries for alerts
- Microsoft-related country distribution
- top attacker IPs by weighted score

Scoring rule (server-side SQL):

- `high` = 5
- `medium` = 3
- `low` = 1.5
- `info` = 0.5

## 8) Caching and Resource Guards

Snifflux uses simple in-memory caches for country and WHOIS responses:

- cache size limited by `SNIFFY_CACHE_MAX_ITEMS` (default `2000`)
- oldest entries are evicted when the limit is exceeded

Other guardrails:

- packet log ring buffer (`maxlen=5000`)
- frontend packet memory cap (`1200`)
- bounded report generation based on in-memory packet set

## 9) Failure Modes and Recovery Behavior

- If eventlet is unavailable/incompatible, app continues in `threading` mode.
- If interface capture fails, app attempts fallback L3 capture.
- If external country/RDAP lookup fails, app returns `"Unknown"` and keeps running.
- If auto-block command fails, error output is returned and logged in DB (no silent failure).

## 10) Data Flow Summary

1. NIC packet -> Scapy capture
2. Packet parsed/classified/scored
3. Realtime event emitted to browser
4. Suspicious packets persisted to SQLite
5. UI updates charts, tables, detail panel
6. Operator can run WHOIS, generate block commands, or execute auto-block
