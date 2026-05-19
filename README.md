# 🛡️ Watch Man — Network Traffic Analyzer

> A production-ready, real-time network packet analysis dashboard with
> multi-rule threat detection, built for cybersecurity labs and final-year
> presentations.

---

## 📸 Features

| Feature | Description |
|---------|-------------|
| 📡 Live Packet Capture | Scapy raw-socket engine captures IP/TCP/UDP/ICMP/DNS/HTTP |
| 🎭 Demo / Simulation Mode | Realistic synthetic traffic — no root required |
| 📊 Real-time Dashboard | Auto-refreshing charts: PPS line chart, protocol doughnut |
| 🚨 Threat Detection | DoS, ICMP flood, SSH brute-force, port scan, DNS amp, suspicious ports |
| 📋 Connection Log | Scrollable table with protocol filter |
| 💾 CSV Export | One-click export of traffic logs and alerts |
| 🩺 Health Endpoint | `/health` for monitoring / load-balancer probes |
| 🗃️ File Logging | Persistent logs written to `logs/watchman.log` |
| 🎨 Cyber UI | Dark terminal-style SOC dashboard |

---

## 🗂️ Project Structure

```
watchman/
├── app.py                      ← Flask entry point + REST API
├── requirements.txt
├── README.md
├── logs/                       ← Auto-created; watchman.log written here
├── sniffer/
│   ├── __init__.py
│   └── capture.py              ← Scapy capture engine + demo simulator
├── models/
│   ├── __init__.py
│   └── data_store.py           ← Thread-safe in-memory state store
├── utils/
│   ├── __init__.py
│   └── threat_detector.py      ← Rule-based threat analysis (7 rules)
├── templates/
│   └── index.html              ← Dashboard HTML
└── static/
    ├── css/style.css           ← Cybersecurity dark theme
    └── js/dashboard.js         ← Charts, polling, interactivity
```

---

## ⚙️ Installation

### Prerequisites

- Python 3.10 or later
- `pip`
- (For live capture only) Linux with root / `CAP_NET_RAW` privileges

### 1. Extract / clone the project

```bash
cd watchman
```

### 2. Create a virtual environment (recommended)

```bash
python3 -m venv venv
source venv/bin/activate        # Linux / macOS
venv\Scripts\activate           # Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## 🚀 Running Watch Man

### Demo mode — simulated traffic (no root required)

```bash
python app.py --demo
```

Or via environment variable:

```bash
DEMO_MODE=1 python app.py
```

### Live capture mode — real packets (requires root on Linux)

```bash
sudo python app.py
```

Open the dashboard at **http://127.0.0.1:5000**

---

## 🌐 REST API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard UI |
| `/traffic` | GET | Full traffic snapshot (JSON) |
| `/alerts` | GET | Threat alerts list, newest first (JSON) |
| `/stats` | GET | KPI summary: packets, bytes, PPS, alerts |
| `/health` | GET | Health check — 200 OK or 503 if capture thread dead |
| `/api/mode` | GET | Returns `{"demo": true/false, "live": true/false}` |
| `/clear-alerts` | POST | Wipe all stored alerts (also clears backend state) |
| `/export/csv` | GET | Download recent packets as `traffic_log.csv` |
| `/export/alerts/csv` | GET | Download alerts as `alerts_log.csv` |

---

## 🛡️ Threat Detection Rules

| # | Rule | Trigger | Severity |
|---|------|---------|----------|
| 1 | DoS / Flood | > 80 packets from one IP in 10 s | HIGH |
| 2 | ICMP Flood | > 40 ICMP packets from one IP in 10 s | HIGH |
| 3 | SSH Brute-Force | > 15 TCP/22 attempts from one IP in 30 s | HIGH |
| 4 | Port Scan | > 12 unique dst ports from one IP in 10 s | HIGH |
| 5 | Suspicious Port | Traffic on Telnet/SMB/RDP/Metasploit/etc. ports | LOW–CRITICAL |
| 6 | DNS Amplification | UDP/53 response > 512 bytes | MEDIUM |
| 7 | Oversized Packet | Single packet > 1460 bytes (above Ethernet MTU) | MEDIUM |

All rules use a sliding deque window and per-IP alert cooldown (15 s) to
prevent alert spam.

---

## 🐛 Bugs Fixed (vs. original network_analyzer)

| # | Location | Bug | Fix |
|---|----------|-----|-----|
| 1 | `data_store.py` | `current_second_count` read outside lock → race condition | Moved read inside `_lock` in `get_snapshot()` |
| 2 | `data_store.py` | PPS current second never flushed when snapshot was taken mid-second | `current_pps` now returns in-progress count directly |
| 3 | `data_store.py` | `ip_packet_counts` grew without bound (memory leak) | Bounded to 500 entries; prunes on overflow |
| 4 | `data_store.py` | `start_time` set at import, not on startup | `reset_state()` called by `start_capture()` |
| 5 | `capture.py` | ICMP flood scenario called `check_packet` without `sport`/`dport` → `TypeError` | Passes explicit `None` arguments |
| 6 | `capture.py` | `_running` flag never set in `stop_capture()` properly | Corrected; `stop_capture()` sets `_running = False` |
| 7 | `capture.py` | Demo could pick `src == dst` | `_pick_pair()` guarantees `src != dst` |
| 8 | `app.py` | `DEMO_MODE` default was `"1"` → always demo even without `--demo` | Corrected default to `"0"` |
| 9 | `app.py` | No `/clear-alerts` endpoint → dashboard "CLEAR" button did nothing server-side | Endpoint added |
| 10 | `app.py` | No `/health` endpoint | Added |
| 11 | `threat_detector.py` | `_ip_window` / `_icmp_window` grew unbounded for unique IPs | Bounded to 300 IPs; `_enforce_ip_cap()` trims on overflow |
| 12 | `threat_detector.py` | Oversized packet threshold 1400 B fired on normal frames | Raised to 1460 B (true Ethernet payload limit) |
| 13 | `threat_detector.py` | DoS threshold 100 was too high for demo; now tuned and documented | Adjusted to 80 with explanatory comment |
| 14 | `dashboard.js` | `clearAlerts()` only cleared the DOM, not server state | Now POSTs to `/clear-alerts` first |
| 15 | `dashboard.js` | Status pill always showed "INITIALIZING" after load | Now shows "SIMULATION ACTIVE" or "LIVE MONITORING" |
| 16 | `dashboard.js` | Alert deduplication key could collide across sessions | Key is now `time|type|detail` string |

### New features added

- Port scan detection (Rule 4)
- SSH brute-force detection (Rule 3)
- DNS amplification detection (Rule 6)
- Port scan & SSH brute-force demo scenarios in simulation mode
- `/health` endpoint
- `/api/mode` endpoint
- File-based logging to `logs/watchman.log`
- `atexit` shutdown hook stops capture thread cleanly

---

## 🏗️ Architecture

```
Browser  ←──2s poll──→  Flask REST API
                              │
                     ┌────────┴────────┐
                     │   data_store    │ ← thread-safe (RLock)
                     └────────┬────────┘
                              │  record_packet / add_alert
              ┌───────────────┴───────────────┐
              │                               │
     sniffer/capture.py              utils/threat_detector.py
    (daemon thread)                  (7 detection rules)
         │
    Scapy sniff  OR  _simulate_traffic()
```

- **3-layer design**: Capture → Analysis → Visualization
- Scapy / simulator runs in a daemon thread; Flask serves the REST API; JavaScript polls every 2 s
- All state is in-memory with thread-safe `RLock` — no database required

---

## 🧪 Verifying Accuracy

1. **Packet count**: Run `tcpdump -i any -c 100` in another terminal;
   Watch Man total should match within a few packets (some may be filtered).

2. **Protocol distribution**: Browse to a website → HTTP/DNS count should rise.

3. **Threat alerts**: In demo mode, wait ~30 s for the DoS spike → alert appears
   with correct count and source IP.

4. **CSV export**: Download `traffic_log.csv` and verify columns match the table.

---

## 📚 Technologies

- **Python 3.10+**
- **Scapy ≥ 2.5** — packet capture
- **Flask ≥ 3.0** — REST API + template serving
- **Chart.js 4.4** — real-time charts (CDN)
- **Orbitron / Rajdhani / Share Tech Mono** — typography (Google Fonts)

---
