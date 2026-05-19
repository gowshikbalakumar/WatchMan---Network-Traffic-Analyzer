"""
models/data_store.py — Watch Man shared in-memory state.

Thread-safe store for all captured network data.
All reads/writes are protected by a single reentrant lock.

Fixes vs. original:
  - current_second_count is now included in get_snapshot() under the lock (was a race condition)
  - ip_packet_counts is pruned to prevent unbounded growth
  - get_snapshot() returns a complete, accurate copy
  - add_alert() and clear_alerts() both lock correctly
  - start_time is reset by reset_state() called from start_capture()
"""

import threading
import time
import logging
from collections import defaultdict, deque

log = logging.getLogger("watchman.store")

# ── Thread lock ────────────────────────────────────────────────────────────────
_lock = threading.RLock()   # reentrant — safe if same thread calls nested helpers

# ── Rolling per-second history (last 60 seconds) ──────────────────────────────
MAX_HISTORY = 60
_pps_history: deque = deque(maxlen=MAX_HISTORY)   # [{time, count}, ...]
_cur_second_count: int = 0
_last_second_ts: int = 0

# ── Protocol counters ──────────────────────────────────────────────────────────
_protocol_counts: dict = defaultdict(int)

# ── IP tracking — bounded to top 500 to prevent memory leak ───────────────────
_ip_packet_counts: dict = defaultdict(int)
MAX_TRACKED_IPS = 500

# ── Recent packets ring buffer ─────────────────────────────────────────────────
MAX_RECENT = 500
_recent_packets: deque = deque(maxlen=MAX_RECENT)

# ── Alerts ring buffer ─────────────────────────────────────────────────────────
MAX_ALERTS = 200
_alerts: deque = deque(maxlen=MAX_ALERTS)

# ── Global counters ────────────────────────────────────────────────────────────
_total_packets: int = 0
_total_bytes: int = 0
_start_time: float = 0.0


# ══════════════════════════════════════════════════════════════════════════════
#  INIT / RESET
# ══════════════════════════════════════════════════════════════════════════════

def reset_state() -> None:
    """Reset all counters — called once at startup by start_capture()."""
    global _cur_second_count, _last_second_ts, _total_packets, _total_bytes, _start_time

    with _lock:
        _pps_history.clear()
        _protocol_counts.clear()
        _ip_packet_counts.clear()
        _recent_packets.clear()
        _alerts.clear()

        _total_packets = 0
        _total_bytes = 0
        _cur_second_count = 0
        _last_second_ts = int(time.time())
        _start_time = time.time()

    log.info("Data store reset.")


# ══════════════════════════════════════════════════════════════════════════════
#  WRITE OPERATIONS
# ══════════════════════════════════════════════════════════════════════════════

def record_packet(
    src_ip: str,
    dst_ip: str,
    protocol: str,
    size: int,
    sport: int | None = None,
    dport: int | None = None,
) -> None:
    """
    Record one captured packet.
    Called from the sniffer thread — must be fast and lock-safe.
    """
    global _cur_second_count, _last_second_ts, _total_packets, _total_bytes

    now_ts = int(time.time())
    now_str = time.strftime("%H:%M:%S")

    with _lock:
        # ── Advance the per-second bucket when the clock ticks ────────────
        if now_ts != _last_second_ts:
            # Flush the just-completed second into history
            _pps_history.append({
                "time":  time.strftime("%H:%M:%S", time.localtime(_last_second_ts)),
                "count": _cur_second_count,
            })
            _cur_second_count = 0
            _last_second_ts = now_ts

        _cur_second_count += 1
        _total_packets += 1
        _total_bytes += max(size, 0)    # guard against negative values

        # ── Protocol counter ───────────────────────────────────────────────
        _protocol_counts[protocol] += 1

        # ── IP tracking — prune when we exceed the cap ────────────────────
        _ip_packet_counts[src_ip] += 1
        if len(_ip_packet_counts) > MAX_TRACKED_IPS:
            # Remove the lowest-count IP to keep the dict bounded
            min_ip = min(_ip_packet_counts, key=_ip_packet_counts.__getitem__)
            del _ip_packet_counts[min_ip]

        # ── Recent packets table ───────────────────────────────────────────
        _recent_packets.append({
            "src":   src_ip,
            "dst":   dst_ip,
            "proto": protocol,
            "size":  size,
            "sport": sport if sport is not None else "-",
            "dport": dport if dport is not None else "-",
            "time":  now_str,
        })


def add_alert(alert_type: str, detail: str, severity: str = "MEDIUM") -> None:
    """Append a threat detection alert.  severity ∈ {LOW, MEDIUM, HIGH, CRITICAL}."""
    with _lock:
        entry = {
            "type":     alert_type,
            "detail":   detail,
            "severity": severity,
            "time":     time.strftime("%H:%M:%S"),
        }
        _alerts.append(entry)

    log.warning("[ALERT] [%s] %s — %s", severity, alert_type, detail)


def clear_alerts() -> None:
    """Remove all stored alerts (called by the /clear-alerts API endpoint)."""
    with _lock:
        _alerts.clear()
    log.info("Alerts cleared via API.")


# ══════════════════════════════════════════════════════════════════════════════
#  READ OPERATIONS
# ══════════════════════════════════════════════════════════════════════════════

def get_snapshot() -> dict:
    """
    Return a consistent copy of all traffic stats for the REST API.
    current_pps now correctly reflects the in-progress second count.
    """
    with _lock:
        uptime_secs = int(time.time() - _start_time) if _start_time else 0
        top_ips = sorted(
            _ip_packet_counts.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:10]

        # Return last 100 packets newest-first
        recent = list(_recent_packets)[-100:]

        return {
            "total_packets":         _total_packets,
            "total_bytes":           _total_bytes,
            "uptime_seconds":        uptime_secs,
            "packets_per_second":    list(_pps_history),          # full history
            "current_pps":           _cur_second_count,           # in-progress second
            "protocol_distribution": dict(_protocol_counts),
            "top_ips":               [{"ip": ip, "count": cnt} for ip, cnt in top_ips],
            "recent_packets":        recent,
        }


def get_alerts() -> list:
    """Return a copy of the alerts list (newest first)."""
    with _lock:
        return list(reversed(_alerts))
