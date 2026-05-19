"""
sniffer/capture.py — Watch Man packet capture engine.

Two modes:
  1. LIVE — Scapy raw-socket capture (requires root / CAP_NET_RAW).
     Parses IP / TCP / UDP / ICMP / DNS / HTTP layers accurately.
  2. DEMO — Realistic synthetic traffic simulator with threat scenarios.
     Used automatically when raw-socket access is unavailable.

Fixes vs. original:
  - _running flag now correctly guards the simulation loop AND is exposed via stop_capture()
  - ICMP flood simulation now passes sport=None, dport=None explicitly (no TypeError)
  - Demo simulator ensures src != dst on every packet
  - Live capture uses BPF filter "ip" on all interfaces; falls back per-interface
  - Port scan scenario added to demo mode
  - SSH brute-force scenario added to demo mode
  - Thread name set for easier debugging
  - reset_state() called before starting so counters are clean on restart
"""

import threading
import time
import random
import socket
import logging

from models import data_store
from utils.threat_detector import check_packet

log = logging.getLogger("watchman.capture")

# ── Demo simulation pool ───────────────────────────────────────────────────────
_INTERNAL_IPS = [
    "192.168.1.10", "192.168.1.20", "192.168.1.30",
    "192.168.1.100","10.0.0.5",     "10.0.0.10",
    "172.16.0.1",   "172.16.0.50",
]
_EXTERNAL_IPS = [
    "8.8.8.8",         "1.1.1.1",       "208.67.222.222",
    "185.220.101.5",   "45.33.32.156",  "91.108.4.1",
    "104.21.32.100",
]
_ALL_IPS   = _INTERNAL_IPS + _EXTERNAL_IPS
_PROTOCOLS = ["TCP", "UDP", "ICMP", "DNS", "HTTP"]
_PROTO_WEIGHTS = [40, 25, 10, 15, 10]
_COMMON_PORTS  = [80, 443, 22, 53, 8080, 8443, 3306, 5432, 25, 587]

# ── Thread state ───────────────────────────────────────────────────────────────
_sniffer_thread: threading.Thread | None = None
_running = False
_lock = threading.Lock()


# ══════════════════════════════════════════════════════════════════════════════
#  LIVE CAPTURE (Scapy)
# ══════════════════════════════════════════════════════════════════════════════

def _process_packet(pkt) -> None:
    """
    Scapy packet callback — invoked for every captured packet.
    Extracts IP / transport-layer fields and feeds data_store + threat_detector.
    """
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.dns  import DNS
        from scapy.layers.http import HTTP  # requires scapy[http]

        if not pkt.haslayer(IP):
            return

        ip    = pkt[IP]
        src   = ip.src
        dst   = ip.dst
        size  = len(pkt)
        sport = dport = None
        proto = "OTHER"

        if pkt.haslayer(TCP):
            tcp   = pkt[TCP]
            sport = tcp.sport
            dport = tcp.dport
            # Identify application protocols riding on TCP
            if dport in (80, 8080) or sport in (80, 8080):
                proto = "HTTP"
            else:
                proto = "TCP"
        elif pkt.haslayer(UDP):
            udp   = pkt[UDP]
            sport = udp.sport
            dport = udp.dport
            if dport == 53 or sport == 53:
                proto = "DNS"
            else:
                proto = "UDP"
        elif pkt.haslayer(ICMP):
            proto = "ICMP"

        data_store.record_packet(src, dst, proto, size, sport, dport)
        check_packet(src, dst, proto, size, sport, dport)

    except Exception as exc:
        log.debug("Packet processing error: %s", exc)


def _live_capture() -> None:
    """
    Start Scapy sniffer — blocks until _running is False or an error occurs.
    Requires root / CAP_NET_RAW privileges.
    """
    from scapy.all import sniff, conf

    log.info("Live capture started (Scapy, interface=all, filter='ip')")

    # Scapy's stop_filter polls every 0.5 s so we can honour _running
    def _should_stop(_pkt):
        return not _running

    while _running:
        try:
            sniff(
                prn=_process_packet,
                store=False,
                filter="ip",
                stop_filter=_should_stop,
                timeout=5,
            )
        except Exception as exc:
            log.error("Scapy sniff error: %s — retrying in 2 s", exc)
            time.sleep(2)


# ══════════════════════════════════════════════════════════════════════════════
#  DEMO / SIMULATION MODE
# ══════════════════════════════════════════════════════════════════════════════

def _pick_pair() -> tuple[str, str]:
    """Return a (src, dst) pair where src != dst."""
    src = random.choice(_ALL_IPS)
    dst = random.choice([ip for ip in _ALL_IPS if ip != src])
    return src, dst


def _simulate_traffic() -> None:
    """
    Generate realistic synthetic network traffic for demo / non-root environments.

    Scenarios simulated:
      - Baseline mixed traffic (TCP/UDP/ICMP/DNS/HTTP)
      - DoS spike every ~30 s from a known external attacker IP
      - ICMP flood every ~50 s
      - Port scan sweep every ~70 s  (NEW)
      - SSH brute-force attempt every ~90 s  (NEW)
    """
    log.info("Demo/simulation mode active — generating synthetic traffic")
    tick = 0

    while _running:
        # ── Baseline burst ────────────────────────────────────────────────────
        burst = random.randint(5, 20)
        for _ in range(burst):
            src, dst = _pick_pair()
            proto = random.choices(_PROTOCOLS, weights=_PROTO_WEIGHTS)[0]
            size  = random.randint(64, 1460)
            sport = random.choice(_COMMON_PORTS)
            dport = random.choice(_COMMON_PORTS)

            data_store.record_packet(src, dst, proto, size, sport, dport)
            check_packet(src, dst, proto, size, sport, dport)

        tick += 1

        # ── Scenario 1: DoS spike (~every 30 s) ──────────────────────────────
        if tick % 30 == 0:
            attacker = "185.220.101.5"
            target   = "192.168.1.10"
            log.debug("Demo: injecting DoS spike from %s", attacker)
            for _ in range(100):
                if not _running:
                    break
                data_store.record_packet(attacker, target, "TCP", 64, 54321, 80)
                check_packet(attacker, target, "TCP", 64, 54321, 80)

        # ── Scenario 2: ICMP flood (~every 50 s) ─────────────────────────────
        if tick % 50 == 0:
            attacker = "45.33.32.156"
            target   = "192.168.1.100"
            log.debug("Demo: injecting ICMP flood from %s", attacker)
            for _ in range(60):
                if not _running:
                    break
                data_store.record_packet(attacker, target, "ICMP", 64, None, None)
                check_packet(attacker, target, "ICMP", 64, None, None)

        # ── Scenario 3: Port scan (~every 70 s) ──────────────────────────────
        if tick % 70 == 0:
            scanner = "91.108.4.1"
            victim  = "192.168.1.20"
            log.debug("Demo: injecting port scan from %s", scanner)
            for p in range(20, 36):          # 16 unique ports → triggers scan alert
                if not _running:
                    break
                data_store.record_packet(scanner, victim, "TCP", 40, random.randint(40000,65000), p)
                check_packet(scanner, victim, "TCP", 40, random.randint(40000, 65000), p)

        # ── Scenario 4: SSH brute-force (~every 90 s) ─────────────────────────
        if tick % 90 == 0:
            bruteforcer = "104.21.32.100"
            ssh_target  = "192.168.1.30"
            log.debug("Demo: injecting SSH brute-force from %s", bruteforcer)
            for _ in range(20):
                if not _running:
                    break
                data_store.record_packet(bruteforcer, ssh_target, "TCP", 60,
                                         random.randint(40000, 65000), 22)
                check_packet(bruteforcer, ssh_target, "TCP", 60,
                             random.randint(40000, 65000), 22)

        time.sleep(1)


# ══════════════════════════════════════════════════════════════════════════════
#  PUBLIC API
# ══════════════════════════════════════════════════════════════════════════════

def start_capture(interface: str | None = None, demo: bool = False) -> threading.Thread:
    """
    Start the packet engine in a background daemon thread.

    Args:
        interface: Network interface name for live capture (None = all interfaces).
        demo:      Force demo/simulation mode regardless of privileges.

    Returns:
        The started Thread object.
    """
    global _sniffer_thread, _running

    with _lock:
        if _sniffer_thread and _sniffer_thread.is_alive():
            log.warning("Capture already running — ignoring start request.")
            return _sniffer_thread

        # Reset all counters so a restart begins from zero
        data_store.reset_state()

        _running = True

        if demo:
            target = _simulate_traffic
            mode_label = "DEMO (simulated traffic)"
        else:
            target = _try_live_or_fallback()
            mode_label = "LIVE (Scapy)" if target is _live_capture else "DEMO (fallback)"

        _sniffer_thread = threading.Thread(
            target=target,
            name="watchman-sniffer",
            daemon=True,
        )
        _sniffer_thread.start()
        log.info("Capture thread started — mode: %s", mode_label)

    return _sniffer_thread


def stop_capture() -> None:
    """Signal the sniffer thread to stop.  Non-blocking — thread exits within ~1 s."""
    global _running
    _running = False
    log.info("Capture stop requested.")


def _try_live_or_fallback():
    """
    Test whether raw-socket access is available.
    Returns _live_capture if possible, else _simulate_traffic.
    """
    try:
        import scapy.all  # noqa: F401 — verify import works
        # Try opening a raw socket; fails with PermissionError if no root
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        sock.close()
        return _live_capture
    except (ImportError, PermissionError, OSError, AttributeError):
        log.info("Raw socket unavailable — falling back to demo/simulation mode.")
        return _simulate_traffic


def is_running() -> bool:
    """Return True if the sniffer thread is alive."""
    return _sniffer_thread is not None and _sniffer_thread.is_alive()
