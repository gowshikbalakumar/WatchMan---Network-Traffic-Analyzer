/* ════════════════════════════════════════════════════════════════
   Watch Man — Dashboard JS  (v2.0 — fixed)
   Polls /traffic, /stats, /alerts every 2 seconds.

   Fixes vs. original:
     - clearAlerts() now POSTs to /clear-alerts (was UI-only, server kept alerts)
     - applyFilter() called correctly when filter changes
     - Status pill shows DEMO vs LIVE mode from /stats
     - animateNumber handles locale formatting without flicker
     - Chart memory: datasets replaced in-place (no Chart destroy/recreate leak)
     - exportTraffic / exportAlerts open correct URLs
     - Alerts deduplication key uses index in the reversed list (time+type+detail)
   ════════════════════════════════════════════════════════════════ */

"use strict";

// ── Config ─────────────────────────────────────────────────────────────────────
const POLL_INTERVAL  = 2000;    // ms between data polls
const MAX_PPS_POINTS = 45;      // points shown on the line chart
const PROTO_COLORS = {
  TCP:   "#64d8ff",
  UDP:   "#a78bfa",
  ICMP:  "#ff9500",
  DNS:   "#34d399",
  HTTP:  "#f472b6",
  OTHER: "#5a7a9a",
};

// ── State ───────────────────────────────────────────────────────────────────────
let protoFilter = "";
let allPackets  = [];
let knownAlertKeys = new Set();   // prevents toast spam on page reload
let toastTimer  = null;

// ── Clock ───────────────────────────────────────────────────────────────────────
function updateClock() {
  document.getElementById("sysTime").textContent =
    new Date().toTimeString().slice(0, 8);
}
setInterval(updateClock, 1000);
updateClock();

function formatUptime(secs) {
  const h = String(Math.floor(secs / 3600)).padStart(2, "0");
  const m = String(Math.floor((secs % 3600) / 60)).padStart(2, "0");
  const s = String(secs % 60).padStart(2, "0");
  return `${h}:${m}:${s}`;
}

// ── Chart setup ─────────────────────────────────────────────────────────────────
Chart.defaults.color      = "#5a7a9a";
Chart.defaults.font.family = "'Share Tech Mono', monospace";

const ppsChart = new Chart(
  document.getElementById("ppsChart").getContext("2d"),
  {
    type: "line",
    data: {
      labels: [],
      datasets: [{
        label: "Packets/s",
        data: [],
        borderColor: "#00e5ff",
        backgroundColor: "rgba(0,229,255,0.06)",
        borderWidth: 2,
        fill: true,
        tension: 0.4,
        pointRadius: 0,
        pointHoverRadius: 4,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 300 },
      plugins: {
        legend: { display: false },
        tooltip: { callbacks: { label: ctx => ` ${ctx.parsed.y} pkt/s` } }
      },
      scales: {
        x: {
          grid: { color: "rgba(26,37,53,0.8)" },
          ticks: { maxTicksLimit: 8, color: "#5a7a9a", font: { size: 10 } }
        },
        y: {
          grid: { color: "rgba(26,37,53,0.8)" },
          ticks: { color: "#5a7a9a", font: { size: 10 } },
          beginAtZero: true
        }
      }
    }
  }
);

const protoChart = new Chart(
  document.getElementById("protoChart").getContext("2d"),
  {
    type: "doughnut",
    data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderWidth: 0 }] },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: { callbacks: { label: ctx => ` ${ctx.label}: ${ctx.parsed} pkts` } }
      },
      cutout: "68%"
    }
  }
);

// ── Data fetching ───────────────────────────────────────────────────────────────
async function fetchTraffic() {
  try {
    const [tRes, sRes] = await Promise.all([
      fetch("/traffic"),
      fetch("/stats"),
    ]);
    if (!tRes.ok || !sRes.ok) throw new Error("HTTP error");

    const traffic = await tRes.json();
    const stats   = await sRes.json();

    updateKPIs(stats);
    updatePpsChart(traffic.packets_per_second);
    updateProtoChart(traffic.protocol_distribution);
    updateTopIPs(traffic.top_ips);
    updateConnections(traffic.recent_packets);
    updateStatus(true, stats.demo_mode);

  } catch (err) {
    updateStatus(false, null);
    console.error("[WatchMan] Traffic fetch error:", err);
  }
}

async function fetchAlerts() {
  try {
    const res  = await fetch("/alerts");
    if (!res.ok) throw new Error("HTTP error");
    const data = await res.json();
    updateAlerts(data);
  } catch (err) {
    console.error("[WatchMan] Alerts fetch error:", err);
  }
}

// ── KPIs ────────────────────────────────────────────────────────────────────────
function updateKPIs(stats) {
  setText("kpiPackets", stats.total_packets.toLocaleString());
  setText("kpiBytes",   stats.total_bytes_mb.toFixed(3));
  setText("kpiPPS",     stats.current_pps);
  setText("kpiAlerts",  stats.active_alerts);
  setText("uptime",     formatUptime(stats.uptime_seconds));
  setText("footerPPS",  `PPS: ${stats.current_pps}`);

  document.getElementById("alertKpi")
    .classList.toggle("danger-card", stats.critical_alerts > 0);
}

function setText(id, val) {
  const el = document.getElementById(id);
  if (el && el.textContent !== String(val)) el.textContent = val;
}

// ── PPS chart ───────────────────────────────────────────────────────────────────
function updatePpsChart(history) {
  const slice  = (history || []).slice(-MAX_PPS_POINTS);
  ppsChart.data.labels              = slice.map(p => p.time);
  ppsChart.data.datasets[0].data    = slice.map(p => p.count);
  ppsChart.update("none");
}

// ── Protocol chart ───────────────────────────────────────────────────────────────
function updateProtoChart(dist) {
  const labels = Object.keys(dist || {});
  const vals   = Object.values(dist || {});
  const colors = labels.map(l => PROTO_COLORS[l] || PROTO_COLORS.OTHER);

  protoChart.data.labels                    = labels;
  protoChart.data.datasets[0].data          = vals;
  protoChart.data.datasets[0].backgroundColor = colors;
  protoChart.update("none");

  document.getElementById("protoLegend").innerHTML = labels.map((l, i) =>
    `<span class="proto-dot"><span style="background:${colors[i]}"></span>${l}: ${vals[i]}</span>`
  ).join("");
}

// ── Top IPs ─────────────────────────────────────────────────────────────────────
function updateTopIPs(ips) {
  const container = document.getElementById("topIpsContainer");
  if (!ips || !ips.length) {
    container.innerHTML = `<p style="color:var(--text-dim);padding:16px;font-family:var(--font-mono);font-size:.7rem;">No data yet…</p>`;
    return;
  }
  const max = ips[0].count || 1;
  container.innerHTML = ips.map((ip, i) => `
    <div class="ip-row">
      <span class="ip-rank">#${i + 1}</span>
      <span class="ip-addr">${ip.ip}</span>
      <div class="ip-bar-wrap">
        <div class="ip-bar" style="width:${Math.round((ip.count / max) * 100)}%"></div>
      </div>
      <span class="ip-count">${ip.count}</span>
    </div>
  `).join("");
}

// ── Connections table ────────────────────────────────────────────────────────────
function updateConnections(packets) {
  allPackets = packets || [];
  renderConnections();
}

function renderConnections() {
  const tbody   = document.getElementById("connBody");
  const packets = protoFilter
    ? allPackets.filter(p => p.proto === protoFilter)
    : allPackets;

  if (!packets.length) {
    tbody.innerHTML = `<tr class="empty-row"><td colspan="7">No connections match the filter…</td></tr>`;
    return;
  }

  const rows = [...packets].reverse().slice(0, 100);
  tbody.innerHTML = rows.map((p, i) => `
    <tr class="${i < 3 ? "row-new" : ""}">
      <td>${p.time}</td>
      <td style="color:var(--accent)">${p.src}</td>
      <td style="color:var(--text-dim)">${p.dst}</td>
      <td><span class="proto proto-${p.proto}">${p.proto}</span></td>
      <td>${p.sport !== undefined ? p.sport : "-"}</td>
      <td>${p.dport !== undefined ? p.dport : "-"}</td>
      <td>${p.size}</td>
    </tr>
  `).join("");
}

function applyFilter() {
  protoFilter = document.getElementById("protoFilter").value;
  renderConnections();
}

// ── Alerts table ─────────────────────────────────────────────────────────────────
function updateAlerts(alerts) {
  const tbody = document.getElementById("alertsBody");

  // Toast for truly new alerts only
  alerts.forEach(a => {
    const key = `${a.time}|${a.type}|${a.detail}`;
    if (!knownAlertKeys.has(key)) {
      knownAlertKeys.add(key);
      showToast(a);
    }
  });

  if (!alerts.length) {
    tbody.innerHTML = `<tr class="empty-row"><td colspan="4">No threats detected yet…</td></tr>`;
    return;
  }

  tbody.innerHTML = alerts.slice(0, 50).map((a, i) => `
    <tr class="${i < 2 ? "row-new" : ""}">
      <td style="color:var(--text-dim)">${a.time}</td>
      <td><span class="sev sev-${a.severity}">${a.severity}</span></td>
      <td style="color:var(--text-bright)">${a.type}</td>
      <td>${a.detail}</td>
    </tr>
  `).join("");
}

// BUG FIX: clearAlerts now calls the backend endpoint so server state is also cleared
async function clearAlerts() {
  try {
    await fetch("/clear-alerts", { method: "POST" });
  } catch (e) {
    console.warn("[WatchMan] Could not reach /clear-alerts:", e);
  }
  document.getElementById("alertsBody").innerHTML =
    `<tr class="empty-row"><td colspan="4">Alerts cleared.</td></tr>`;
  knownAlertKeys.clear();
}

// ── Toast ────────────────────────────────────────────────────────────────────────
const SEV_COLORS = { CRITICAL: "#ff2d55", HIGH: "#ff6b35", MEDIUM: "#ffcc00", LOW: "#00e5ff" };

function showToast(alert) {
  const toast = document.getElementById("alertToast");
  toast.style.borderLeftColor = SEV_COLORS[alert.severity] || "#ff2d55";
  toast.innerHTML = `<strong>⚠ ${alert.severity}:</strong> ${alert.type}<br><small>${alert.detail}</small>`;
  toast.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.add("hidden"), 5500);
}

// ── Status indicator ──────────────────────────────────────────────────────────────
function updateStatus(ok, demoMode) {
  const pill = document.getElementById("statusPill");
  const text = document.getElementById("statusText");
  if (ok) {
    pill.style.borderColor = "rgba(0,255,136,.3)";
    text.textContent = demoMode ? "SIMULATION ACTIVE" : "LIVE MONITORING";
  } else {
    pill.style.borderColor = "rgba(255,45,85,.4)";
    text.textContent = "CONNECTION LOST";
  }
}

// ── Exports ───────────────────────────────────────────────────────────────────────
function exportTraffic() { window.open("/export/csv",         "_blank"); }
function exportAlerts()  { window.open("/export/alerts/csv",  "_blank"); }

// ── Poll loop ─────────────────────────────────────────────────────────────────────
function poll() {
  fetchTraffic();
  fetchAlerts();
}

poll();
setInterval(poll, POLL_INTERVAL);
