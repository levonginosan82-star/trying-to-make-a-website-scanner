// ASMS dashboard — fetch mock JSON, render KPIs, trend, critical list, and table.

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const SEVERITY_STYLE = {
  critical: { pill: "bg-red-500/15 text-red-300 ring-1 ring-inset ring-red-500/40", dot: "bg-red-500" },
  high:     { pill: "bg-orange-500/15 text-orange-300 ring-1 ring-inset ring-orange-500/40", dot: "bg-orange-500" },
  medium:   { pill: "bg-amber-500/15 text-amber-300 ring-1 ring-inset ring-amber-500/40", dot: "bg-amber-500" },
  low:      { pill: "bg-sky-500/15 text-sky-300 ring-1 ring-inset ring-sky-500/40", dot: "bg-sky-500" },
  info:     { pill: "bg-slate-500/15 text-slate-300 ring-1 ring-inset ring-slate-500/40", dot: "bg-slate-500" },
};
const STATUS_LABEL = {
  open: "Open",
  in_progress: "In progress",
  fixed: "Fixed",
  false_positive: "False positive",
  accepted_risk: "Accepted risk",
  wont_fix: "Won't fix",
};

const $ = (id) => document.getElementById(id);

function severityBadge(sev) {
  const s = SEVERITY_STYLE[sev] ?? SEVERITY_STYLE.info;
  return `<span class="inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium ${s.pill}">
    <span class="h-1.5 w-1.5 rounded-full ${s.dot}"></span>${sev}
  </span>`;
}

function statusBadge(status) {
  const tone = status === "open" ? "bg-red-500/10 text-red-300"
              : status === "in_progress" ? "bg-amber-500/10 text-amber-300"
              : status === "fixed" ? "bg-emerald-500/10 text-emerald-300"
              : "bg-slate-500/10 text-slate-300";
  return `<span class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${tone}">${STATUS_LABEL[status] ?? status}</span>`;
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (ch) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]
  ));
}

function formatTime(iso) {
  try {
    const d = new Date(iso);
    return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  } catch {
    return iso;
  }
}

function relativeTime(iso) {
  const then = new Date(iso).getTime();
  const diff = Math.max(0, Date.now() - then);
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function bandFor(score) {
  if (score >= 85) return { text: "Healthy",  cls: "bg-emerald-500/15 text-emerald-300", colour: "rgb(16 185 129)" };
  if (score >= 65) return { text: "Watch",    cls: "bg-amber-500/15 text-amber-300",     colour: "rgb(245 158 11)" };
  if (score >= 40) return { text: "At risk",  cls: "bg-orange-500/15 text-orange-300",   colour: "rgb(249 115 22)" };
  return                    { text: "Critical", cls: "bg-red-500/15 text-red-300",       colour: "rgb(239 68 68)"  };
}

function renderScore(score) {
  $("score-value").textContent = score;
  const arc = $("score-arc");
  const circumference = 2 * Math.PI * 52;
  arc.setAttribute("stroke-dasharray", circumference.toFixed(2));
  arc.setAttribute("stroke-dashoffset", (circumference * (1 - score / 100)).toFixed(2));
  const band = bandFor(score);
  arc.setAttribute("stroke", band.colour);
  const badge = $("score-band");
  badge.textContent = band.text;
  badge.className = "rounded-full px-2 py-0.5 text-xs font-medium " + band.cls;
}

function renderKpis(breakdown) {
  $("kpi-critical").textContent = breakdown.critical ?? 0;
  $("kpi-high").textContent     = breakdown.high     ?? 0;
  $("kpi-medium").textContent   = breakdown.medium   ?? 0;
  $("kpi-low").textContent      = breakdown.low      ?? 0;
  $("kpi-info").textContent     = breakdown.info     ?? 0;
}

function renderCompliance(items) {
  $("compliance-list").innerHTML = items.map((c) => `
    <li>
      <div class="flex justify-between text-xs text-slate-300">
        <span>${escapeHtml(c.name)}</span>
        <span class="tabular-nums">${c.coverage}%</span>
      </div>
      <div class="mt-1 h-1.5 rounded-full bg-slate-800 overflow-hidden">
        <div class="h-full bg-gradient-to-r from-emerald-400 to-cyan-400" style="width:${c.coverage}%"></div>
      </div>
    </li>
  `).join("");
}

function renderCriticalList(vulns) {
  const top = [...vulns]
    .filter((v) => v.severity === "critical")
    .sort((a, b) => (b.cvss ?? 0) - (a.cvss ?? 0))
    .slice(0, 5);
  const list = $("critical-list");
  if (top.length === 0) {
    list.innerHTML = `<li class="px-6 py-6 text-sm text-slate-400">No critical threats — nice work.</li>`;
    return;
  }
  list.innerHTML = top.map((v) => `
    <li class="px-6 py-4 flex items-center gap-4">
      <div class="shrink-0 w-14 text-center">
        <div class="text-lg font-bold text-red-300 tabular-nums">${v.cvss?.toFixed(1) ?? "—"}</div>
        <div class="text-[10px] uppercase tracking-wider text-slate-500">CVSS</div>
      </div>
      <div class="flex-1 min-w-0">
        <div class="flex items-center gap-2">
          ${severityBadge(v.severity)}
          <span class="text-sm font-medium truncate">${escapeHtml(v.title)}</span>
        </div>
        <div class="mt-1 text-xs text-slate-400 truncate">
          ${escapeHtml(v.asset)} · <code class="text-slate-300">${escapeHtml(v.url)}</code>
          ${v.parameter && v.parameter !== "n/a" ? ` · <span class="text-slate-500">param</span> <code class="text-slate-300">${escapeHtml(v.parameter)}</code>` : ""}
        </div>
      </div>
      <div class="text-xs text-slate-400 text-right">
        <div>${statusBadge(v.status)}</div>
        <div class="mt-1">${relativeTime(v.discovered)}</div>
      </div>
    </li>
  `).join("");
}

function renderTable(vulns) {
  const tbody = $("vuln-tbody");
  if (vulns.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="px-6 py-6 text-center text-slate-400">No findings match the current filters.</td></tr>`;
    $("row-count").textContent = "0 findings";
    return;
  }
  const sorted = [...vulns].sort((a, b) =>
    (SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]) || ((b.cvss ?? 0) - (a.cvss ?? 0))
  );
  tbody.innerHTML = sorted.map((v) => `
    <tr class="hover:bg-slate-800/40">
      <td class="px-6 py-3">${severityBadge(v.severity)}</td>
      <td class="px-6 py-3">
        <div class="font-medium text-slate-100">${escapeHtml(v.title)}</div>
        <div class="text-xs text-slate-500">${escapeHtml(v.type)}</div>
      </td>
      <td class="px-6 py-3 text-slate-300">${escapeHtml(v.asset)}</td>
      <td class="px-6 py-3">
        <div class="truncate max-w-[28rem] text-slate-200"><code>${escapeHtml(v.url)}</code></div>
        <div class="text-xs text-slate-500">${escapeHtml(v.parameter)}</div>
      </td>
      <td class="px-6 py-3 tabular-nums">${v.cvss?.toFixed(1) ?? "—"}</td>
      <td class="px-6 py-3">${statusBadge(v.status)}</td>
      <td class="px-6 py-3 text-slate-400 text-xs">${formatTime(v.discovered)}</td>
    </tr>
  `).join("");
  $("row-count").textContent = `${vulns.length} finding${vulns.length === 1 ? "" : "s"}`;
}

let trendChart;
function renderTrend(trend) {
  const ctx = $("trend-chart").getContext("2d");
  const gradient = ctx.createLinearGradient(0, 0, 0, 90);
  gradient.addColorStop(0, "rgba(16,185,129,0.4)");
  gradient.addColorStop(1, "rgba(16,185,129,0)");
  if (trendChart) trendChart.destroy();
  trendChart = new Chart(ctx, {
    type: "line",
    data: {
      labels: trend.map((p) => p.date.slice(5)),
      datasets: [{
        data: trend.map((p) => p.score),
        borderColor: "rgb(16,185,129)",
        backgroundColor: gradient,
        fill: true,
        tension: 0.35,
        pointRadius: 0,
        borderWidth: 2,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false }, tooltip: { intersect: false, mode: "index" } },
      scales: {
        x: { display: false },
        y: { display: false, min: 0, max: 100 },
      },
    },
  });
}

let allVulns = [];
function applyFilters() {
  const sev = $("filter-severity").value;
  const status = $("filter-status").value;
  const q = $("search").value.trim().toLowerCase();
  const filtered = allVulns.filter((v) => {
    if (sev && v.severity !== sev) return false;
    if (status && v.status !== status) return false;
    if (q) {
      const hay = `${v.title} ${v.asset} ${v.url} ${v.parameter} ${v.type}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
  renderTable(filtered);
}

/**
 * Try to load live data from the ASMS API; fall back to the bundled sample.json
 * so the static dashboard keeps working even when the API isn't running.
 */
const PARAMS = new URLSearchParams(window.location.search);
const API_BASE = PARAMS.get("api") || window.ASMS_API_BASE || "";
const ORG_SLUG = PARAMS.get("org") || window.ASMS_ORG || "acme";

async function fetchLive() {
  if (!API_BASE) return null;
  try {
    const [scoreRes, vulnRes] = await Promise.all([
      fetch(`${API_BASE}/api/v1/organizations/${ORG_SLUG}/security-score`),
      fetch(`${API_BASE}/api/v1/organizations/${ORG_SLUG}/vulnerabilities?limit=500`),
    ]);
    if (!scoreRes.ok || !vulnRes.ok) return null;
    const score = await scoreRes.json();
    const vulns = await vulnRes.json();
    return {
      source: "live",
      organization: { name: "ASMS", assets_total: "—", scans_today: "—" },
      security_score: score.security_score,
      severity_breakdown: {
        critical: score.open_critical,
        high: score.open_high,
        medium: score.open_medium,
        low: score.open_low,
        info: score.open_info,
      },
      vulnerabilities: vulns.map((v) => ({
        id: v.id,
        type: v.type,
        title: v.title,
        severity: v.severity,
        cvss: v.cvss,
        url: v.url,
        parameter: v.parameter,
        status: v.status,
        asset: v.asset_id,
        discovered: v.first_seen_at,
      })),
      // The compliance + trend datasets aren't yet wired through the API;
      // borrow them from the mock JSON so the rest of the dashboard renders.
      _need_mock_supplements: true,
    };
  } catch (err) {
    console.warn("ASMS API unreachable, falling back to mock data:", err);
    return null;
  }
}

async function fetchMock() {
  const res = await fetch("data/sample.json");
  if (!res.ok) throw new Error(`Failed to load data: ${res.status}`);
  const data = await res.json();
  data.source = "mock";
  return data;
}

async function load() {
  const mock = await fetchMock();
  const live = await fetchLive();
  const data = live ? { ...live } : mock;
  if (live && live._need_mock_supplements) {
    data.compliance = mock.compliance;
    data.trend = mock.trend;
  }

  $("org-name").textContent = (data.organization?.name ?? "ASMS") + " — Security Command Center";
  $("org-meta").textContent =
    `${data.organization?.assets_total ?? "—"} assets monitored · ${data.organization?.scans_today ?? "—"} scans today` +
    (data.source === "live" ? " · live data" : "");
  $("last-refresh").textContent = new Date().toLocaleTimeString();

  renderScore(data.security_score);
  renderKpis(data.severity_breakdown);
  renderCompliance(data.compliance);
  renderCriticalList(data.vulnerabilities);
  renderTrend(data.trend);

  allVulns = data.vulnerabilities;
  applyFilters();

  ["filter-severity", "filter-status", "search"].forEach((id) => {
    $(id).addEventListener("input", applyFilters);
  });
}

load().catch((err) => {
  console.error(err);
  const main = document.querySelector("main");
  if (main) {
    main.innerHTML = `<div class="rounded-xl border border-red-500/40 bg-red-500/10 p-6 text-red-200">Failed to load dashboard data: ${err.message}. If you opened this file directly via <code>file://</code>, run it through a local server: <code>python -m http.server --directory asms/dashboard 8080</code>.</div>`;
  }
});
