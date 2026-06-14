/**
 * script.js — VulnScan frontend logic
 * Handles scan requests, result rendering, history, export, and PDF generation.
 */

"use strict";

// ─────────────────────────────────────────────────────────────────────────────
// DOM references
// ─────────────────────────────────────────────────────────────────────────────
const urlInput       = document.getElementById("urlInput");
const scanBtn        = document.getElementById("scanBtn");
const scanBtnText    = document.getElementById("scanBtnText");
const scanSpinner    = document.getElementById("scanSpinner");
const inputError     = document.getElementById("inputError");
const progressWrap   = document.getElementById("progressWrap");
const progressBar    = document.getElementById("progressBar");
const progressLabel  = document.getElementById("progressLabel");
const progressPct    = document.getElementById("progressPct");
const resultsArea    = document.getElementById("resultsArea");
const findingsAccordion = document.getElementById("findingsAccordion");
const noFindingsMsg  = document.getElementById("noFindingsMsg");
const historyTableBody = document.getElementById("historyTableBody");
const historyEmpty   = document.getElementById("historyEmpty");
const exportJsonBtn  = document.getElementById("exportJsonBtn");
const downloadPdfBtn = document.getElementById("downloadPdfBtn");

// Stores the latest scan result for export
let lastScanResult = null;

// ─────────────────────────────────────────────────────────────────────────────
// Risk helpers
// ─────────────────────────────────────────────────────────────────────────────
const RISK_ICON = {
  Critical: "bi-exclamation-octagon-fill",
  High:     "bi-exclamation-triangle-fill",
  Medium:   "bi-exclamation-circle-fill",
  Low:      "bi-info-circle-fill",
};

const RISK_COLOR_CLASS = {
  Critical: "vs-risk-critical",
  High:     "vs-risk-high",
  Medium:   "vs-risk-medium",
  Low:      "vs-risk-low",
};

const SEV_DOT_COLOR = {
  Critical: "#ef4444",
  High:     "#f97316",
  Medium:   "#f59e0b",
  Low:      "#22c55e",
};

function riskBadgeHTML(risk) {
  const cls  = RISK_COLOR_CLASS[risk] || "vs-risk-low";
  const icon = RISK_ICON[risk] || "bi-info-circle-fill";
  return `<span class="vs-risk-badge ${cls}"><i class="bi ${icon}"></i>${risk}</span>`;
}

function scoreColor(label) {
  return { Safe: "#22c55e", Low: "#22c55e", Medium: "#f59e0b", High: "#f97316", Critical: "#ef4444" }[label] || "#fff";
}

// ─────────────────────────────────────────────────────────────────────────────
// Progress bar simulation
// ─────────────────────────────────────────────────────────────────────────────
const SCAN_STEPS = [
  [10, "Connecting to target…"],
  [25, "Checking HTTPS enforcement…"],
  [38, "Analysing security headers…"],
  [52, "Testing cookie attributes…"],
  [63, "Probing for injection vectors…"],
  [74, "Checking for open redirects…"],
  [84, "Scanning directory listing…"],
  [92, "Detecting info disclosure…"],
  [97, "Calculating risk score…"],
];

let progressTimer = null;

function startProgress() {
  progressWrap.classList.remove("d-none");
  let step = 0;

  function tick() {
    if (step >= SCAN_STEPS.length) return;
    const [pct, label] = SCAN_STEPS[step];
    setProgress(pct, label);
    step++;
    progressTimer = setTimeout(tick, 800 + Math.random() * 400);
  }
  tick();
}

function setProgress(pct, label) {
  progressBar.style.width = pct + "%";
  progressLabel.textContent = label;
  progressPct.textContent   = pct + "%";
}

function finishProgress() {
  clearTimeout(progressTimer);
  setProgress(100, "Scan complete.");
  setTimeout(() => progressWrap.classList.add("d-none"), 1200);
}

function resetProgress() {
  clearTimeout(progressTimer);
  progressWrap.classList.add("d-none");
  progressBar.style.width = "0%";
}

// ─────────────────────────────────────────────────────────────────────────────
// Scan trigger
// ─────────────────────────────────────────────────────────────────────────────
scanBtn.addEventListener("click", triggerScan);
urlInput.addEventListener("keydown", e => { if (e.key === "Enter") triggerScan(); });

async function triggerScan() {
  const raw = urlInput.value.trim();
  if (!raw) { showInputError("Please enter a URL."); return; }

  clearInputError();
  setScanningState(true);
  startProgress();
  resultsArea.classList.add("d-none");

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: raw }),
    });

    const data = await res.json();
    finishProgress();

    if (!data.success) {
      showInputError(data.error || "Scan failed. Please check the URL and try again.");
    } else {
      lastScanResult = data;
      renderResults(data);
      refreshHistory();
    }
  } catch (err) {
    finishProgress();
    showInputError("Network error. Is the server running?");
    console.error(err);
  } finally {
    setScanningState(false);
  }
}

function setScanningState(scanning) {
  scanBtn.disabled      = scanning;
  urlInput.disabled     = scanning;
  scanBtnText.textContent = scanning ? "Scanning…" : "Start Scan";
  scanSpinner.classList.toggle("d-none", !scanning);
}

function showInputError(msg) {
  inputError.textContent = msg;
  inputError.classList.remove("d-none");
}

function clearInputError() {
  inputError.textContent = "";
  inputError.classList.add("d-none");
}

// ─────────────────────────────────────────────────────────────────────────────
// Render results
// ─────────────────────────────────────────────────────────────────────────────
function renderResults(data) {
  // Metrics row
  const scoreEl = document.getElementById("metricScore");
  scoreEl.textContent = data.risk_score;
  scoreEl.style.color = scoreColor(data.risk_label);

  const levelEl = document.getElementById("metricLevel");
  levelEl.textContent = data.risk_label;
  levelEl.style.color = scoreColor(data.risk_label);

  document.getElementById("metricTotal").textContent = data.total_vulnerabilities;
  document.getElementById("metricTime").textContent  = data.timestamp.replace(" UTC", "");

  // Severity breakdown
  const breakdown = document.getElementById("severityBreakdown");
  breakdown.innerHTML = "";
  const counts = data.severity_counts || {};
  ["Critical", "High", "Medium", "Low"].forEach(level => {
    const col = document.createElement("div");
    col.className = "col-6 col-md-3";
    col.innerHTML = `
      <div class="vs-sev-pill">
        <span class="vs-sev-dot" style="background:${SEV_DOT_COLOR[level]}"></span>
        <div>
          <div class="vs-sev-count">${counts[level] ?? 0}</div>
          <div class="vs-sev-label">${level}</div>
        </div>
      </div>`;
    breakdown.appendChild(col);
  });

  // Findings accordion
  const badge = document.getElementById("findingsBadge");
  badge.textContent = data.findings.length;
  findingsAccordion.innerHTML = "";

  if (data.findings.length === 0) {
    noFindingsMsg.classList.remove("d-none");
  } else {
    noFindingsMsg.classList.add("d-none");
    data.findings.forEach((f, idx) => {
      findingsAccordion.insertAdjacentHTML("beforeend", buildFindingItem(f, idx));
    });
  }

  // Recommendations (top 5 unique fixes from highest-risk findings)
  const sorted = [...data.findings].sort((a, b) => {
    const order = { Critical: 4, High: 3, Medium: 2, Low: 1 };
    return (order[b.risk] || 0) - (order[a.risk] || 0);
  });
  const rList = document.getElementById("recommendationsList");
  rList.innerHTML = "";
  const seen = new Set();
  sorted.slice(0, 7).forEach(f => {
    if (seen.has(f.name)) return;
    seen.add(f.name);
    const li = document.createElement("li");
    li.innerHTML = `<strong>${f.name}:</strong> ${escapeHtml(f.fix)}`;
    rList.appendChild(li);
  });

  if (sorted.length === 0) {
    rList.innerHTML = '<li>No issues found — your security posture looks good!</li>';
  }

  resultsArea.classList.remove("d-none");
  // Smooth scroll to results
  setTimeout(() => resultsArea.scrollIntoView({ behavior: "smooth", block: "start" }), 100);
}

function buildFindingItem(finding, idx) {
  const collapseId = `finding-${idx}`;
  return `
    <div class="accordion-item">
      <h2 class="accordion-header">
        <button class="accordion-button collapsed vs-accordion-btn" type="button"
          data-bs-toggle="collapse" data-bs-target="#${collapseId}">
          <span class="me-2">${riskBadgeHTML(finding.risk)}</span>
          <span class="text-truncate">${escapeHtml(finding.name)}</span>
          <span class="ms-auto me-3 text-muted small flex-shrink-0">${escapeHtml(finding.category || "")}</span>
        </button>
      </h2>
      <div id="${collapseId}" class="accordion-collapse collapse">
        <div class="accordion-body">
          <div class="vs-finding-section">
            <div class="vs-finding-label">Description</div>
            <div class="vs-finding-text">${escapeHtml(finding.description)}</div>
          </div>
          <div class="vs-finding-section">
            <div class="vs-finding-label">Recommended Fix</div>
            <div class="vs-fix-box">${escapeHtml(finding.fix)}</div>
          </div>
        </div>
      </div>
    </div>`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Scan history
// ─────────────────────────────────────────────────────────────────────────────
async function refreshHistory() {
  try {
    const res = await fetch("/api/history");
    const data = await res.json();
    renderHistory(data.history || []);
  } catch (e) {
    console.warn("Could not refresh history:", e);
  }
}

function renderHistory(entries) {
  if (!entries.length) {
    historyEmpty.style.display = "";
    return;
  }
  historyEmpty.style.display = "none";
  historyTableBody.innerHTML = "";

  entries.forEach(entry => {
    const cls = RISK_COLOR_CLASS[entry.risk_label] || "vs-risk-low";
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${entry.id}</td>
      <td class="url-cell" title="${escapeHtml(entry.url)}">${escapeHtml(entry.url)}</td>
      <td><span class="vs-risk-badge ${cls}">${entry.risk_label}</span></td>
      <td><span style="font-family:var(--vs-mono)">${entry.risk_score}</span></td>
      <td>${entry.total_vulnerabilities}</td>
      <td class="text-muted">${entry.timestamp}</td>`;
    historyTableBody.appendChild(tr);
  });
}

// Load history on page load
refreshHistory();

// ─────────────────────────────────────────────────────────────────────────────
// Export JSON
// ─────────────────────────────────────────────────────────────────────────────
exportJsonBtn.addEventListener("click", () => {
  if (!lastScanResult) return;
  const blob = new Blob([JSON.stringify(lastScanResult, null, 2)], { type: "application/json" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href     = url;
  a.download = `vulnscan_${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
});

// ─────────────────────────────────────────────────────────────────────────────
// Download PDF (print-to-PDF approach)
// ─────────────────────────────────────────────────────────────────────────────
downloadPdfBtn.addEventListener("click", () => {
  if (!lastScanResult) return;
  const d = lastScanResult;

  const findingsHtml = d.findings.map(f => `
    <div style="margin-bottom:18px;padding:12px;border:1px solid #ddd;border-radius:6px">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
        <span style="font-weight:700">${escapeHtml(f.name)}</span>
        <span style="padding:2px 8px;border-radius:12px;font-size:12px;font-weight:600;
          background:${severityBg(f.risk)};color:${severityFg(f.risk)}">${f.risk}</span>
      </div>
      <p style="margin:0 0 6px;color:#444;font-size:13px">${escapeHtml(f.description)}</p>
      <p style="margin:0;font-size:12px;color:#666"><strong>Fix:</strong> ${escapeHtml(f.fix)}</p>
    </div>`).join("") || "<p>No vulnerabilities found.</p>";

  const html = `<!DOCTYPE html><html><head><title>VulnScan Report</title>
    <style>
      body{font-family:Arial,sans-serif;margin:40px;color:#111}
      h1{color:#00d4aa}
      table{border-collapse:collapse;width:100%;margin-bottom:24px}
      td,th{border:1px solid #ddd;padding:8px 12px;font-size:13px}
      th{background:#f5f5f5}
    </style></head><body>
    <h1>VulnScan Report</h1>
    <table>
      <tr><th>Target URL</th><td>${escapeHtml(d.url)}</td></tr>
      <tr><th>Scan Time</th><td>${d.timestamp}</td></tr>
      <tr><th>Risk Level</th><td>${d.risk_label} (${d.risk_score}/100)</td></tr>
      <tr><th>Total Findings</th><td>${d.total_vulnerabilities}</td></tr>
    </table>
    <h2>Findings</h2>${findingsHtml}
    <p style="color:#888;font-size:11px;margin-top:30px">
      Generated by VulnScan — for authorised security testing only.
    </p>
    </body></html>`;

  const win = window.open("", "_blank");
  win.document.write(html);
  win.document.close();
  win.print();
});

function severityBg(risk) {
  return { Critical:"#fde8e8", High:"#fff0e6", Medium:"#fef9e7", Low:"#e8fdf0" }[risk] || "#f5f5f5";
}
function severityFg(risk) {
  return { Critical:"#c0392b", High:"#e67e22", Medium:"#d4ac0d", Low:"#1e8449" }[risk] || "#333";
}

// ─────────────────────────────────────────────────────────────────────────────
// Utilities
// ─────────────────────────────────────────────────────────────────────────────
function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
