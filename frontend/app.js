// SentinelEML 3.0 Frontend Core State & Tab Manager
let selectedFile = null;
let leafletMap = null;
let currentMarker = null;
let currentScanData = null;

// DOM Elements
const dropZone = document.getElementById("drop-zone");
const fileInput = document.getElementById("file-input");
const selectedFileDisplay = document.getElementById("selected-file-display");
const selectedFilename = document.getElementById("selected-filename");
const analyzeBtn = document.getElementById("analyze-btn");
const togglePasteBtn = document.getElementById("toggle-paste-btn");
const pasteSection = document.getElementById("paste-section");
const rawEmlTextarea = document.getElementById("raw-eml-textarea");
const scanProgressBox = document.getElementById("scan-progress-box");
const progressStepText = document.getElementById("progress-step-text");
const progressBar = document.getElementById("progress-bar");
const progressPercent = document.getElementById("progress-percent");
const resultsContainer = document.getElementById("results-container");

// Modals
const complaintModal = document.getElementById("complaint-modal");
const takedownModal = document.getElementById("takedown-modal");

// Preset sample emails
const PRESET_EMAILS = {
  "quishing_phishing.eml": `From: "IT Support Desk" <security-update@office365-verify.com>
To: victim@company.com
Subject: [URGENT] Mandatory MFA Authentication Update - Scan QR Code
Date: Thu, 27 Aug 2026 10:15:00 +0530
Message-ID: <982341.quishing@office365-verify.com>
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html>
<body>
<h2 style="color: #d97706;">Mandatory Security Re-Authentication Required</h2>
<p>Dear Employee,</p>
<p>Your Office 365 MFA security token will expire within <strong>24 hours</strong>. Action is required immediately to prevent account suspension.</p>
<p><strong>Scan the QR Code below with your mobile device camera to update your credentials:</strong></p>
<div style="background:#fff; padding:15px; width:200px; text-align:center; border:2px dashed #d97706;">
    <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==" alt="QR Code Login" width="180" height="180" />
    <p style="font-size:12px; color:#666;">Scan QR Code to Login</p>
</div>
<p style="color:red; font-size:12px;">Do not share this email. Confidential IT Helpdesk notification.</p>
</body>
</html>`,

  "phishing_ceo_fraud.eml": `From: "Apple Executive Office" <tim.cook@apple-executive-support.xyz>
To: victim@company.com
Subject: URGENT: Immediate Action Required - Confidential Acquisition Wire Transfer
Date: Wed, 27 Aug 2026 09:15:00 +0000
Message-ID: <20260827091500.84920.phish@apple-executive-support.xyz>
Return-Path: <bounce-handler@random-spammer-relay.xyz>
Reply-To: <external-attacker-box@darkweb-mail.top>
Authentication-Results: mx.company.com;
 spf=softfail (sender IP 185.220.101.5 is not designated permitted sender) smtp.mailfrom=bounce-handler@random-spammer-relay.xyz;
 dkim=fail (signature did not verify);
 dmarc=fail (p=none dis=none) header.from=apple-executive-support.xyz
Received: from mail-relay-attacker.xyz (mail-relay-attacker.xyz [185.220.101.5])
    by mx.company.com (Postfix) with ESMTPS id 4T093K12
    for <victim@company.com>; Wed, 27 Aug 2026 09:15:05 +0000
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"

<!DOCTYPE html>
<html>
<body>
<p>Hello Team,</p>
<p>We are closing a strictly confidential strategic acquisition today. <strong>Immediate action required</strong> to avoid contract penalties.</p>
<p>Please initiate a wire transfer of $45,000 to our escrow partner immediately.</p>
<p>Click below to verify the invoice credentials and wire routing instructions:</p>
<p><a href="http://185.220.101.5/apple-verify/login.php">https://secure.apple.com/corporate-acquisition-wire</a></p>
<br/>
<p>Best regards,<br/>Tim Cook<br/>Chief Executive Officer</p>
</body>
</html>`,

  "malware_invoice.eml": `From: "Accounts Billing Department" <billing@supplier-quickbooks-portal.top>
To: accounts-payable@organization.com
Subject: FINAL NOTICE: Overdue Invoice #INV-88391 - Account Suspended Pending Payment
Date: Wed, 27 Aug 2026 08:30:12 +0000
Message-ID: <983192039.20260827.malware@supplier-quickbooks-portal.top>
Return-Path: <nobody@185.220.101.5>
Authentication-Results: mailfilter.corp.com;
 spf=fail (IP 185.220.101.5 is unauthorized);
 dkim=fail;
 dmarc=fail
Received: from 185.220.101.5 (unknown [185.220.101.5])
    by mailfilter.corp.com (SpamTitan) with ESMTP id 9A102BF;
    Wed, 27 Aug 2026 08:30:15 +0000
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"

<html>
<body>
<h3>Urgent: Final Notice Regarding Overdue Balance</h3>
<p>Dear Customer,</p>
<p>Your enterprise service account has been suspended due to an unpaid balance on Invoice #INV-88391.</p>
<p>Please download your billing receipt and settle the payment immediately:</p>
<p><a href="http://invoice-download-verify.top/download.php?id=9921">Download Overdue Invoice PDF</a></p>
</body>
</html>`,

  "clean_security_alert.eml": `From: "GitHub Security" <notifications@github.com>
To: developer@organization.com
Subject: [GitHub] Security advisory alert: dependencies updated
Date: Wed, 27 Aug 2026 07:00:00 +0000
Message-ID: <github/repo/security/20260827@github.com>
Return-Path: <notifications@github.com>
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=github.com; s=s20210512;
Authentication-Results: mx.google.com;
 spf=pass (google.com: domain of notifications@github.com designates 192.30.252.0 as permitted sender) smtp.mailfrom=notifications@github.com;
 dkim=pass header.i=@github.com;
 dmarc=pass (p=REJECT sp=REJECT dis=none) header.from=github.com
Received: from smtp.github.com (smtp.github.com [192.30.252.0])
    by mx.google.com with ESMTPS id g12si392819plb.12.2026.08.27.07.00.02
    for <developer@organization.com>; Wed, 27 Aug 2026 07:00:02 +0000
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"

<html>
<body>
<h2>GitHub Security Advisory Notification</h2>
<p>Hello Developer,</p>
<p>One of your repository dependencies has an available patch update. Please review the security advisory details in your dashboard.</p>
<p><a href="https://github.com/advisories">View Security Advisory on GitHub</a></p>
</body>
</html>`
};

document.addEventListener("DOMContentLoaded", () => {
  initDropZone();
  initMap(37.7749, -122.4194);
  fetchHealth();
  fetchHistory();
  fetchComplaints();
});

// Tab Switcher
function switchTab(tabId) {
  const tabs = ["soc-dashboard", "ai-quishing", "ncrp-portal", "dark-tracer", "ai-copilot"];
  tabs.forEach(t => {
    const btn = document.getElementById(`tab-${t}`);
    const view = document.getElementById(`view-${t}`);
    if (btn && view) {
      if (t === tabId) {
        btn.classList.add("text-cyan-400", "border-b-2", "border-cyan-400");
        btn.classList.remove("text-slate-400");
        view.classList.remove("hidden");
      } else {
        btn.classList.remove("text-cyan-400", "border-b-2", "border-cyan-400");
        btn.classList.add("text-slate-400");
        view.classList.add("hidden");
      }
    }
  });

  if (tabId === "dark-tracer") fetchCanaryLogs();
}

function initDropZone() {
  dropZone.addEventListener("click", () => fileInput.click());

  dropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropZone.classList.add("border-cyan-400", "bg-cyan-950/20");
  });

  dropZone.addEventListener("dragleave", () => {
    dropZone.classList.remove("border-cyan-400", "bg-cyan-950/20");
  });

  dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.classList.remove("border-cyan-400", "bg-cyan-950/20");
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileSelected(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener("change", (e) => {
    if (e.target.files && e.target.files.length > 0) {
      handleFileSelected(e.target.files[0]);
    }
  });

  togglePasteBtn.addEventListener("click", () => {
    pasteSection.classList.toggle("hidden");
  });

  analyzeBtn.addEventListener("click", runAnalysis);
}

function handleFileSelected(file) {
  selectedFile = file;
  selectedFilename.innerText = file.name;
  selectedFileDisplay.classList.remove("hidden");
  rawEmlTextarea.value = "";
}

function loadSample(sampleName) {
  const content = PRESET_EMAILS[sampleName];
  if (!content) return;
  
  selectedFile = null;
  selectedFilename.innerText = sampleName;
  selectedFileDisplay.classList.remove("hidden");
  rawEmlTextarea.value = content;
  
  runAnalysis();
}

async function fetchHealth() {
  try {
    const res = await fetch("/api/health");
    if (res.ok) {
      const data = await res.json();
      console.log("Service Online:", data);
    }
  } catch (err) {
    console.warn("Backend starting up...", err);
  }
}

async function runAnalysis() {
  const rawText = rawEmlTextarea.value.trim();
  if (!selectedFile && !rawText) {
    alert("Please drop a .eml file, select a sample preset, or paste email content.");
    return;
  }

  analyzeBtn.disabled = true;
  scanProgressBox.classList.remove("hidden");
  resultsContainer.classList.add("hidden");
  
  const steps = [
    { p: 15, text: "Cyber Leader: Parsing email headers, hops & attachments..." },
    { p: 35, text: "Cyber Leader: Extracting hyperlinks & checking obfuscations..." },
    { p: 55, text: "AI NLP: Scanning inline images for QR Code Quishing payloads..." },
    { p: 75, text: "AI NLP: Classifying social engineering intent & urgency triggers..." },
    { p: 90, text: "CSE 3 & Cyber 2: Querying Threat Intel & Geolocation..." }
  ];

  let currentStep = 0;
  const progressInterval = setInterval(() => {
    if (currentStep < steps.length) {
      progressBar.style.width = steps[currentStep].p + "%";
      progressPercent.innerText = steps[currentStep].p + "%";
      progressStepText.innerHTML = `<i data-lucide="loader-2" class="w-4 h-4 animate-spin"></i> ${steps[currentStep].text}`;
      lucide.createIcons();
      currentStep++;
    }
  }, 300);

  const formData = new FormData();
  if (selectedFile) {
    formData.append("file", selectedFile);
  } else {
    formData.append("raw_content", rawText);
  }

  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      body: formData
    });

    clearInterval(progressInterval);
    progressBar.style.width = "100%";
    progressPercent.innerText = "100%";
    progressStepText.innerText = "Scan Complete!";

    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.detail || "Analysis failed");
    }

    const data = await response.json();
    currentScanData = data;

    setTimeout(() => {
      scanProgressBox.classList.add("hidden");
      analyzeBtn.disabled = false;
      renderScanResults(data);
      renderAiQuishingTab(data);
      fetchHistory();
    }, 300);

  } catch (error) {
    clearInterval(progressInterval);
    scanProgressBox.classList.add("hidden");
    analyzeBtn.disabled = false;
    alert("Error running analysis: " + error.message);
  }
}

function renderScanResults(data) {
  resultsContainer.classList.remove("hidden");
  
  const risk = data.risk_assessment || {};
  const headers = data.parsed_headers?.headers || {};
  const auth = data.parsed_headers?.authentication || {};
  const routing = data.parsed_headers?.routing || {};
  const intel = data.threat_intelligence || {};
  const geo = data.geolocation || {};
  const links = data.extracted_links || {};
  const attachments = data.attachments || {};

  // Setup Export Links
  document.getElementById("export-stix-link").href = `/api/scan/${data.scan_id}/export/stix`;
  document.getElementById("export-csv-link").href = `/api/scan/${data.scan_id}/export/csv`;
  document.getElementById("export-rules-link").href = `/api/scan/${data.scan_id}/export/rules`;

  // Evidence SHA short
  const shaElem = document.getElementById("evidence-sha-short");
  if (shaElem) {
    shaElem.innerText = `SHA256: ${data.scan_id.replace('scan_', '')}...`;
  }

  // 1. Risk Score Card
  const scoreVal = risk.score || 0;
  const scoreElem = document.getElementById("risk-score-val");
  scoreElem.innerText = scoreVal;
  scoreElem.style.color = risk.color || "#ffffff";

  const levelBadge = document.getElementById("threat-level-badge");
  levelBadge.innerText = risk.threat_level || "CLEAN";
  if (risk.threat_level === "MALICIOUS") {
    levelBadge.className = "px-2 py-0.5 rounded text-xs font-bold bg-red-500/20 text-red-400 border border-red-500/40";
  } else if (risk.threat_level === "SUSPICIOUS") {
    levelBadge.className = "px-2 py-0.5 rounded text-xs font-bold bg-amber-500/20 text-amber-400 border border-amber-500/40";
  } else {
    levelBadge.className = "px-2 py-0.5 rounded text-xs font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/40";
  }

  document.getElementById("risk-summary-text").innerText = risk.summary || "";

  // 2. Auth Badges
  renderBadge("spf-badge", auth.spf_status);
  renderBadge("dkim-badge", auth.dkim_status);
  renderBadge("dmarc-badge", auth.dmarc_status);

  const alignDiv = document.getElementById("domain-alignment-status");
  if (auth.domain_mismatch) {
    alignDiv.className = "text-[11px] text-amber-400 flex items-center gap-1 font-medium";
    alignDiv.innerHTML = `<i data-lucide="alert-triangle" class="w-3.5 h-3.5"></i> Domain Mismatch Detected`;
  } else {
    alignDiv.className = "text-[11px] text-emerald-400 flex items-center gap-1 font-medium";
    alignDiv.innerHTML = `<i data-lucide="check" class="w-3.5 h-3.5"></i> Headers Aligned`;
  }

  // 3. Threat Intel Card
  const ipIntel = intel.ip_intelligence || {};
  const domIntel = intel.domain_intelligence || {};
  const summaryIntel = intel.summary || {};

  document.getElementById("abuseipdb-val").innerText = `${ipIntel.abuse_confidence_score || 0}% Abuse (${ipIntel.total_reports || 0} reports)`;
  document.getElementById("vt-domain-val").innerText = `${domIntel.malicious_count || 0} Flagged / ${domIntel.total_engines || 90}`;
  document.getElementById("vt-urls-val").innerText = `${summaryIntel.total_malicious_urls || 0} Malicious Links`;

  // 4. PDF Download Button
  const pdfBtn = document.getElementById("download-pdf-btn");
  pdfBtn.href = `/api/reports/${data.scan_id}/download`;

  // 5. Triggered Risk Signals
  const signalsList = document.getElementById("signals-list");
  const signals = risk.signals || [];
  document.getElementById("signals-count").innerText = signals.length;

  if (signals.length === 0) {
    signalsList.innerHTML = `<div class="p-3 rounded-lg bg-emerald-950/20 border border-emerald-500/30 text-emerald-400 text-xs flex items-center gap-2">
      <i data-lucide="check-circle" class="w-4 h-4"></i> No suspicious signals or anomalies were triggered for this email.
    </div>`;
  } else {
    signalsList.innerHTML = signals.map(s => {
      const sevColor = s.severity === "CRITICAL" || s.severity === "HIGH" ? "border-red-500/40 bg-red-950/20 text-red-400" :
                       s.severity === "MEDIUM" ? "border-amber-500/40 bg-amber-950/20 text-amber-400" :
                       "border-blue-500/40 bg-blue-950/20 text-blue-400";
      return `
        <div class="p-3 rounded-xl bg-slate-900/70 border ${sevColor} space-y-1">
          <div class="flex items-center justify-between">
            <span class="font-bold text-xs text-white flex items-center gap-2">
              <span class="px-1.5 py-0.5 rounded text-[10px] font-mono uppercase bg-slate-800 border border-slate-700">${s.category}</span>
              ${s.name}
            </span>
            <span class="font-mono font-bold text-xs px-2 py-0.5 rounded bg-slate-800 text-white">+${s.weight} Risk</span>
          </div>
          <p class="text-xs text-slate-300 pl-1">${s.description}</p>
        </div>
      `;
    }).join("");
  }

  // 6. Attachments Inspection
  const attachContainer = document.getElementById("attachments-container");
  const attList = attachments.attachments || [];
  document.getElementById("attachments-count").innerText = attList.length;

  if (attList.length === 0) {
    attachContainer.innerHTML = `<div class="p-3 rounded-lg bg-slate-900/50 border border-slate-800 text-slate-400 text-xs">No file attachments detected in this email.</div>`;
  } else {
    attachContainer.innerHTML = attList.map(a => `
      <div class="p-3 rounded-xl bg-slate-900/80 border ${a.is_dangerous ? 'border-red-500/50 bg-red-950/20' : 'border-slate-800'} space-y-1.5 text-xs">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-2 font-bold text-white">
            <i data-lucide="file" class="w-4 h-4 text-rose-400"></i>
            <span>${a.filename}</span>
            <span class="text-slate-400 font-normal">(${a.file_size_formatted})</span>
          </div>
          <span class="px-2 py-0.5 rounded text-[10px] font-bold ${a.is_dangerous ? 'bg-red-500/20 text-red-400 border border-red-500/40' : 'bg-slate-800 text-emerald-400'}">${a.threat_flag}</span>
        </div>
        <div class="font-mono text-[10px] text-slate-400 flex flex-wrap gap-x-4">
          <span><b>SHA256:</b> ${a.sha256}</span>
          <span><b>MD5:</b> ${a.md5}</span>
        </div>
      </div>
    `).join("");
  }

  // 7. Extracted URLs Table
  const urlsTable = document.getElementById("urls-table-body");
  const urlItems = links.urls || [];
  document.getElementById("urls-count").innerText = urlItems.length;

  if (urlItems.length === 0) {
    urlsTable.innerHTML = `<tr><td colspan="3" class="py-4 text-center text-slate-500">No embedded URLs found in body.</td></tr>`;
  } else {
    urlsTable.innerHTML = urlItems.map(u => {
      const flagsText = u.flags && u.flags.length > 0 ? 
        u.flags.map(f => `<span class="inline-block px-1.5 py-0.5 text-[10px] rounded bg-red-500/20 text-red-300 border border-red-500/30 mr-1 mb-1">${f}</span>`).join("") :
        `<span class="text-emerald-400 text-[11px]">Clean</span>`;
      return `
        <tr class="hover:bg-slate-800/40 transition">
          <td class="py-2.5 px-3 text-cyan-300 break-all">${u.defanged_url}</td>
          <td class="py-2.5 px-3 text-slate-400">${u.anchor_text || '<span class="text-slate-600">None</span>'}</td>
          <td class="py-2.5 px-3">${flagsText}</td>
        </tr>
      `;
    }).join("");
  }

  // 8. Origin Geolocation & Leaflet Map
  document.getElementById("geo-ip").innerText = routing.originating_ip || geo.ip || "127.0.0.1";
  document.getElementById("geo-location").innerText = `${geo.city || 'Unknown City'}, ${geo.country || 'Unknown Country'} (${geo.country_code || 'UN'})`;
  document.getElementById("geo-isp").innerText = `${geo.isp || 'N/A'} • ${geo.org || ''}`;
  document.getElementById("geo-asn").innerText = `${geo.asn || 'AS0000'} • ${geo.timezone || 'UTC'}`;

  const lat = geo.lat || 37.7749;
  const lon = geo.lon || -122.4194;
  updateMap(lat, lon, `${geo.city || 'Origin'}, ${geo.country || ''}`, routing.originating_ip || geo.ip);

  // 9. Relay Hops Timeline
  const hopsTimeline = document.getElementById("hops-timeline");
  const hops = routing.hops || [];
  document.getElementById("hops-count").innerText = routing.total_hops || 0;

  if (hops.length === 0) {
    hopsTimeline.innerHTML = `<p class="text-slate-500">No Received headers found.</p>`;
  } else {
    hopsTimeline.innerHTML = hops.map(h => `
      <div class="relative pl-6 pb-2 timeline-item">
        <div class="w-3 h-3 rounded-full bg-cyan-400 border-2 border-slate-900 absolute left-1 top-1"></div>
        <div class="text-[11px] font-semibold text-white">Hop #${h.hop_number}</div>
        <div class="text-[10px] text-slate-400 break-all">${h.raw}</div>
      </div>
    `).join("");
  }

  lucide.createIcons();
}

function renderAiQuishingTab(data) {
  const quishing = data.quishing_analysis || {};
  const aiIntent = data.ai_intent_analysis || {};

  const qBadge = document.getElementById("quishing-badge");
  const qContent = document.getElementById("quishing-results-content");
  const aiContent = document.getElementById("ai-intent-results-content");

  if (quishing.has_quishing_threat) {
    qBadge.innerText = "CRITICAL: Quishing QR Threat Found!";
    qBadge.className = "px-3 py-1 rounded-full text-xs font-bold bg-red-500/20 text-red-300 border border-red-500/50 animate-pulse";

    const qrList = quishing.detected_qr_codes || [];
    qContent.innerHTML = qrList.map(q => `
      <div class="p-3 rounded-lg bg-red-950/30 border border-red-500/40 space-y-1">
        <div class="font-bold text-red-400 flex items-center justify-between">
          <span>${q.threat_name}</span>
          <span>Source: ${q.source}</span>
        </div>
        <div class="font-mono text-[11px] text-cyan-300">Payload: ${q.decoded_payload}</div>
        <p class="text-slate-300">Decoded inline QR code target redirects to fake login credential trap.</p>
      </div>
    `).join("");
  } else {
    qBadge.innerText = "Clean: No Quishing Detected";
    qBadge.className = "px-3 py-1 rounded-full text-xs font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40";
    qContent.innerHTML = `<div class="p-3 rounded-lg bg-slate-950 text-emerald-400 border border-emerald-500/30">No embedded QR code phishing vectors found in body or attachments.</div>`;
  }

  // AI Intent Breakdown
  aiContent.innerHTML = `
    <div class="p-3 rounded-lg bg-slate-950 border border-purple-500/30 space-y-2">
      <div class="font-bold text-purple-300">Primary Attack Vector: ${aiIntent.primary_tactic || 'General Phishing'}</div>
      <p class="text-slate-300">${aiIntent.ai_summary || ''}</p>
      <div class="pt-2 flex flex-wrap gap-1">
        ${(aiIntent.psychological_triggers || []).map(t => `<span class="px-2 py-0.5 rounded bg-purple-900/50 text-purple-200 text-[10px] border border-purple-500/40">${t.name}</span>`).join("")}
      </div>
    </div>
  `;
}

function renderBadge(elemId, status) {
  const badge = document.getElementById(elemId);
  const s = (status || "none").toLowerCase ? status.toLowerCase() : "none";
  
  if (s === "pass") {
    badge.className = "font-bold px-2 py-0.5 rounded text-[11px] bg-emerald-500/20 text-emerald-400 border border-emerald-500/30";
    badge.innerText = "PASS";
  } else if (s === "fail") {
    badge.className = "font-bold px-2 py-0.5 rounded text-[11px] bg-red-500/20 text-red-400 border border-red-500/30";
    badge.innerText = "FAIL";
  } else if (s === "softfail") {
    badge.className = "font-bold px-2 py-0.5 rounded text-[11px] bg-amber-500/20 text-amber-400 border border-amber-500/30";
    badge.innerText = "SOFTFAIL";
  } else {
    badge.className = "font-bold px-2 py-0.5 rounded text-[11px] bg-slate-800 text-slate-400 border border-slate-700";
    badge.innerText = s.toUpperCase();
  }
}

function initMap(lat, lon) {
  const mapContainer = document.getElementById("map");
  if (!mapContainer) return;
  
  leafletMap = L.map('map', { zoomControl: false }).setView([lat, lon], 4);
  
  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
    attribution: '&copy; OpenStreetMap contributors &copy; CARTO',
    subdomains: 'abcd',
    maxZoom: 19
  }).addTo(leafletMap);

  currentMarker = L.marker([lat, lon]).addTo(leafletMap);
}

function updateMap(lat, lon, locationName, ip) {
  if (!leafletMap) return;
  leafletMap.setView([lat, lon], 5);
  
  if (currentMarker) {
    leafletMap.removeLayer(currentMarker);
  }

  currentMarker = L.circleMarker([lat, lon], {
    radius: 9,
    fillColor: "#06b6d4",
    color: "#ffffff",
    weight: 2,
    opacity: 1,
    fillOpacity: 0.9
  }).addTo(leafletMap);

  currentMarker.bindPopup(`<b>Origin IP:</b> ${ip}<br><b>Location:</b> ${locationName}`).openPopup();
  setTimeout(() => leafletMap.invalidateSize(), 300);
}

// -------------------------------------------------------------
// Dark Tracer Canary & Copilot Logic
// -------------------------------------------------------------

async function generateCanaryForCurrentScan() {
  if (!currentScanData) {
    alert("Please run a forensic scan first.");
    return;
  }
  const headers = currentScanData.parsed_headers?.headers || {};
  try {
    const res = await fetch("/api/tracer/canary", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scan_id: currentScanData.scan_id,
        suspect_email: headers.from_address || "suspect@phish.com"
      })
    });
    if (res.ok) {
      alert("Honeypot Canary Token Created!");
      fetchCanaryLogs();
    }
  } catch (err) {
    alert(err.message);
  }
}

async function fetchCanaryLogs() {
  try {
    const res = await fetch("/api/tracer/logs");
    if (!res.ok) return;
    const data = await res.json();
    const container = document.getElementById("canary-list-container");
    
    if (!data.canaries || data.canaries.length === 0) {
      container.innerHTML = `<p class="text-slate-500">No active honeypots deployed yet.</p>`;
      return;
    }

    container.innerHTML = data.canaries.map(c => `
      <div class="p-3 rounded-lg bg-slate-950 border border-purple-500/30 space-y-1">
        <div class="flex justify-between font-bold text-purple-400">
          <span>Token ID: ${c.token_id}</span>
          <span>Hits Logged: ${c.hits_count}</span>
        </div>
        <div class="text-[11px] text-cyan-300">Tracking Link: ${c.tracking_link}</div>
        <div class="text-[11px] text-slate-400">Target Suspect: ${c.suspect_email}</div>
      </div>
    `).join("");

  } catch (err) {
    console.error(err);
  }
}

async function sendCopilotQuery() {
  const input = document.getElementById("copilot-input");
  const query = input.value.trim();
  if (!query) return;

  const chatBox = document.getElementById("copilot-chat-box");
  
  // User message
  chatBox.innerHTML += `
    <div class="p-3 rounded-lg bg-slate-900 border border-slate-700 text-slate-200">
      <span class="text-cyan-400 font-bold block mb-1">👤 Investigator:</span>
      ${query}
    </div>
  `;

  input.value = "";
  chatBox.scrollTop = chatBox.scrollHeight;

  try {
    const res = await fetch("/api/copilot/query", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        query: query,
        scan_id: currentScanData ? currentScanData.scan_id : null
      })
    });

    if (res.ok) {
      const data = await res.json();
      chatBox.innerHTML += `
        <div class="p-3 rounded-lg bg-slate-900 border border-emerald-500/40 text-slate-200 space-y-2">
          <span class="text-emerald-400 font-bold block mb-1">🤖 Sentinel AI Assistant:</span>
          <div>${data.response.replace(/\n/g, '<br/>')}</div>
        </div>
      `;
      chatBox.scrollTop = chatBox.scrollHeight;
    }
  } catch (err) {
    console.error(err);
  }
}

// -------------------------------------------------------------
// Cyber Crime Complaint Modal Logic
// -------------------------------------------------------------

function openComplaintModal() {
  if (!currentScanData) {
    alert("Please run a forensic scan first.");
    return;
  }

  const headers = currentScanData.parsed_headers?.headers || {};
  const routing = currentScanData.parsed_headers?.routing || {};
  const geo = currentScanData.geolocation || {};

  document.getElementById("modal-suspect-ip").innerText = routing.originating_ip || geo.ip || "127.0.0.1";
  document.getElementById("modal-suspect-loc").innerText = `${geo.city || 'N/A'}, ${geo.country || 'Unknown'}`;
  document.getElementById("modal-suspect-sender").innerText = `${headers.from_name ? headers.from_name + ' ' : ''}<${headers.from_address || ''}>`;
  document.getElementById("modal-evidence-sha").innerText = `SHA256: ${currentScanData.scan_id.replace('scan_', '')}...`;

  document.getElementById("complaint-success-box").classList.add("hidden");
  document.getElementById("complaint-form").classList.remove("hidden");

  complaintModal.classList.remove("hidden");
  lucide.createIcons();
}

function closeComplaintModal() {
  complaintModal.classList.add("hidden");
}

async function submitCyberComplaint(event) {
  event.preventDefault();
  if (!currentScanData) return;

  const btn = document.getElementById("submit-complaint-btn");
  btn.disabled = true;
  btn.innerText = "Submitting to NCRP State Cyber Cell...";

  const payload = {
    scan_id: currentScanData.scan_id,
    victim_name: document.getElementById("victim-name").value,
    victim_email: document.getElementById("victim-email").value,
    victim_phone: document.getElementById("victim-phone").value,
    incident_type: document.getElementById("incident-type").value,
    financial_loss: parseFloat(document.getElementById("financial-loss").value) || 0.0,
    narrative: document.getElementById("incident-narrative").value
  };

  try {
    const res = await fetch("/api/complaints/ncrp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Failed to file complaint");
    }

    const complaintResult = await res.json();

    document.getElementById("complaint-form").classList.add("hidden");
    const successBox = document.getElementById("complaint-success-box");
    successBox.classList.remove("hidden");

    document.getElementById("generated-case-id").innerText = complaintResult.case_id;
    document.getElementById("modal-download-complaint-btn").href = complaintResult.download_url;

    fetchComplaints();
    lucide.createIcons();

  } catch (err) {
    alert("Error filing complaint: " + err.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<i data-lucide="file-plus" class="w-4 h-4"></i> Submit NCRP FIR & Generate Dossier`;
    lucide.createIcons();
  }
}

// -------------------------------------------------------------
// ISP Takedown Modal Logic
// -------------------------------------------------------------

async function openTakedownModal() {
  if (!currentScanData) {
    alert("Please run a forensic scan first.");
    return;
  }

  try {
    const res = await fetch(`/api/scan/${currentScanData.scan_id}/takedown`);
    if (!res.ok) throw new Error("Failed to load takedown notice.");
    const data = await res.json();

    document.getElementById("takedown-text-area").value = data.email_body;
    takedownModal.classList.remove("hidden");
    lucide.createIcons();
  } catch (err) {
    alert(err.message);
  }
}

function closeTakedownModal() {
  takedownModal.classList.add("hidden");
}

function copyTakedownEmail() {
  const textArea = document.getElementById("takedown-text-area");
  textArea.select();
  navigator.clipboard.writeText(textArea.value);
  alert("Takedown notice copied to clipboard!");
}

async function blockCurrentThreatIP() {
  if (!currentScanData) {
    alert("Please run a forensic scan first.");
    return;
  }
  const ip = currentScanData.parsed_headers?.routing?.originating_ip || currentScanData.geolocation?.ip || "185.220.101.5";
  const domain = currentScanData.parsed_headers?.headers?.from_domain || "";

  try {
    const res = await fetch("/api/block/firewall", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip, domain })
    });
    if (!res.ok) throw new Error("Failed to apply firewall block.");
    const data = await res.json();
    alert(`Firewall Block Applied for Malicious IP: ${ip}!\n\nExecution Status: ${data.execution_status.message || 'Block Rule Active'}`);
  } catch (err) {
    alert(err.message);
  }
}

// -------------------------------------------------------------
// History & Filed Complaints Fetchers
// -------------------------------------------------------------

async function fetchComplaints() {
  try {
    const res = await fetch("/api/complaints");
    if (!res.ok) return;
    const data = await res.json();
    const tableBody = document.getElementById("complaints-table-body");
    const badgeCount = document.getElementById("cases-badge-count");
    if (badgeCount) badgeCount.innerText = data.total || 0;

    if (!data.complaints || data.complaints.length === 0) {
      tableBody.innerHTML = `<tr><td colspan="7" class="text-center py-6 text-slate-500">No Cyber Crime complaints filed yet.</td></tr>`;
      return;
    }

    tableBody.innerHTML = data.complaints.map(c => `
      <tr class="hover:bg-slate-800/40 transition">
        <td class="py-2.5 px-3 font-mono font-bold text-red-400">${c.case_id}</td>
        <td class="py-2.5 px-3 font-medium text-white">${c.victim_name}<br/><span class="text-[10px] text-slate-400">${c.victim_email}</span></td>
        <td class="py-2.5 px-3 text-slate-300">${c.incident_type}</td>
        <td class="py-2.5 px-3 font-mono text-[11px] text-slate-400">${c.suspect_ip}<br/><span class="text-[10px] text-slate-500 truncate block max-w-xs">${c.suspect_email}</span></td>
        <td class="py-2.5 px-3 font-mono text-emerald-400">$${c.financial_loss.toLocaleString()}</td>
        <td class="py-2.5 px-3"><span class="px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/20 text-red-400 border border-red-500/40">NCRP FILED</span></td>
        <td class="py-2.5 px-3 text-right">
          <a href="${c.download_url}" target="_blank" class="px-2.5 py-1 rounded bg-red-950/60 hover:bg-red-900/60 border border-red-500/40 text-red-300 text-[11px] font-bold transition inline-flex items-center gap-1">
            <i data-lucide="download" class="w-3 h-3"></i> NCRP FIR PDF
          </a>
        </td>
      </tr>
    `).join("");

    lucide.createIcons();
  } catch (err) {
    console.error("Failed to fetch complaints", err);
  }
}

async function fetchHistory() {
  try {
    const res = await fetch("/api/history");
    if (!res.ok) return;
    const data = await res.json();
    const historyTable = document.getElementById("history-table-body");
    
    if (!data.history || data.history.length === 0) {
      historyTable.innerHTML = `<tr><td colspan="6" class="text-center py-6 text-slate-500">No previous scans found.</td></tr>`;
      return;
    }

    historyTable.innerHTML = data.history.map(item => {
      const levelColor = item.threat_level === "MALICIOUS" ? "bg-red-500/20 text-red-400 border-red-500/30" :
                         item.threat_level === "SUSPICIOUS" ? "bg-amber-500/20 text-amber-400 border-amber-500/30" :
                         "bg-emerald-500/20 text-emerald-400 border-emerald-500/30";
      const dateStr = item.uploaded_at ? new Date(item.uploaded_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', month: 'short', day: 'numeric' }) : "";
      
      return `
        <tr class="hover:bg-slate-800/40 transition">
          <td class="py-2.5 px-3 text-slate-400 font-mono text-[11px]">${dateStr}</td>
          <td class="py-2.5 px-3 font-medium text-white max-w-xs truncate">${item.subject || item.filename}</td>
          <td class="py-2.5 px-3 text-slate-300 font-mono text-[11px]">${item.sender || 'N/A'}</td>
          <td class="py-2.5 px-3 font-bold font-mono">${item.risk_score}/100</td>
          <td class="py-2.5 px-3">
            <span class="px-2 py-0.5 rounded text-[10px] font-bold border ${levelColor}">${item.threat_level}</span>
          </td>
          <td class="py-2.5 px-3 text-right">
            <a href="${item.report_url}" target="_blank" class="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 text-[11px] font-semibold transition inline-flex items-center gap-1">
              <i data-lucide="download" class="w-3 h-3"></i> PDF
            </a>
          </td>
        </tr>
      `;
    }).join("");

    lucide.createIcons();
  } catch (err) {
    console.error("Failed to load history", err);
  }
}
