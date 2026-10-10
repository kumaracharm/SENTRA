document.addEventListener("DOMContentLoaded", () => {
    // Configurable API base URL (supports cross-origin & separate host deployments)
    const API_BASE = window.LOGSHIELD_API_BASE || localStorage.getItem("LOGSHIELD_API_BASE") || "";
    let currentData = null;
    let pollInterval = null;

    // DOM Elements
    const elSyncStatus = document.getElementById("sync-status");
    const btnRefresh = document.getElementById("btn-refresh");
    const btnResetApi = document.getElementById("btn-reset-api");

    // Ingestion Elements
    const btnSelectFile = document.getElementById("btn-select-file");
    const logFileInput = document.getElementById("log-file-input");
    const selectedFileName = document.getElementById("selected-file-name");
    const uploadModeSelect = document.getElementById("upload-mode-select");
    const btnUploadFile = document.getElementById("btn-upload-file");
    const uploadStatusMsg = document.getElementById("upload-status-msg");
    const fileDropArea = document.getElementById("file-drop-area");

    // KPI Elements
    const kpiTotalEvents = document.getElementById("kpi-total-events");
    const kpiCriticalAlerts = document.getElementById("kpi-critical-alerts");
    const kpiHighRisk = document.getElementById("kpi-high-risk");
    const kpiAnomalous = document.getElementById("kpi-anomalous");
    const kpiAvgRisk = document.getElementById("kpi-avg-risk");

    // Risk Elements
    const riskScoreVal = document.getElementById("risk-score-value");
    const riskSeverityBadge = document.getElementById("risk-severity-badge");
    const confidenceVal = document.getElementById("confidence-val");
    const riskGaugeOuter = document.querySelector(".risk-circle-outer");

    // Breakdown Elements
    const scoreRule = document.getElementById("score-rule");
    const scoreAi = document.getElementById("score-ai");
    const scoreCorr = document.getElementById("score-corr");
    const barRule = document.getElementById("bar-rule");
    const barAi = document.getElementById("bar-ai");
    const barCorr = document.getElementById("bar-corr");

    // Panels
    const reasonsContainer = document.getElementById("reasons-container");
    const reasonsCount = document.getElementById("reasons-count");
    const timelineContainer = document.getElementById("timeline-container");
    const incidentsCount = document.getElementById("incidents-count");
    const streamContainer = document.getElementById("stream-container");

    // Table Elements
    const searchInput = document.getElementById("search-input");
    const filterType = document.getElementById("filter-type");
    const eventsTbody = document.getElementById("events-tbody");
    const tableCount = document.getElementById("table-count");

    // Event Listeners
    btnRefresh.addEventListener("click", fetchAnalysis);
    btnResetApi.addEventListener("click", resetLogs);
    searchInput.addEventListener("input", renderEventsTable);
    filterType.addEventListener("change", renderEventsTable);

    // Upload Listeners
    if (btnSelectFile && logFileInput) {
        btnSelectFile.addEventListener("click", () => logFileInput.click());
        logFileInput.addEventListener("change", handleFileSelected);
    }
    if (btnUploadFile) {
        btnUploadFile.addEventListener("click", uploadSelectedFile);
    }
    if (fileDropArea) {
        fileDropArea.addEventListener("dragover", (e) => {
            e.preventDefault();
            fileDropArea.style.borderColor = "var(--color-medium)";
        });
        fileDropArea.addEventListener("dragleave", () => {
            fileDropArea.style.borderColor = "var(--border-light)";
        });
        fileDropArea.addEventListener("drop", (e) => {
            e.preventDefault();
            fileDropArea.style.borderColor = "var(--border-light)";
            if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
                logFileInput.files = e.dataTransfer.files;
                handleFileSelected();
            }
        });
    }

    function handleFileSelected() {
        if (logFileInput.files && logFileInput.files.length > 0) {
            const file = logFileInput.files[0];
            selectedFileName.textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
            btnUploadFile.disabled = false;
        } else {
            selectedFileName.textContent = "No file selected";
            btnUploadFile.disabled = true;
        }
    }

    async function uploadSelectedFile() {
        if (!logFileInput.files || logFileInput.files.length === 0) return;
        const file = logFileInput.files[0];

        const mode = uploadModeSelect ? uploadModeSelect.value : "overwrite";
        const formData = new FormData();
        formData.append("file", file);

        if (uploadStatusMsg) {
            uploadStatusMsg.textContent = "Parsing & Ingesting log file...";
            uploadStatusMsg.className = "upload-status";
        }

        try {
            const res = await fetch(`${API_BASE}/api/upload?mode=${encodeURIComponent(mode)}`, {
                method: "POST",
                body: formData
            });

            if (!res.ok) {
                const errData = await res.json().catch(() => ({ detail: "Upload failed" }));
                throw new Error(errData.detail || `HTTP ${res.status}`);
            }

            const data = await res.json();
            currentData = data;
            renderDashboard(data);

            if (uploadStatusMsg) {
                uploadStatusMsg.textContent = `✓ Ingested ${data.total_events} log events from '${file.name}'.`;
                uploadStatusMsg.className = "upload-status success";
            }

            logFileInput.value = "";
            selectedFileName.textContent = "No file selected";
            btnUploadFile.disabled = true;

        } catch (err) {
            console.error("Upload error:", err);
            if (uploadStatusMsg) {
                uploadStatusMsg.textContent = `❌ Ingestion Error: ${err.message}`;
                uploadStatusMsg.className = "upload-status error";
            }
        }
    }

    // Initial Fetch & Start Polling (every 3s)
    fetchAnalysis();
    pollInterval = setInterval(fetchAnalysis, 3000);

    async function fetchAnalysis() {
        try {
            const res = await fetch(`${API_BASE}/api/analyze`);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            currentData = data;
            renderDashboard(data);
            if (elSyncStatus) elSyncStatus.textContent = "LIVE MONITORING";
        } catch (err) {
            console.error("Fetch error:", err);
            if (elSyncStatus) elSyncStatus.textContent = "SYNC ERROR";
        }
    }

    async function resetLogs() {
        if (!confirm("Are you sure you want to clear all logs?")) return;
        try {
            const res = await fetch(`${API_BASE}/api/reset`, { method: "POST" });
            if (res.ok) {
                fetchAnalysis();
            }
        } catch (err) {
            alert("Error clearing logs: " + err.message);
        }
    }

    function renderDashboard(data) {
        // 1. Update KPI Cards
        kpiTotalEvents.textContent = data.total_events || 0;
        kpiCriticalAlerts.textContent = data.critical_alerts || 0;
        kpiHighRisk.textContent = data.high_risk_events || 0;
        kpiAnomalous.textContent = data.anomalous_events_count || 0;
        kpiAvgRisk.textContent = data.average_risk || 0;

        // 2. Risk Score & Gauge
        const riskSummary = data.risk_summary || {};
        const score = riskSummary.risk_score || 0;
        const severity = riskSummary.severity || "LOW";
        const confidence = riskSummary.confidence || "100% (HIGH)";

        riskScoreVal.textContent = score;
        confidenceVal.textContent = confidence;

        riskSeverityBadge.textContent = severity;
        riskSeverityBadge.className = `badge badge-${severity.toLowerCase()}`;

        // Set Gauge conic gradient percentage & color
        let gaugeColor = "var(--color-low)";
        if (severity === "MEDIUM") gaugeColor = "var(--color-medium)";
        if (severity === "HIGH") gaugeColor = "var(--color-high)";
        if (severity === "CRITICAL") gaugeColor = "var(--color-critical)";

        riskGaugeOuter.style.setProperty("--gauge-pct", score);
        riskGaugeOuter.style.setProperty("--gauge-color", gaugeColor);

        // 3. Breakdown Metrics
        const breakdown = data.detection_breakdown || { rule_score: 0, ai_score: 0, correlation_bonus: 0 };
        scoreRule.textContent = breakdown.rule_score;
        scoreAi.textContent = breakdown.ai_score;
        scoreCorr.textContent = breakdown.correlation_bonus;

        barRule.style.width = `${Math.min(100, (breakdown.rule_score / 60) * 100)}%`;
        barAi.style.width = `${Math.min(100, (breakdown.ai_score / 25) * 100)}%`;
        barCorr.style.width = `${Math.min(100, (breakdown.correlation_bonus / 25) * 100)}%`;

        // 4. Source Health & Evidence Gaps
        renderSources(data.sources_health || []);

        // 5. Why This Was Flagged (Reasons)
        renderReasons(riskSummary.reasons || []);

        // 6. Correlated Attack Timelines & Incident Case Files
        renderIncidents(data.incidents || []);

        // 7. Live Stream & Events Table
        renderStream(data.events || []);
        renderEventsTable();
    }

    function renderSources(sources) {
        const container = document.getElementById("sources-container");
        const countLbl = document.getElementById("sources-count");
        if (!container) return;

        if (countLbl) countLbl.textContent = `${sources.length} Tracked Source(s)`;

        if (!sources || sources.length === 0) {
            container.innerHTML = `<div class="empty-state">No source telemetry recorded. Send JSON events to /api/ingest to track sources.</div>`;
            return;
        }

        container.innerHTML = sources.map(s => {
            const isGap = s.is_evidence_gap;
            const statusClass = isGap ? "badge-critical" : "badge-low";
            const icon = isGap ? "⚠️" : "🟢";
            const borderStyle = isGap ? "border: 1px solid var(--border-critical); background: var(--bg-critical);" : "border: 1px solid var(--border-color); background: var(--bg-card);";

            return `
                <div class="source-card" style="padding: 12px 16px; border-radius: 6px; ${borderStyle} min-width: 220px; flex: 1;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                        <strong style="font-family: var(--font-mono);">${escapeHtml(s.source_ip)}</strong>
                        <span class="badge ${statusClass}">${icon} ${escapeHtml(s.status)}</span>
                    </div>
                    <div style="font-size: 11px; color: var(--text-secondary);">
                        <div>Events: <strong>${s.event_count}</strong></div>
                        <div>Silence Duration: <strong>${s.silence_seconds}s</strong></div>
                        <div>Last Active: <span class="text-muted">${formatTime(s.last_seen)}</span></div>
                    </div>
                </div>
            `;
        }).join("");
    }

    function renderReasons(reasons) {
        reasonsCount.textContent = `${reasons.length} Factors`;
        if (reasons.length === 0) {
            reasonsContainer.innerHTML = `<div class="empty-state">No threat factors detected.</div>`;
            return;
        }

        reasonsContainer.innerHTML = reasons.map(r => {
            let cls = "rule";
            if (r.includes("AI")) cls = "ai";
            if (r.includes("Attack Chain") || r.includes("Correlated")) cls = "chain";
            if (r.includes("Telemetry Loss") || r.includes("EVIDENCE GAP")) cls = "chain";
            return `<div class="reason-item ${cls}">${escapeHtml(r)}</div>`;
        }).join("");
    }

    function renderIncidents(incidents) {
        incidentsCount.textContent = `${incidents.length} Incidents`;
        if (incidents.length === 0) {
            timelineContainer.innerHTML = `<div class="empty-state">No multi-stage attack chains identified.</div>`;
            return;
        }

        timelineContainer.innerHTML = incidents.map(inc => {
            const stepsHtml = (inc.attack_timeline || []).map(step => {
                const isCrit = step.event_type === "privilege_change" || step.event_type === "sensitive_resource_access";
                return `
                    <div class="timeline-step ${isCrit ? 'critical' : ''}">
                        <div class="step-header">
                            <span>Step ${step.step}: ${escapeHtml(step.title)}</span>
                            <span class="text-muted">${formatTime(step.timestamp)}</span>
                        </div>
                        <div class="step-desc">${escapeHtml(step.details)}</div>
                    </div>
                `;
            }).join("");

            const missingEvidenceHtml = (inc.missing_evidence || []).map(m => `<li>${escapeHtml(m)}</li>`).join("");
            const benignHtml = (inc.plausible_benign_explanations || []).map(b => `<li>${escapeHtml(b)}</li>`).join("");
            const eventIdsStr = (inc.supporting_event_ids || []).slice(0, 6).join(", ");

            return `
                <div class="incident-card" style="border: 1px solid var(--border-light); border-radius: 8px; margin-bottom: 16px; overflow: hidden; background: var(--bg-card);">
                    <!-- Case File Banner -->
                    <div style="background: var(--bg-header); padding: 12px 16px; border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <span style="font-weight: 700; color: var(--color-critical); font-family: var(--font-mono); margin-right: 8px;">${inc.incident_id}</span>
                            <strong style="font-size: 14px;">${escapeHtml(inc.verdict || inc.explanation)}</strong>
                        </div>
                        <div style="display: flex; gap: 8px; align-items: center;">
                            <span class="badge badge-${inc.severity.toLowerCase()}">${inc.severity} (Risk: ${inc.risk_score})</span>
                            <span class="badge badge-subtle" style="font-size: 11px;">Confidence: ${escapeHtml(inc.confidence || 'HIGH')}</span>
                        </div>
                    </div>

                    <!-- Attack Timeline -->
                    <div style="padding: 12px 16px;">
                        <h4 style="font-size: 12px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px;">Correlated Attack Timeline</h4>
                        <div class="timeline-steps">
                            ${stepsHtml}
                        </div>
                    </div>

                    <!-- Incident Case File Breakdown -->
                    <div style="padding: 12px 16px; background: rgba(0,0,0,0.15); border-top: 1px solid var(--border-color); display: grid; grid-template-columns: 1fr 1fr; gap: 12px; font-size: 12px;">
                        <div>
                            <strong style="color: var(--color-high);">⚠️ Missing Telemetry / Evidence Gaps:</strong>
                            <ul style="margin-left: 16px; margin-top: 4px; color: var(--text-secondary);">
                                ${missingEvidenceHtml || '<li>No telemetry gaps identified.</li>'}
                            </ul>
                        </div>
                        <div>
                            <strong style="color: var(--color-medium);">💡 Plausible Benign Explanations:</strong>
                            <ul style="margin-left: 16px; margin-top: 4px; color: var(--text-secondary);">
                                ${benignHtml || '<li>Unexplained anomalous pattern.</li>'}
                            </ul>
                        </div>
                    </div>

                    <!-- Reversible Recommended Action -->
                    <div style="padding: 10px 16px; background: var(--bg-header); border-top: 1px solid var(--border-color); display: flex; justify-content: space-between; align-items: center;">
                        <div style="font-size: 12px;">
                            <strong style="color: var(--color-low);">🛠️ Recommended Action:</strong>
                            <span style="color: var(--text-primary); margin-left: 6px;">${escapeHtml(inc.recommended_action || 'Review incident logs.')}</span>
                        </div>
                        <span class="badge badge-subtle" style="font-size: 10px; border: 1px dashed var(--border-light);">Advisory — Not Auto-Executed</span>
                    </div>
                </div>
            `;
        }).join("");
    }

    function renderStream(events) {
        if (!events || events.length === 0) {
            streamContainer.innerHTML = `<div class="empty-state">No activity logged.</div>`;
            return;
        }

        const recent = [...events].reverse().slice(0, 15);
        streamContainer.innerHTML = recent.map(e => `
            <div class="stream-item ${e.event_type}">
                <span>${formatTime(e.timestamp)} | <strong>${escapeHtml(e.user)}</strong> (${e.source_ip})</span>
                <span class="event-type-badge">${e.event_type}</span>
            </div>
        `).join("");
    }

    function renderEventsTable() {
        if (!currentData || !currentData.events) {
            eventsTbody.innerHTML = `<tr><td colspan="7" class="text-center">No logs loaded.</td></tr>`;
            tableCount.textContent = "0 Events";
            return;
        }

        const query = searchInput.value.toLowerCase().strip ? searchInput.value.toLowerCase().strip() : searchInput.value.toLowerCase();
        const typeFilter = filterType.value;

        // Build anomalous events map for table lookup
        const anomalousMap = {};
        if (currentData.ai_analysis && currentData.ai_analysis.anomalous_events) {
            currentData.ai_analysis.anomalous_events.forEach(ae => {
                anomalousMap[ae.event_id] = ae;
            });
        }

        const filtered = currentData.events.filter(e => {
            const matchesQuery = !query || 
                (e.user && e.user.toLowerCase().includes(query)) ||
                (e.source_ip && e.source_ip.toLowerCase().includes(query)) ||
                (e.resource && e.resource.toLowerCase().includes(query)) ||
                (e.details && e.details.toLowerCase().includes(query));

            const matchesType = (typeFilter === "ALL") || (e.event_type === typeFilter);

            return matchesQuery && matchesType;
        });

        tableCount.textContent = `${filtered.length} Events`;

        if (filtered.length === 0) {
            eventsTbody.innerHTML = `<tr><td colspan="7" class="text-center">No matching event logs found.</td></tr>`;
            return;
        }

        eventsTbody.innerHTML = filtered.map(e => {
            const anomaly = anomalousMap[e.id];
            const anomalyBadge = anomaly ? 
                `<span class="badge badge-high" title="${escapeHtml(anomaly.reason)}">AI Outlier (${anomaly.anomaly_score})</span>` : 
                `<span class="text-muted">Normal</span>`;

            return `
                <tr>
                    <td>${formatTime(e.timestamp)}</td>
                    <td><span class="event-type-badge">${e.event_type}</span></td>
                    <td><strong>${escapeHtml(e.user)}</strong></td>
                    <td><code>${escapeHtml(e.source_ip)}</code></td>
                    <td><code>${escapeHtml(e.resource)}</code></td>
                    <td>${escapeHtml(e.details)}</td>
                    <td>${anomalyBadge}</td>
                </tr>
            `;
        }).join("");
    }

    function formatTime(ts) {
        if (!ts) return "";
        try {
            const d = new Date(ts);
            return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        } catch (e) {
            return ts;
        }
    }

    function escapeHtml(str) {
        if (!str) return "";
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
});
