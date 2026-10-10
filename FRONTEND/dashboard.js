/**
 * AGEINS Cyber Guard - User Personal History & Dashboard Script (Zero Emojis)
 */

const API_BASE_DASHBOARD = window.getApiBase ? window.getApiBase() : "http://127.0.0.1:8001/api";

function formatTimestamp(ts) {
    if (!ts) return "N/A";
    const date = typeof ts === "number" ? new Date(ts * 1000) : new Date(ts);
    return date.toLocaleString();
}

async function loadUserDashboard() {
    const user = JSON.parse(localStorage.getItem("ageins_user") || "null");
    const token = localStorage.getItem("ageins_token");

    const gate = document.getElementById("userDashboardAuthGate");
    const view = document.getElementById("userDashboardView");

    if (!user || !token) {
        if (gate) gate.style.display = "block";
        if (view) view.style.display = "none";
        return;
    }

    if (gate) gate.style.display = "none";
    if (view) view.style.display = "block";

    const headers = { "Authorization": `Bearer ${token}` };

    try {
        const res = await fetch(`${API_BASE_DASHBOARD}/user/dashboard?user_id=${encodeURIComponent(user.email)}`, { headers });
        if (!res.ok) throw new Error("Could not load user telemetry data.");

        const data = await res.json();

        // Update 4 Telemetry Metrics
        document.getElementById("userTotalScans").textContent = data.total_scans || 0;
        document.getElementById("userThreatsPrevented").textContent = data.threats_prevented || 0;
        document.getElementById("userAvgScore").textContent = `${data.avg_threat_score || 0}%`;

        // Render History Table
        renderUserHistoryTable(data.recent_scans || []);

    } catch (err) {
        console.error("Dashboard Error:", err);
    }
}

function renderUserHistoryTable(scans) {
    const tbody = document.getElementById("userHistoryTableBody");
    if (!tbody) return;

    if (scans.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; padding: 25px;">No previous scan history found. Run your first scan from the Threat Scanner!</td></tr>`;
        return;
    }

    tbody.innerHTML = scans.map(s => {
        const score = s.risk_score || 0;
        const badgeClass = score >= 65 ? "badge-danger" : score >= 35 ? "badge-warning" : "badge-safe";
        const badgeText = score >= 65 ? "HIGH RISK" : score >= 35 ? "MEDIUM" : "SAFE";

        return `
            <tr>
                <td><strong>#${s.id}</strong></td>
                <td><span class="engine-tag">${(s.scan_type || 'SCAN').toUpperCase()}</span></td>
                <td><code style="color: #fff;">${s.target_preview || 'N/A'}</code></td>
                <td><strong style="color: ${score >= 65 ? '#ef4444' : score >= 35 ? '#f59e0b' : '#34d399'};">${score}%</strong></td>
                <td>${s.verdict || 'Scan Complete'}</td>
                <td><span class="threat-level-badge ${badgeClass}">${badgeText}</span></td>
                <td>${formatTimestamp(s.created_at || s.timestamp)}</td>
            </tr>
        `;
    }).join("");
}

document.addEventListener("DOMContentLoaded", () => {
    if (window.location.pathname.includes("dashboard.html")) {
        loadUserDashboard();
    }
});
