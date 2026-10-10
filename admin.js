/**
 * AGEINS Cyber Guard - Organiser Operations & User Management Console Script (Zero Emojis)
 */

const API_BASE_ADMIN = window.getApiBase ? window.getApiBase() : "http://127.0.0.1:8001/api";

function formatTimestamp(ts) {
    if (!ts) return "N/A";
    const date = typeof ts === "number" ? new Date(ts * 1000) : new Date(ts);
    return date.toLocaleString();
}

function formatSpentTime(seconds) {
    if (!seconds || seconds <= 0) return "0 mins";
    const hrs = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    if (hrs > 0) return `${hrs}h ${mins}m`;
    if (mins > 0) return `${mins}m ${secs}s`;
    return `${secs}s`;
}

function checkOrganiserAuth() {
    const token = localStorage.getItem("ageins_token");
    const user = JSON.parse(localStorage.getItem("ageins_user") || "null");

    const gate = document.getElementById("organiserLoginGate");
    const view = document.getElementById("organiserDashboardView");

    if (!token || !user || user.role !== "admin") {
        if (gate) gate.style.display = "block";
        if (view) view.style.display = "none";
        return false;
    } else {
        if (gate) gate.style.display = "none";
        if (view) view.style.display = "block";
        return true;
    }
}

async function submitOrganiserLogin() {
    const email = document.getElementById("orgEmailInput")?.value.trim();
    const password = document.getElementById("orgPasswordInput")?.value.trim();
    const errBox = document.getElementById("orgLoginErr");

    if (!email || !password) {
        if (errBox) { errBox.textContent = "Please enter Organiser email and password."; errBox.style.display = "block"; }
        return;
    }

    try {
        const res = await fetch(`${API_BASE_ADMIN}/auth/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, password })
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Organiser sign-in failed.");

        if (data.user.role !== "admin") {
            throw new Error("Access Denied: This account does not have Organiser Admin permissions.");
        }

        localStorage.setItem("ageins_token", data.token);
        localStorage.setItem("ageins_user", JSON.stringify(data.user));

        checkOrganiserAuth();
        loadAdminOverview();
    } catch (err) {
        if (errBox) { errBox.textContent = err.message; errBox.style.display = "block"; }
    }
}

async function loadAdminOverview() {
    if (!checkOrganiserAuth()) return;

    const token = localStorage.getItem("ageins_token");

    try {
        const res = await fetch(`${API_BASE_ADMIN}/admin/overview`, {
            headers: { "Authorization": `Bearer ${token}` }
        });

        if (!res.ok) throw new Error("Failed to load Organiser telemetry.");
        const data = await res.json();

        // 1. Update Metrics Cards
        document.getElementById("adminTotalScans").textContent = data.metrics?.total_scans || 0;
        document.getElementById("adminTotalCritical").textContent = data.metrics?.total_critical || 0;
        document.getElementById("adminTotalQuarantined").textContent = data.metrics?.total_quarantined || 0;
        document.getElementById("adminActiveUsers").textContent = data.metrics?.active_users || 0;

        // 2. Render User Login Data Table (Organiser Exclusive)
        renderUsersTable(data.users || []);

        // 3. Render Quarantined Items
        renderQuarantineTable(data.quarantined_items || []);

        // 4. Render Config Controls & Engines
        renderConfigControls(data.configs_full || []);
        renderEnginesList(data.engines || []);

        // 5. Render Audit Logs
        renderAuditLogs(data.audit_logs || []);

    } catch (err) {
        console.error("Organiser Overview Error:", err);
    }
}

function renderUsersTable(users) {
    const tbody = document.getElementById("usersTableBody");
    if (!tbody) return;

    if (users.length === 0) {
        tbody.innerHTML = `<tr><td colspan="10" style="text-align: center; padding: 20px;">No registered user records found.</td></tr>`;
        return;
    }

    tbody.innerHTML = users.map(u => `
        <tr>
            <td><strong>#${u.id}</strong></td>
            <td>${u.username || 'User'}</td>
            <td><code style="color: var(--primary);">${u.email}</code></td>
            <td>
                <span class="tier-chip ${u.role === 'admin' ? 'high-chip' : 'safe-chip'}">
                    ${u.role === 'admin' ? 'Organiser Admin' : 'Standard User'}
                </span>
            </td>
            <td>
                <span style="color: ${u.status === 'active' ? '#34d399' : '#ef4444'}; font-weight: 700;">
                    ${(u.status || 'active').toUpperCase()}
                </span>
            </td>
            <td>${formatTimestamp(u.created_at)}</td>
            <td>${formatTimestamp(u.last_login)}</td>
            <td><strong>${formatSpentTime(u.spent)}</strong></td>
            <td><strong>${u.total_scans || 0} scans</strong></td>
            <td>
                ${u.role !== 'admin' ? `
                    <button class="secondary-btn" onclick="deleteUserAccount(${u.id})" style="padding: 4px 8px; font-size: 11px; color: #ef4444; border-color: rgba(239, 68, 68, 0.3);">
                        Delete
                    </button>
                ` : '<span style="color: var(--text-muted); font-size: 11px;">Root Account</span>'}
            </td>
        </tr>
    `).join("");
}

function renderQuarantineTable(items) {
    const tbody = document.getElementById("quarantineTableBody");
    if (!tbody) return;

    if (items.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; padding: 20px;">Quarantine vault is clean. No active quarantined threats.</td></tr>`;
        return;
    }

    tbody.innerHTML = items.map(s => `
        <tr>
            <td><strong>#${s.id}</strong></td>
            <td><span class="engine-tag">${s.scan_type.toUpperCase()}</span></td>
            <td><code style="color: #fff;">${s.target_preview || 'N/A'}</code></td>
            <td><strong style="color: #ef4444;">${s.risk_score}%</strong></td>
            <td>${s.verdict || 'Quarantined Payload'}</td>
            <td>
                <button class="secondary-btn" onclick="toggleQuarantineItem(${s.id}, false)" style="padding: 4px 10px; font-size: 11.5px; color: #34d399;">
                    Release Quarantine
                </button>
            </td>
        </tr>
    `).join("");
}

function renderConfigControls(configs) {
    const container = document.getElementById("configControlsList");
    if (!container) return;

    container.innerHTML = configs.map(c => `
        <div style="background: rgba(12, 10, 25, 0.5); border: 1px solid var(--card-border); border-radius: 10px; padding: 12px; font-size: 13px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                <strong style="color: var(--primary);">${c.key}</strong>
                <code style="color: var(--cyan); font-weight: 700;">${c.value}</code>
            </div>
            <p style="color: var(--text-muted); font-size: 12px; margin-bottom: 8px;">${c.description || ''}</p>
            <div style="display: flex; gap: 8px;">
                <input type="text" id="cfg_val_${c.key}" class="scan-textarea" style="height: 34px; padding: 6px 10px; font-size: 12px;" value="${c.value}">
                <button class="primary-btn" onclick="updateConfigValue('${c.key}')" style="padding: 4px 12px; font-size: 12px;">Save</button>
            </div>
        </div>
    `).join("");
}

function renderEnginesList(engines) {
    const container = document.getElementById("enginesList");
    if (!container) return;

    container.innerHTML = engines.map(e => `
        <div style="background: rgba(12, 10, 25, 0.5); border: 1px solid var(--card-border); border-radius: 10px; padding: 12px; display: flex; justify-content: space-between; align-items: center; font-size: 13px;">
            <div>
                <strong style="color: #fff; display: block;">${e.name}</strong>
                <small style="color: var(--text-muted);">${e.source_type}</small>
            </div>
            <div style="text-align: right;">
                <span class="tier-chip safe-chip">${e.status.toUpperCase()}</span>
                <small style="display: block; color: var(--cyan); margin-top: 4px;">${e.threat_count} detections</small>
            </div>
        </div>
    `).join("");
}

function renderAuditLogs(logs) {
    const tbody = document.getElementById("auditLogsBody");
    if (!tbody) return;

    if (logs.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; padding: 20px;">No audit log records available.</td></tr>`;
        return;
    }

    tbody.innerHTML = logs.map(l => `
        <tr>
            <td><strong>#${l.id}</strong></td>
            <td><code style="color: var(--primary);">${l.actor}</code></td>
            <td><strong>${l.action}</strong></td>
            <td>${l.target}</td>
            <td>${l.details || ''}</td>
            <td>${formatTimestamp(l.timestamp)}</td>
        </tr>
    `).join("");
}

async function deleteUserAccount(uid) {
    if (!confirm(`Are you sure you want to delete User Account #${uid}?`)) return;
    const token = localStorage.getItem("ageins_token");

    try {
        const res = await fetch(`${API_BASE_ADMIN}/admin/users/${uid}`, {
            method: "DELETE",
            headers: { "Authorization": `Bearer ${token}` }
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Delete failed.");
        alert(data.message || "User account removed.");
        loadAdminOverview();
    } catch (err) {
        alert("Error: " + err.message);
    }
}

async function toggleQuarantineItem(scanId, status) {
    const token = localStorage.getItem("ageins_token");
    try {
        const res = await fetch(`${API_BASE_ADMIN}/admin/quarantine`, {
            method: "POST",
            headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
            body: JSON.stringify({ scan_id: scanId, quarantine: status })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Failed to update quarantine.");
        loadAdminOverview();
    } catch (err) {
        alert("Error: " + err.message);
    }
}

async function updateConfigValue(key) {
    const valInput = document.getElementById(`cfg_val_${key}`);
    if (!valInput) return;
    const value = valInput.value.trim();
    const token = localStorage.getItem("ageins_token");

    try {
        const res = await fetch(`${API_BASE_ADMIN}/admin/config`, {
            method: "POST",
            headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
            body: JSON.stringify({ key, value })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Failed to update config.");
        alert(`Config '${key}' updated to '${value}'.`);
        loadAdminOverview();
    } catch (err) {
        alert("Error: " + err.message);
    }
}

document.addEventListener("DOMContentLoaded", () => {
    if (window.location.pathname.includes("admin.html")) {
        loadAdminOverview();
    }
});
