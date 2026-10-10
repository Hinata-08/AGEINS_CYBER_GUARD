/**
 * AGEINS Cyber Guard Platform — Main Frontend Engine
 * Fixed: 90-second scan timeout, session-expiry handler, all scan types restored.
 */

const API_BASE = window.getApiBase ? window.getApiBase() : "http://127.0.0.1:8001/api";

let currentTab = "url";
let mediaSubtype = "image";
let selectedFile = null;
let currentAuthMode = "login";
let pendingAction = null;

// -------------------- 1. Navbar Real-Time Clock --------------------
function startRealtimeClock() {
    const clockEl = document.getElementById("clockTimeStr");
    if (!clockEl) return;
    function updateClock() {
        const now = new Date();
        clockEl.textContent = now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: true })
            + " | " + now.toLocaleDateString([], { day: "2-digit", month: "short", year: "numeric" });
    }
    updateClock();
    setInterval(updateClock, 1000);
}

// -------------------- 2. Auth --------------------
function getAuthToken() { return localStorage.getItem("ageins_token") || ""; }
function getAuthUser() { try { return JSON.parse(localStorage.getItem("ageins_user") || "null"); } catch (e) { return null; } }

function requireAuth(actionCallback, actionName = "this operation") {
    if (!getAuthUser() || !getAuthToken()) {
        pendingAction = actionCallback;
        openAuthModal("login", "Account Required: Please sign in before performing " + actionName + ".");
        return false;
    }
    return true;
}

function updateAuthNavbarUI() {
    const u = getAuthUser();
    const gate = document.getElementById("navAuthGate");
    const userBadge = document.getElementById("navUserBadge");
    const chipName = document.getElementById("userChipName");
    if (u && gate && userBadge) {
        gate.style.display = "none"; userBadge.style.display = "flex";
        if (chipName) chipName.textContent = u.role === "admin" ? ("Organiser (" + u.username + ")") : u.username;
    } else if (gate && userBadge) { gate.style.display = "flex"; userBadge.style.display = "none"; }
}

function openAuthModal(mode, customMsg) {
    mode = mode || "login"; currentAuthMode = mode; switchAuthTab(mode);
    const modal = document.getElementById("authModal");
    const sub = document.getElementById("modalSub");
    if (customMsg && sub) sub.textContent = customMsg;
    else if (sub) sub.textContent = "Sign in or create an account to access threat scanners.";
    if (modal) modal.style.display = "grid";
}
function closeAuthModal() { const m = document.getElementById("authModal"); if (m) m.style.display = "none"; }

function switchAuthTab(mode) {
    currentAuthMode = mode;
    const tabIn = document.getElementById("authTabLogin"), tabUp = document.getElementById("authTabRegister");
    const uField = document.getElementById("usernameField"), submitBtn = document.getElementById("authSubmitBtn");
    const errBox = document.getElementById("authErrMsg");
    if (errBox) errBox.style.display = "none";
    if (mode === "login") {
        if (tabIn) tabIn.className = "active"; if (tabUp) tabUp.className = "";
        if (uField) uField.style.display = "none"; if (submitBtn) submitBtn.textContent = "Sign In";
    } else {
        if (tabIn) tabIn.className = ""; if (tabUp) tabUp.className = "active";
        if (uField) uField.style.display = "block"; if (submitBtn) submitBtn.textContent = "Create Account & Save Details";
    }
}

async function submitAuthForm() {
    const email = document.getElementById("authEmailInput")?.value.trim();
    const password = document.getElementById("authPasswordInput")?.value.trim();
    const username = document.getElementById("authUsernameInput")?.value.trim();
    const errBox = document.getElementById("authErrMsg");
    if (!email || !password) {
        if (errBox) { errBox.textContent = "Please enter your email and password."; errBox.style.display = "block"; }
        return;
    }
    const endpoint = currentAuthMode === "login" ? (API_BASE + "/auth/login") : (API_BASE + "/auth/register");
    const payload = currentAuthMode === "login" ? { email, password } : { username: username || email.split("@")[0], email, password };
    try {
        const res = await fetch(endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Authentication failed.");
        localStorage.setItem("ageins_token", data.token);
        localStorage.setItem("ageins_user", JSON.stringify(data.user));
        closeAuthModal(); updateAuthNavbarUI();
        const currentPage = window.location.pathname;
        if (currentPage.includes("admin.html")) {
            if (data.user.role === "admin" && window.loadAdminOverview) window.loadAdminOverview();
        } else if (pendingAction && !currentPage.includes("index.html") && currentPage !== "/") {
            const act = pendingAction; pendingAction = null; act();
        } else {
            window.location.href = "dashboard.html";
        }
    } catch (err) { if (errBox) { errBox.textContent = err.message; errBox.style.display = "block"; } }
}

function logoutUser() {
    localStorage.removeItem("ageins_token"); localStorage.removeItem("ageins_user");
    updateAuthNavbarUI();
    if (window.location.pathname.includes("admin.html") || window.location.pathname.includes("dashboard.html")) window.location.reload();
}

setInterval(async () => {
    const token = getAuthToken();
    if (token) { try { await fetch(API_BASE + "/session/ping", { method: "POST", headers: { "Authorization": "Bearer " + token } }); } catch (e) {} }
}, 30000);

// -------------------- 3. Footer Modals --------------------
function openPrivacyModal() { const m = document.getElementById("privacyPolicyModal"); if (m) m.style.display = "grid"; }
function closePrivacyModal() { const m = document.getElementById("privacyPolicyModal"); if (m) m.style.display = "none"; }
function openSafetyModal() { const m = document.getElementById("safetyGuidelinesModal"); if (m) m.style.display = "grid"; }
function closeSafetyModal() { const m = document.getElementById("safetyGuidelinesModal"); if (m) m.style.display = "none"; }

// -------------------- 4. Tab Switching --------------------
function switchTab(tabName) {
    currentTab = tabName;
    document.querySelectorAll(".tab-btn").forEach(function(btn) { btn.classList.toggle("active", btn.getAttribute("data-tab") === tabName); });
    const textPanel = document.getElementById("textInputPanel"), filePanel = document.getElementById("fileInputPanel");
    const mediaSubtypeBox = document.getElementById("mediaSubtypeBox"), label = document.getElementById("inputLabel");
    const textarea = document.getElementById("scaninput"), fileTitle = document.getElementById("fileDropTitle");
    const fileSubtext = document.getElementById("fileDropSubtext"), fileInput = document.getElementById("fileUploadInput");
    const heading = document.getElementById("scannerHeading"), subHeading = document.getElementById("scannerSubHeading");
    selectedFile = null; clearFilePreview();

    var show = function(p) { if (p) p.style.display = "block"; };
    var hide = function(p) { if (p) p.style.display = "none"; };
    var set = function(el, txt) { if (el) el.textContent = txt; };
    var ph = function(el, txt) { if (el) { el.placeholder = txt; el.value = ""; } };

    if (tabName === "url") {
        show(textPanel); hide(filePanel); hide(mediaSubtypeBox);
        set(heading, "Phishing URL & Link Scanner"); set(subHeading, "Inspect domain entropy, typosquatting, TLD reputation, and credential lures.");
        set(label, "Target URL or Domain:"); ph(textarea, "Enter URL e.g. https://paypal-security-update.xyz/login");
    } else if (tabName === "email") {
        show(textPanel); hide(filePanel); hide(mediaSubtypeBox);
        set(heading, "Phishing Email & Scam Analyzer"); set(subHeading, "Analyze social engineering lures, urgent banking threats, and email headers.");
        set(label, "Suspicious Email Subject, Sender or Body Text:"); ph(textarea, "Paste email subject, sender, or message body...");
    } else if (tabName === "trust_mismatch") {
        hide(textPanel); show(filePanel); hide(mediaSubtypeBox);
        set(heading, "Deepfake Trust Mismatch Detector"); set(subHeading, "Cross-evaluates facial lip sync vs audio pitch, spectral artifacts, and temporal jitter.");
        set(fileTitle, "Upload Image, Audio, or Video for Trust Mismatch Analysis"); set(fileSubtext, "Supports JPG, PNG, MP3, WAV, MP4 (Max 50MB).");
        if (fileInput) fileInput.accept = "image/*,audio/*,video/*";
    } else if (tabName === "deepfake_media") {
        hide(textPanel); show(filePanel); show(mediaSubtypeBox);
        set(heading, "Deepfake Media Forensics"); set(subHeading, "Forensic inspection for synthetic images (ELA), cloned voices, and video keyframes.");
        setMediaSubtype(mediaSubtype);
    } else if (tabName === "payment_qr") {
        show(textPanel); hide(filePanel); hide(mediaSubtypeBox);
        set(heading, "Payment QR Code & Fake Scanner Detector"); set(subHeading, "Inspect UPI QR URI payloads, fake refund handles, auto-debit mandates.");
        set(label, "Payment QR Payload / Link or UPI URI:"); ph(textarea, "Paste QR code text e.g. upi://pay?pa=gpay-refund@ybl&am=5000");
    } else if (tabName === "bank_details") {
        show(textPanel); hide(filePanel); hide(mediaSubtypeBox);
        set(heading, "Fraud Bank Details & Payment Detector"); set(subHeading, "Validate IFSC code, account number patterns, VPA handles.");
        set(label, "Bank Details or Transfer Request Message:"); ph(textarea, "Paste bank details (e.g. Bank: SBI, Account: 3948291039, IFSC: SBIN0001234)...");
    } else if (tabName === "phone_number") {
        show(textPanel); hide(filePanel); hide(mediaSubtypeBox);
        set(heading, "Fraud Phone Number & SMS Detector"); set(subHeading, "Evaluate call/SMS spam rating, VoIP ranges, and scam SMS patterns.");
        set(label, "Phone Number or SMS Content:"); ph(textarea, "Enter phone number (+91 9876543210) or paste suspicious SMS text...");
    }
}

function setMediaSubtype(type) {
    mediaSubtype = type;
    document.querySelectorAll(".seg-btn").forEach(function(btn) { btn.classList.toggle("active", btn.getAttribute("data-media") === type); });
    var fileTitle = document.getElementById("fileDropTitle"), fileSubtext = document.getElementById("fileDropSubtext"), fileInput = document.getElementById("fileUploadInput");
    if (type === "image") {
        if (fileTitle) fileTitle.textContent = "Upload Image for Deepfake ELA Forensics";
        if (fileSubtext) fileSubtext.textContent = "Supports JPG, PNG, WEBP."; if (fileInput) fileInput.accept = "image/*";
    } else if (type === "audio") {
        if (fileTitle) fileTitle.textContent = "Upload Audio for Voice Clone Forensics";
        if (fileSubtext) fileSubtext.textContent = "Supports WAV, MP3, M4A."; if (fileInput) fileInput.accept = "audio/*";
    } else if (type === "video") {
        if (fileTitle) fileTitle.textContent = "Upload Video for Face-Swap Forensics";
        if (fileSubtext) fileSubtext.textContent = "Supports MP4, WebM, MOV."; if (fileInput) fileInput.accept = "video/*";
    }
}

// -------------------- 5. File Drop --------------------
function handleDrop(e) { e.preventDefault(); document.getElementById("dropzone")?.classList.remove("dragover"); if (e.dataTransfer.files && e.dataTransfer.files[0]) handleFileSelect(e.dataTransfer.files[0]); }
function handleDragOver(e) { e.preventDefault(); document.getElementById("dropzone")?.classList.add("dragover"); }
function handleDragLeave(e) { e.preventDefault(); document.getElementById("dropzone")?.classList.remove("dragover"); }
function handleFileInputChange(e) { if (e.target.files && e.target.files[0]) handleFileSelect(e.target.files[0]); }
function handleFileSelect(file) {
    selectedFile = file;
    var strip = document.getElementById("filePreviewStrip"), nameEl = document.getElementById("selectedFileName"), sizeEl = document.getElementById("selectedFileSize");
    if (nameEl) nameEl.textContent = file.name;
    if (sizeEl) sizeEl.textContent = (file.size / (1024 * 1024)).toFixed(2) + " MB";
    if (strip) strip.style.display = "flex";
}
function clearFilePreview() {
    selectedFile = null;
    var strip = document.getElementById("filePreviewStrip"), fileInput = document.getElementById("fileUploadInput");
    if (strip) strip.style.display = "none"; if (fileInput) fileInput.value = "";
}

// -------------------- 6. Execute Threat Scan (90-second timeout) --------------------
async function startscan() {
    if (!requireAuth(function() { startscan(); }, "a threat scan")) return;

    var scanBtn = document.getElementById("scanBtn");
    var verdictEl = document.getElementById("threatVerdict");
    var badgeEl = document.getElementById("threatBadge");
    var explanationEl = document.getElementById("scoreExplanationText");

    var isFileScan = (currentTab === "trust_mismatch" || currentTab === "deepfake_media");
    var content = "";

    if (!isFileScan) {
        content = document.getElementById("scaninput")?.value.trim() || "";
        if (!content) { alert("Please enter input content to scan."); return; }
        var piiMasking = document.getElementById("privacyShieldToggle")?.checked;
        if (piiMasking && (currentTab === "bank_details" || currentTab === "email")) {
            content = content.replace(/\b\d{10,16}\b/g, "[PROTECTED_PII]");
        }
    } else {
        if (!selectedFile) { alert("Please select or upload a media file to scan."); return; }
    }

    if (scanBtn) { scanBtn.disabled = true; scanBtn.innerHTML = "Analyzing Telemetry..."; }
    if (verdictEl) verdictEl.textContent = "Executing Forensic Pipeline...";
    if (badgeEl) { badgeEl.textContent = "ANALYZING"; badgeEl.className = "threat-level-badge badge-warning"; }

    try {
        var token = getAuthToken(), user = getAuthUser();
        var authHeader = { "Authorization": "Bearer " + token };
        var endpoint = "", requestOptions = {};

        if (currentTab === "url") {
            endpoint = API_BASE + "/scan/url";
            requestOptions = { method: "POST", headers: Object.assign({ "Content-Type": "application/json" }, authHeader), body: JSON.stringify({ content: content, user_id: user.email }) };
        } else if (currentTab === "email") {
            endpoint = API_BASE + "/scan/email";
            requestOptions = { method: "POST", headers: Object.assign({ "Content-Type": "application/json" }, authHeader), body: JSON.stringify({ content: content, user_id: user.email }) };
        } else if (currentTab === "payment_qr") {
            endpoint = API_BASE + "/scan/payment-qr";
            requestOptions = { method: "POST", headers: Object.assign({ "Content-Type": "application/json" }, authHeader), body: JSON.stringify({ payload: content }) };
        } else if (currentTab === "bank_details") {
            endpoint = API_BASE + "/scan/bank-details";
            requestOptions = { method: "POST", headers: Object.assign({ "Content-Type": "application/json" }, authHeader), body: JSON.stringify({ details: content }) };
        } else if (currentTab === "phone_number") {
            endpoint = API_BASE + "/scan/phone-number";
            requestOptions = { method: "POST", headers: Object.assign({ "Content-Type": "application/json" }, authHeader), body: JSON.stringify({ number_or_text: content }) };
        } else if (currentTab === "trust_mismatch") {
            endpoint = API_BASE + "/scan/trust-mismatch";
            var fd1 = new FormData(); fd1.append("file", selectedFile); fd1.append("user_id", user.email);
            requestOptions = { method: "POST", headers: authHeader, body: fd1 };
        } else if (currentTab === "deepfake_media") {
            endpoint = API_BASE + "/scan/" + mediaSubtype;
            var fd2 = new FormData(); fd2.append("file", selectedFile); fd2.append("user_id", user.email);
            requestOptions = { method: "POST", headers: authHeader, body: fd2 };
        }

        // 90-second AbortController timeout
        var controller = new AbortController();
        var timeoutId = setTimeout(function() { controller.abort(); }, 90000);
        var response = await fetch(endpoint, Object.assign({}, requestOptions, { signal: controller.signal }));
        clearTimeout(timeoutId);
        var data = await response.json();

        if (response.status === 401) {
            localStorage.removeItem("ageins_token"); localStorage.removeItem("ageins_user");
            updateAuthNavbarUI();
            if (verdictEl) verdictEl.textContent = "Session Expired";
            if (badgeEl) { badgeEl.textContent = "SESSION EXPIRED"; badgeEl.className = "threat-level-badge badge-warning"; }
            if (explanationEl) explanationEl.innerHTML = "Your session has expired. <a href=\"#\" onclick=\"openAuthModal('login')\" style=\"color:#a855f7;text-decoration:underline\">Sign in again</a> to continue scanning.";
            return;
        }

        if (!response.ok) throw new Error(data.detail || "Diagnostic analysis failed.");
        renderScanResults(data);

    } catch (err) {
        if (err.name === "AbortError") {
            if (verdictEl) verdictEl.textContent = "Scan Timed Out";
            if (badgeEl) { badgeEl.textContent = "TIMEOUT"; badgeEl.className = "threat-level-badge badge-warning"; }
            if (explanationEl) explanationEl.innerHTML = "The scan took over 90 seconds. Please try with a smaller file or simpler input.";
        } else {
            if (verdictEl) verdictEl.textContent = "Analysis Connection Error";
            if (badgeEl) { badgeEl.textContent = "OFFLINE"; badgeEl.className = "threat-level-badge badge-danger"; }
            if (explanationEl) explanationEl.innerHTML = "Cannot reach backend: <code>" + err.message + "</code>. Make sure the server is running on port 8001.";
        }
    } finally {
        if (scanBtn) {
            scanBtn.disabled = false;
            scanBtn.innerHTML = "<svg width=\"18\" height=\"18\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><path d=\"M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z\"/></svg> Execute Forensic Analysis";
        }
    }
}

// -------------------- 7. Render Results --------------------
function renderScanResults(data) {
    var score = Math.round(Number(data.score) || 0);
    var res = data.result || {};
    var sources = data.sources || ["AGEINS Telemetry Engine"];
    var flags = res.flags || [];
    var recommendations = res.recommendations || ["Inspect verified official channels prior to taking action.", "Always maintain strict digital security standards."];

    var ring = document.getElementById("gaugeProgressRing"), scoreEl = document.getElementById("score");
    if (scoreEl) scoreEl.textContent = score + "%";
    if (ring) {
        var circumference = 440;
        ring.style.strokeDashoffset = circumference - (score / 100) * circumference;
        ring.style.stroke = score >= 65 ? "#ef4444" : score >= 35 ? "#f59e0b" : "#34d399";
    }

    var verdictEl = document.getElementById("threatVerdict"), badgeEl = document.getElementById("threatBadge");
    if (verdictEl) verdictEl.textContent = res.verdict || data.verdict || "Analysis Complete";
    if (badgeEl) {
        if (score >= 65) { badgeEl.textContent = "HIGH LEVEL RISK"; badgeEl.className = "threat-level-badge badge-danger"; }
        else if (score >= 35) { badgeEl.textContent = "MEDIUM LEVEL RISK"; badgeEl.className = "threat-level-badge badge-warning"; }
        else { badgeEl.textContent = "SAFE LEVEL"; badgeEl.className = "threat-level-badge badge-safe"; }
    }

    var expEl = document.getElementById("scoreExplanationText");
    if (expEl) {
        var expText = "<strong>Score Assessment (" + score + "% Risk):</strong> ";
        if (score >= 65) expText += "Confirmed high-risk malicious markers detected. Multiple heuristic engines flagged critical anomalies.";
        else if (score >= 35) expText += "Suspicious indicators detected (elevated entropy, urgency signals, or structural anomalies). Verify before proceeding.";
        else expText += "No major threat anomalies detected across protocol, spectral, or heuristic telemetry. Evaluated as low-risk.";
        if (res.metrics) expText += "<br><br><small><strong>Metrics:</strong> " + JSON.stringify(res.metrics) + "</small>";
        expEl.innerHTML = expText;
    }

    var stepsEl = document.getElementById("safeStepsList");
    if (stepsEl) stepsEl.innerHTML = recommendations.map(function(step) { return "<li>" + step + "</li>"; }).join("");

    var tagsEl = document.getElementById("engineTagsList");
    if (tagsEl) tagsEl.innerHTML = sources.map(function(src) { return "<span class=\"engine-tag\">\u2713 " + src + "</span>"; }).join("");

    var flagsEl = document.getElementById("flagsList");
    if (flagsEl) {
        if (flags.length === 0) {
            flagsEl.innerHTML = "<div class=\"flag-item\" style=\"border-left-color:#34d399\"><strong>Clean Diagnostic:</strong> No malicious flags or synthetic anomalies detected.</div>";
        } else {
            flagsEl.innerHTML = flags.map(function(f) { return "<div class=\"flag-item " + (f.severity || "medium") + "\"><strong style=\"color:#fff\">" + (f.title || "Threat Anomaly") + ":</strong> " + (f.desc || "") + "</div>"; }).join("");
        }
    }
}

function toggleChatModal() { alert("Copilot Assistant: Ask questions about scan results or get cybersecurity guidance."); }

// -------------------- 8. Page Load --------------------
document.addEventListener("DOMContentLoaded", function() {
    startRealtimeClock();
    updateAuthNavbarUI();
    var urlParams = new URLSearchParams(window.location.search);
    var tabParam = urlParams.get("tab");
    if (tabParam) switchTab(tabParam);
});
