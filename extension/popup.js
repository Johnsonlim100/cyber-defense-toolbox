

const API_BASE = "https://cyber-defense-toolbox.onrender.com";

// ── Shared UI state ───────────────────────────────────────────────────────────
let scanState = {
    results    : [],
    currentPage: 1,
    pageSize   : 3,
};

let whitelistState = {
    domains    : [],
    pageSize   : 3,
    currentPage: 1,
    searchTerm : "",
};

// Popup-side timer so the clock ticks even when the storage update lags
let uiTimerInterval  = null;
let storageWatcher   = null;
let backendReady     = false;
let currentScanMode  = "idle";

// ─────────────────────────────────────────────────────────────────────────────
// Bootstrap
// ─────────────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
    setupTabs();
    setupButtons();
    setupGenerator();
    checkBackendStatus();
    loadDetectedStrength();
    watchDetectedStrength();
    restoreSessionState();   // reconnect to any in-progress or finished session
    loadWhitelistEntries();
    loadMalwareResults();
    watchMalwareResults();
});

// ─────────────────────────────────────────────────────────────────────────────
// Tab navigation
// ─────────────────────────────────────────────────────────────────────────────
function setupTabs() {
    const buttons = document.querySelectorAll(".tab-btn");
    const tabs    = document.querySelectorAll(".tab-content");
    buttons.forEach(btn => {
        btn.addEventListener("click", () => {
            const tabName = btn.dataset.tab;
            buttons.forEach(b => b.classList.remove("active"));
            tabs.forEach(t => t.classList.remove("active"));
            btn.classList.add("active");
            document.getElementById(tabName).classList.add("active");
        });
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Button wiring
// ─────────────────────────────────────────────────────────────────────────────
function setupButtons() {
    document.getElementById("scanCurrentBtn").addEventListener("click", toggleLiveScan);
    document.getElementById("clearScanBtn").addEventListener("click", clearScan);
    document.getElementById("checkPasswordBtn").addEventListener("click", checkPassword);
    document.getElementById("checkFileBtn").addEventListener("click", checkFileName);
    document.getElementById("refreshWhitelistBtn").addEventListener("click", loadWhitelistEntries);
    document.getElementById("clearMalwareBtn").addEventListener("click", clearMalwareResults);

    document.getElementById("whitelistSearch").addEventListener("input", (e) => {
        whitelistState.searchTerm  = e.target.value.trim().toLowerCase();
        whitelistState.currentPage = 1;
        renderWhitelistEntries(whitelistState.domains);
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// PHISHING — Live session  (Start / Stop / Clear)
// ─────────────────────────────────────────────────────────────────────────────

async function toggleLiveScan() {
    if (currentScanMode === "active") {
        await sendMessage({ action: "stopLiveScan" });
        enterStoppedState();
        return;
    }

    const backendOk = await checkBackendStatus();
    if (!backendOk) {
        setStatus("Backend offline. Start the Flask backend before scanning.", "warning");
        return;
    }

    const reply = await sendMessage({ action: "startLiveScan" });

    if (!reply?.started) {
        setStatus(reply?.reason || "Could not start scan.", "warning");
        return;
    }

    enterActiveState();
}

async function clearScan() {
    stopUiTimer();
    stopStorageWatcher();
    await sendMessage({ action: "clearScan" });

    scanState.results     = [];
    scanState.currentPage = 1;

    document.getElementById("scanResultsList").innerHTML = "";
    document.getElementById("elapsedTimer").textContent  = "00:00:00";
    setStatus("Cleared. Press Start Scanning to begin a new session.", "neutral");
    setScanButtonMode("idle");
}

// ─────────────────────────────────────────────────────────────────────────────
// UI state machines
// ─────────────────────────────────────────────────────────────────────────────

/** Called when a session goes active (start pressed or restored from storage). */
function enterActiveState() {
    setScanButtonMode("active");
    setStatus("🟢 Scanning… visit any website and it will be evaluated automatically.", "safe");
    startUiTimer();
    startStorageWatcher();
}

/** Called when Stop is pressed. */
function enterStoppedState() {
    stopUiTimer();
    stopStorageWatcher();
    setScanButtonMode("stopped");

    const count = scanState.results.length;
    setStatus(`⏹ Scan stopped — ${count} URL${count !== 1 ? "s" : ""} evaluated.`, "neutral");
}

/**
 * Restore the correct UI state when the popup is re-opened.
 * Reads scanStatus + scanResults + scanElapsed from storage.
 */
function restoreSessionState() {
    chrome.storage.local.get(["scanStatus", "scanResults", "scanElapsed", "scanStart"], (res) => {
        const status  = res.scanStatus  || "idle";
        const results = res.scanResults || [];
        const elapsed = res.scanElapsed || 0;

        scanState.results     = results;
        scanState.currentPage = 1;

        if (results.length) renderScanResults();

        if (status === "active") {
            // Sync the elapsed display to what the background has been ticking
            setElapsedDisplay(elapsed);
            enterActiveState();
        } else if (status === "stopped") {
            setElapsedDisplay(elapsed);
            setScanButtonMode("stopped");
            const count = results.length;
            setStatus(`⏹ Scan stopped — ${count} URL${count !== 1 ? "s" : ""} evaluated.`, "neutral");
        } else {
            setScanButtonMode("idle");
            setStatus("Press Start Scanning to begin live phishing detection.", "neutral");
        }
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Elapsed timer  (popup-side; synced to background's storage tick)
// ─────────────────────────────────────────────────────────────────────────────
let uiElapsedSeconds = 0;

function startUiTimer() {
    stopUiTimer();
    // Seed from storage in case we're resuming
    chrome.storage.local.get(["scanElapsed"], (res) => {
        uiElapsedSeconds = res.scanElapsed || 0;
        setElapsedDisplay(uiElapsedSeconds);
        uiTimerInterval = setInterval(() => {
            uiElapsedSeconds++;
            setElapsedDisplay(uiElapsedSeconds);
        }, 1000);
    });
}

function stopUiTimer() {
    if (uiTimerInterval) { clearInterval(uiTimerInterval); uiTimerInterval = null; }
}

function setElapsedDisplay(totalSeconds) {
    const h = String(Math.floor(totalSeconds / 3600)).padStart(2, "0");
    const m = String(Math.floor((totalSeconds % 3600) / 60)).padStart(2, "0");
    const s = String(totalSeconds % 60).padStart(2, "0");
    document.getElementById("elapsedTimer").textContent = `${h}:${m}:${s}`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Storage watcher  — picks up new scan results written by background
// ─────────────────────────────────────────────────────────────────────────────
function startStorageWatcher() {
    stopStorageWatcher();
    storageWatcher = chrome.storage.onChanged.addListener((changes, area) => {
        if (area !== "local") return;

        if (changes.scanResults) {
            scanState.results     = changes.scanResults.newValue || [];
            scanState.currentPage = 1;
            renderScanResults();

            const count = scanState.results.length;
            // Only update status text if still active (don't overwrite "stopped")
            chrome.storage.local.get(["scanStatus"], (res) => {
                if (res.scanStatus === "active") {
                    setStatus(`🟢 Scanning… ${count} URL${count !== 1 ? "s" : ""} evaluated so far.`, "safe");
                }
            });
        }
    });
}

function stopStorageWatcher() {
    if (storageWatcher) {
        chrome.storage.onChanged.removeListener(storageWatcher);
        storageWatcher = null;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Render helpers
// ─────────────────────────────────────────────────────────────────────────────

/** Switch Start / Stop / Clear buttons to reflect current session state. */
function setScanButtonMode(mode) {
    currentScanMode = mode;
    const startBtn = document.getElementById("scanCurrentBtn");
    const clearBtn = document.getElementById("clearScanBtn");

    startBtn.disabled = false;
    clearBtn.disabled = false;

    if (mode === "active") {
        startBtn.textContent = "⏹ Stop Detection";
        startBtn.classList.add("stop-btn");
        clearBtn.disabled = true;
    } else {
        startBtn.textContent = backendReady ? "▶ Start Scanning" : "▶ Start Scanning";
        startBtn.classList.remove("stop-btn");
        clearBtn.disabled = false;
    }
}

function setStatus(text, cssClass) {
    setResult(document.getElementById("phishingResult"), text, cssClass);
}

/** Render paginated scan result cards — 3 per page. */
function renderScanResults() {
    const listEl   = document.getElementById("scanResultsList");
    const results  = scanState.results;
    const pageSize = scanState.pageSize;

    if (!results.length) { listEl.innerHTML = ""; return; }

    const totalPages = Math.max(1, Math.ceil(results.length / pageSize));
    if (scanState.currentPage > totalPages) scanState.currentPage = totalPages;

    const start   = (scanState.currentPage - 1) * pageSize;
    const visible = results.slice(start, start + pageSize);

    listEl.innerHTML = "";

    // Meta row
    const meta = document.createElement("div");
    meta.className = "scan-meta";
    meta.innerHTML = `
        <span>${results.length} URL${results.length !== 1 ? "s" : ""} scanned</span>
        <span>Page ${scanState.currentPage} of ${totalPages}</span>
    `;
    listEl.appendChild(meta);

    // Cards
    const cards = document.createElement("div");
    cards.className = "scan-items";

    visible.forEach(item => {
        const card = document.createElement("div");
        card.className = "scan-item";

        const cls = item.whitelisted
            ? "neutral"
            : item.label === 1    ? "safe"
            : item.label === 0 && item.confidence >= 70 ? "danger"
            : item.label === 0    ? "warning"
            : "neutral";

        card.innerHTML = `
            <div class="scan-domain">${escHtml(item.domain)}</div>
            <div class="scan-url">${escHtml(item.url)}</div>
            <div class="scan-result ${cls}">${escHtml(item.result)}</div>
        `;

        if (!item.whitelisted && item.label === 0) {
            const wlBtn = document.createElement("button");
            wlBtn.className   = "whitelist-action-btn secondary small-btn";
            wlBtn.textContent = "Trust domain";
            wlBtn.style.marginTop = "8px";
            wlBtn.addEventListener("click", () => addDomainToWhitelist(item.domain));
            card.appendChild(wlBtn);
        }

        cards.appendChild(card);
    });

    listEl.appendChild(cards);

    // Pagination
    const pg = document.createElement("div");
    pg.className = "whitelist-pagination";
    pg.innerHTML = `
        <button class="whitelist-nav-btn" data-dir="prev" ${scanState.currentPage === 1 ? "disabled" : ""}>← Prev</button>
        <span class="whitelist-page-indicator">
            ${start + 1}–${Math.min(start + visible.length, results.length)} of ${results.length}
        </span>
        <button class="whitelist-nav-btn" data-dir="next" ${scanState.currentPage === totalPages ? "disabled" : ""}>Next →</button>
    `;
    pg.querySelector('[data-dir="prev"]').addEventListener("click", () => {
        if (scanState.currentPage > 1) { scanState.currentPage--; renderScanResults(); }
    });
    pg.querySelector('[data-dir="next"]').addEventListener("click", () => {
        if (scanState.currentPage < totalPages) { scanState.currentPage++; renderScanResults(); }
    });
    listEl.appendChild(pg);
}

// ─────────────────────────────────────────────────────────────────────────────
// Whitelist management
// ─────────────────────────────────────────────────────────────────────────────
function setWhitelistStatus(message, cssClass = "neutral") {
    const el = document.getElementById("whitelistStatus");
    if (!el) return;
    el.textContent = message;
    el.className   = `small-note ${cssClass}-note`;
}

function sortWhitelistDomains(domains) {
    return [...domains].sort((a, b) => a.localeCompare(b, undefined, { sensitivity: "base" }));
}

async function loadWhitelistEntries() {
    const listEl = document.getElementById("whitelistList");
    listEl.innerHTML = "<p class='small-note'>Loading whitelist…</p>";
    try {
        const res  = await fetch(`${API_BASE}/api/whitelist-domains`);
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || "Unable to load whitelist");
        whitelistState.domains     = sortWhitelistDomains(data.domains || []);
        whitelistState.currentPage = 1;
        renderWhitelistEntries(whitelistState.domains);
    } catch (err) {
        listEl.innerHTML = `<p class='small-note danger-note'>${err.message}</p>`;
    }
}

function renderWhitelistEntries(domains) {
    const listEl = document.getElementById("whitelistList");
    const sorted = sortWhitelistDomains(domains);
    whitelistState.domains = sorted;

    const filtered = whitelistState.searchTerm
        ? sorted.filter(d => d.toLowerCase().includes(whitelistState.searchTerm))
        : sorted;

    if (!sorted.length)    { listEl.innerHTML = "<p class='small-note'>No trusted domains yet.</p>"; return; }
    if (!filtered.length)  { listEl.innerHTML = "<p class='small-note'>No domains match your search.</p>"; return; }

    const totalPages = Math.max(1, Math.ceil(filtered.length / whitelistState.pageSize));
    if (whitelistState.currentPage > totalPages) whitelistState.currentPage = totalPages;

    const start   = (whitelistState.currentPage - 1) * whitelistState.pageSize;
    const visible = filtered.slice(start, start + whitelistState.pageSize);

    const panel = document.createElement("div");
    panel.className = "whitelist-panel";

    const meta = document.createElement("div");
    meta.className = "whitelist-meta";
    meta.innerHTML = `
        <span>${filtered.length} domain${filtered.length !== 1 ? "s" : ""}</span>
        <span>Page ${whitelistState.currentPage} of ${totalPages}</span>
    `;

    const ul = document.createElement("ul");
    ul.className = "whitelist-items";

    visible.forEach(domain => {
        const li  = document.createElement("li");
        li.className = "whitelist-item";

        const span = document.createElement("span");
        span.className   = "whitelist-domain";
        span.textContent = domain;

        const btn = document.createElement("button");
        btn.className   = "whitelist-remove-btn";
        btn.textContent = "Remove";
        btn.addEventListener("click", () => removeWhitelistDomain(domain));

        li.appendChild(span);
        li.appendChild(btn);
        ul.appendChild(li);
    });

    const pg = document.createElement("div");
    pg.className = "whitelist-pagination";
    pg.innerHTML = `
        <button class="whitelist-nav-btn" data-dir="prev" ${whitelistState.currentPage === 1 ? "disabled" : ""}>← Prev</button>
        <span class="whitelist-page-indicator">${start + 1}–${Math.min(start + visible.length, filtered.length)} of ${filtered.length}</span>
        <button class="whitelist-nav-btn" data-dir="next" ${whitelistState.currentPage === totalPages ? "disabled" : ""}>Next →</button>
    `;
    pg.querySelector('[data-dir="prev"]').addEventListener("click", () => {
        if (whitelistState.currentPage > 1) { whitelistState.currentPage--; renderWhitelistEntries(whitelistState.domains); }
    });
    pg.querySelector('[data-dir="next"]').addEventListener("click", () => {
        if (whitelistState.currentPage < totalPages) { whitelistState.currentPage++; renderWhitelistEntries(whitelistState.domains); }
    });

    panel.appendChild(meta);
    panel.appendChild(ul);
    panel.appendChild(pg);

    listEl.innerHTML = "";
    listEl.appendChild(panel);
}


function markScanResultsTrusted(domain) {
    const updated = scanState.results.map(item => {
        if (item.domain === domain && !item.whitelisted) {
            return {
                ...item,
                whitelisted: true,
                label: 1,
                result: "✅ Whitelisted",
                confidence: 100,
            };
        }
        return item;
    });

    scanState.results = updated;
    chrome.storage.local.set({ scanResults: updated });
    renderScanResults();
}

async function addDomainToWhitelist(domain) {
    const addBtn = document.getElementById("addWhitelistBtn");
    if (addBtn) addBtn.disabled = true;
    setWhitelistStatus("Adding domain…", "neutral");
    try {
        const res  = await fetch(`${API_BASE}/api/whitelist-domains`, {
            method : "POST",
            headers: { "Content-Type": "application/json" },
            body   : JSON.stringify({ domain }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.message || "Unable to add domain");
        setWhitelistStatus(`✅ ${domain} added to whitelist.`, "safe");
        markScanResultsTrusted(domain);
        whitelistState.currentPage = 1;
        await loadWhitelistEntries();
    } catch (err) {
        setWhitelistStatus(err.message, "danger");
    } finally {
        if (addBtn) addBtn.disabled = false;
    }
}

async function removeWhitelistDomain(domain) {
    try {
        const res  = await fetch(`${API_BASE}/api/whitelist-domains/${encodeURIComponent(domain)}`, { method: "DELETE" });
        const data = await res.json();
        if (!res.ok) throw new Error(data.message || "Unable to remove domain");
        setWhitelistStatus(`Removed ${domain}.`, "safe");
        whitelistState.currentPage = 1;
        await loadWhitelistEntries();
    } catch (err) {
        setWhitelistStatus(err.message, "danger");
    }
}

async function getCurrentDomain() {
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab?.url) return null;
        return new URL(tab.url).hostname.replace(/^www\./i, "").toLowerCase();
    } catch { return null; }
}

// ─────────────────────────────────────────────────────────────────────────────
// Backend health check
// ─────────────────────────────────────────────────────────────────────────────
async function checkBackendStatus() {
    const statusEl = document.getElementById("backendStatus");
    const dot      = document.querySelector(".status-dot");
    try {
        const res  = await fetch(`${API_BASE}/api/dashboard`);
        if (!res.ok) throw new Error();
        const data = await res.json();
        statusEl.textContent = `Backend connected (${data.models?.device ?? "cpu"})`;
        dot.classList.replace("offline", "online") || dot.classList.add("online");
        backendReady = true;
    } catch {
        statusEl.textContent = "Backend offline";
        dot.classList.replace("online", "offline") || dot.classList.add("offline");
        backendReady = false;
    }
    setScanButtonMode(currentScanMode);
    return backendReady;
}

// ─────────────────────────────────────────────────────────────────────────────
// Password — manual check
// ─────────────────────────────────────────────────────────────────────────────
async function checkPassword() {
    const password = document.getElementById("passwordInput").value.trim();
    const resultEl = document.getElementById("passwordResult");
    if (!password) { setResult(resultEl, "Please enter a password.", "warning"); return; }
    setResult(resultEl, "Checking…", "neutral");
    try {
        const res  = await fetch(`${API_BASE}/api/password-check`, {
            method : "POST",
            headers: { "Content-Type": "application/json" },
            body   : JSON.stringify({ password }),
        });
        const data = await res.json();
        if (data.error) { setResult(resultEl, data.error, "warning"); return; }
        const conf   = data.confidence;
        const detail = `  [W:${conf.weak}%  M:${conf.moderate}%  S:${conf.strong}%]`;
        setResult(resultEl, data.result + detail, resolveClass(data.result));
    } catch {
        setResult(resultEl, "Unable to connect to backend.", "danger");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Malware — manual file name check (AI model)
// ─────────────────────────────────────────────────────────────────────────────
async function checkFileName() {
    const filename   = document.getElementById("fileInput").value.trim();
    const resultEl   = document.getElementById("malwareResult");
    const reasonsEl  = document.getElementById("malwareReasons");
    if (!filename) { setResult(resultEl, "Please enter a file name.", "warning"); reasonsEl.textContent = ""; return; }
    setResult(resultEl, "Scanning…", "neutral");
    reasonsEl.textContent = "";
    try {
        const res  = await fetch(`${API_BASE}/api/malware-check`, {
            method : "POST",
            headers: { "Content-Type": "application/json" },
            body   : JSON.stringify({ filename }),
        });
        const data = await res.json();
        if (data.error) { setResult(resultEl, data.error, "warning"); return; }
        setResult(resultEl, `${data.result}  [confidence: ${data.confidence}%]`, resolveClass(data.result));
        if (data.reasons?.length) reasonsEl.textContent = "Why: " + data.reasons.join(" ");
    } catch {
        setResult(resultEl, "Unable to connect to backend.", "danger");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Malware — automatic download-scan history (populated by background.js)
// ─────────────────────────────────────────────────────────────────────────────
function loadMalwareResults() {
    chrome.storage.local.get(["malwareScanResults"], (res) => {
        renderMalwareResults(res.malwareScanResults || []);
    });
}

function watchMalwareResults() {
    chrome.storage.onChanged.addListener((changes, area) => {
        if (area !== "local" || !changes.malwareScanResults) return;
        renderMalwareResults(changes.malwareScanResults.newValue || []);
    });
}

function renderMalwareResults(results) {
    const listEl   = document.getElementById("malwareResultsList");
    const statusEl = document.getElementById("malwareAutoStatus");

    if (!results.length) {
        listEl.innerHTML = "";
        setResult(statusEl, "Watching downloads in the background…", "neutral");
        return;
    }

    const flagged = results.filter(r => r.label === 1).length;
    setResult(
        statusEl,
        `${results.length} download${results.length !== 1 ? "s" : ""} scanned — ${flagged} flagged.`,
        flagged > 0 ? "warning" : "safe"
    );

    const cards = document.createElement("div");
    cards.className = "scan-items";

    results.slice(0, 10).forEach(item => {
        const cls = item.label === 1
            ? (item.confidence >= 75 ? "danger" : "warning")
            : item.label === -1 ? "neutral" : "safe";

        const card = document.createElement("div");
        card.className = "scan-item";
        card.innerHTML = `
            <div class="scan-domain">${escHtml(item.filename)}</div>
            <div class="scan-url">${escHtml(item.sourceUrl || "unknown source")}</div>
            <div class="scan-result ${cls}">${escHtml(item.result)}${item.confidence ? `  (${item.confidence}%)` : ""}</div>
            ${item.reasons?.[0] ? `<div class="small-note">Why: ${escHtml(item.reasons[0])}</div>` : ""}
        `;
        cards.appendChild(card);
    });

    listEl.innerHTML = "";
    listEl.appendChild(cards);
}

async function clearMalwareResults() {
    await sendMessage({ action: "clearMalwareResults" });
    renderMalwareResults([]);
}

// ─────────────────────────────────────────────────────────────────────────────
// Detected-strength panel
// ─────────────────────────────────────────────────────────────────────────────
function loadDetectedStrength() {
    chrome.storage.local.get(["detectedStrength"], res => {
        const text = res.detectedStrength || "No password detected";
        setResult(document.getElementById("detectedStrengthText"), text, resolveClass(text));
    });
}

function watchDetectedStrength() {
    chrome.storage.onChanged.addListener((changes, area) => {
        if (area !== "local" || !changes.detectedStrength) return;
        const text = changes.detectedStrength.newValue || "No password detected";
        setResult(document.getElementById("detectedStrengthText"), text, resolveClass(text));
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Password generator
// ─────────────────────────────────────────────────────────────────────────────
function setupGenerator() {
    const genLength      = document.getElementById("genLength");
    const genLengthValue = document.getElementById("genLengthValue");
    const generateBtn    = document.getElementById("generatePasswordBtn");
    const copyBtn        = document.getElementById("copyPasswordBtn");
    const copyStatus     = document.getElementById("copyStatus");

    genLength.addEventListener("input", () => { genLengthValue.textContent = genLength.value; });

    generateBtn.addEventListener("click", async () => {
        const length    = parseInt(genLength.value, 10);
        const outputBox = document.getElementById("generatedPassword");
        outputBox.value        = "";
        copyStatus.textContent = "Generating a strong password…";
        copyStatus.className   = "small-note";
        generateBtn.disabled   = true;
        try {
            outputBox.value        = await generateStrongPassword(length);
            copyStatus.textContent = "✅ Strong password confirmed by AI model.";
            copyStatus.className   = "small-note safe-note";
        } catch {
            copyStatus.textContent = "⚠️ Backend offline — generated without model check.";
            copyStatus.className   = "small-note danger-note";
            outputBox.value = generateCandidate(length);
        } finally {
            generateBtn.disabled = false;
        }
    });

    copyBtn.addEventListener("click", async () => {
        const pw = document.getElementById("generatedPassword").value;
        if (!pw) { copyStatus.textContent = "Nothing to copy."; copyStatus.className = "small-note danger-note"; return; }
        try {
            await navigator.clipboard.writeText(pw);
            copyStatus.textContent = "Password copied to clipboard.";
            copyStatus.className   = "small-note safe-note";
        } catch {
            copyStatus.textContent = "Copy failed.";
            copyStatus.className   = "small-note danger-note";
        }
    });
}

async function generateStrongPassword(length, maxTries = 20) {
    for (let i = 1; i <= maxTries; i++) {
        const candidate = generateCandidate(length);
        const res  = await fetch(`${API_BASE}/api/password-verify`, {
            method : "POST",
            headers: { "Content-Type": "application/json" },
            body   : JSON.stringify({ password: candidate }),
        });
        const data = await res.json();
        if (data.strong === true) return candidate;
    }
    return generateCandidate(length);
}

function generateCandidate(length) {
    const upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const lower   = "abcdefghijklmnopqrstuvwxyz";
    const digits  = "0123456789";
    const special = "!@#$%^&*()_+{}[]<>?/";
    const all     = upper + lower + digits + special;
    const mandatory = [
        upper  [Math.floor(Math.random() * upper.length)],
        lower  [Math.floor(Math.random() * lower.length)],
        digits [Math.floor(Math.random() * digits.length)],
        special[Math.floor(Math.random() * special.length)],
    ];
    const rest = Array.from({ length: length - 4 }, () => all[Math.floor(Math.random() * all.length)]);
    return shuffleArray([...mandatory, ...rest]).join("");
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility helpers
// ─────────────────────────────────────────────────────────────────────────────
function setResult(el, text, cssClass) {
    el.textContent = text;
    el.className   = `result-text ${cssClass}`;
}

function resolveClass(text = "") {
    const t = text.toLowerCase();
    if (t.includes("safe") || t.includes("strong") || t.includes("no threat") || t.includes("whitelisted")) return "safe";
    if (t.includes("moderate") || t.includes("unsafe") || t.includes("maybe"))                              return "warning";
    if (t.includes("suspicious") || t.includes("weak") || t.includes("likely") || t.includes("phishing"))  return "danger";
    return "neutral";
}

function shuffleArray(arr) {
    for (let i = arr.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
}

function escHtml(str) {
    return String(str)
        .replace(/&/g, "&amp;").replace(/</g, "&lt;")
        .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function sendMessage(msg) {
    return new Promise((resolve, reject) => {
        chrome.runtime.sendMessage(msg, (response) => {
            if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
            else resolve(response);
        });
    });
}