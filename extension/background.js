

const API_BASE = "https://cyber-defense-toolbox.onrender.com";

// ── Storage keys ──────────────────────────────────────────────────────────────
const KEY_SCAN_STATUS  = "scanStatus";   // "idle" | "active" | "stopped"
const KEY_SCAN_RESULTS = "scanResults";  // ScanResult[]
const KEY_SCAN_START   = "scanStart";    // ISO timestamp — when session began
const KEY_SCAN_ELAPSED = "scanElapsed";  // seconds elapsed (updated every second)
const KEY_PHISH_ALERT  = "lastPhishingAlert";
const KEY_MALWARE_RESULTS = "malwareScanResults"; // auto-scanned downloads

// ── Runtime state (lost on service-worker restart, restored from storage) ─────
let scanActive   = false;   // true while a session is running
let scannedUrls  = new Set(); // domains already scanned this session (dedup)
let elapsedTimer = null;    // setInterval handle for the elapsed-seconds ticker
let sessionStart = null;    // Date object

// Maps a Chrome notification id -> the downloadId it refers to, so the
// Cancel/Keep buttons on a malware alert know which download to act on.
// (In-memory only — acceptable for a student project; if the service worker
// restarts mid-decision the download simply stays paused until the user
// resumes/cancels it manually from chrome://downloads.)
const pendingDownloadDecisions = new Map();


chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status !== "complete" || !tab.url) return;
    handleNewUrl(tab.url);
});

chrome.tabs.onActivated.addListener(({ tabId }) => {
    chrome.tabs.get(tabId, (tab) => {
        if (chrome.runtime.lastError || !tab?.url) return;
        handleNewUrl(tab.url);
    });
});


function handleNewUrl(url) {
    if (!scanActive) return;
    if (/^(chrome|edge|chrome-extension|about|data|blob):/.test(url)) return;

    const domain = extractDomain(url);
    if (scannedUrls.has(domain)) return;  // already scanned this domain
    scannedUrls.add(domain);

    scanUrl(url, domain);  // fire-and-forget — results written to storage
}


async function isBackendReachable() {
    try {
        const res = await fetch(`${API_BASE}/api/dashboard`);
        return res.ok;
    } catch {
        return false;
    }
}

async function scanUrl(url, domain) {
    try {
        // Check whitelist first
        const wlData   = await fetchJSON(`${API_BASE}/api/whitelist-domains`);
        const whitelist = wlData?.domains || [];

        if (whitelist.includes(domain)) {
            appendResult({ url, domain, label: 1, result: "✅ Whitelisted", confidence: 100, whitelisted: true });
            return;
        }

        const data       = await postJSON(`${API_BASE}/api/phishing-check`, { url });
        const label      = data.label ?? 1;
        const confidence = Number(data.confidence ?? 0);
        const resultText = label === 0
            ? (confidence >= 70
                ? `🚨 Likely phishing (${confidence}% confidence)`
                : `⚠️ Maybe phishing (${confidence}% confidence)`)
            : `✅ Safe (${confidence}% confidence)`;

        appendResult({ url, domain, label, result: resultText, confidence });

        if (label === 0 && confidence >= 70) {
            storeAndNotify(url, resultText);
        }
    } catch {
        appendResult({ url, domain, label: -1, result: "⚠️ Scan failed", confidence: 0 });
    }
}

function appendResult(item) {
    chrome.storage.local.get([KEY_SCAN_RESULTS], (res) => {
        const existing = res[KEY_SCAN_RESULTS] || [];
        chrome.storage.local.set({ [KEY_SCAN_RESULTS]: [...existing, item] });
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// MALWARE — automatic scanning of real downloads (chrome.downloads API)
// ─────────────────────────────────────────────────────────────────────────────
chrome.downloads.onCreated.addListener((item) => {
    scanDownload(item);
});

function basenameOf(pathOrUrl) {
    if (!pathOrUrl) return "";
    const clean = pathOrUrl.split(/[?#]/)[0];
    const parts = clean.split(/[\\/]/);
    return decodeURIComponent(parts[parts.length - 1] || "");
}

async function scanDownload(item) {
    const filename  = basenameOf(item.filename) || basenameOf(item.finalUrl || item.url);
    const sourceUrl = item.finalUrl || item.url || "";
    const fileSize  = typeof item.fileSize === "number" && item.fileSize > 0 ? item.fileSize : null;

    if (!filename) return;

    try {
        const backendOk = await isBackendReachable();
        if (!backendOk) {
            appendMalwareResult({
                filename, sourceUrl, label: -1,
                result: "⚠️ Scan skipped — backend offline", confidence: 0, reasons: [],
            });
            return;
        }

        const data = await postJSON(`${API_BASE}/api/malware-check`, {
            filename, fileSize, sourceUrl,
        });

        const label      = data.label ?? 0;
        const confidence = Number(data.confidence ?? 0);
        const reasons    = data.reasons || [];

        appendMalwareResult({ filename, sourceUrl, label, result: data.result, confidence, reasons });

        if (label === 1 && confidence >= 75) {
            // High-confidence malicious: pause the download and let the user decide.
            chrome.downloads.pause(item.id, () => void chrome.runtime.lastError);
            notifyMalwareDetected(item.id, filename, data.result, reasons, true);
        } else if (label === 1) {
            // Lower-confidence: warn only, don't interrupt the download.
            notifyMalwareDetected(item.id, filename, data.result, reasons, false);
        }
    } catch {
        appendMalwareResult({
            filename, sourceUrl, label: -1,
            result: "⚠️ Scan failed", confidence: 0, reasons: [],
        });
    }
}

function appendMalwareResult(item) {
    const entry = { ...item, timestamp: new Date().toISOString() };
    chrome.storage.local.get([KEY_MALWARE_RESULTS], (res) => {
        const existing = res[KEY_MALWARE_RESULTS] || [];
        const updated  = [entry, ...existing].slice(0, 25); // keep last 25
        chrome.storage.local.set({ [KEY_MALWARE_RESULTS]: updated });
    });
}

function notifyMalwareDetected(downloadId, filename, resultText, reasons, paused) {
    const notifId = `malware-${downloadId}-${Date.now()}`;
    const reasonLine = reasons?.[0] ? `\nWhy: ${reasons[0]}` : "";

    if (paused) {
        pendingDownloadDecisions.set(notifId, downloadId);
        chrome.notifications.create(notifId, {
            type       : "basic",
            iconUrl    : "img/logo.png",
            title      : "🚨 Malicious download paused",
            message    : `${filename}\n${resultText}${reasonLine}`,
            buttons    : [{ title: "Delete & keep blocked" }, { title: "It's safe — resume" }],
            requireInteraction: true,
        });
    } else {
        chrome.notifications.create(notifId, {
            type   : "basic",
            iconUrl: "img/logo.png",
            title  : "⚠️ Suspicious download",
            message: `${filename}\n${resultText}${reasonLine}`,
        });
    }
}

chrome.notifications.onButtonClicked.addListener((notifId, buttonIndex) => {
    const downloadId = pendingDownloadDecisions.get(notifId);
    if (downloadId === undefined) return;

    if (buttonIndex === 0) {
        // Delete & keep blocked
        chrome.downloads.cancel(downloadId, () => void chrome.runtime.lastError);
        chrome.downloads.removeFile(downloadId, () => void chrome.runtime.lastError);
    } else {
        // User confirms it's safe — resume the paused download
        chrome.downloads.resume(downloadId, () => void chrome.runtime.lastError);
    }

    pendingDownloadDecisions.delete(notifId);
    chrome.notifications.clear(notifId);
});

function startElapsedTicker() {
    sessionStart = new Date();
    chrome.storage.local.set({ [KEY_SCAN_START]: sessionStart.toISOString(), [KEY_SCAN_ELAPSED]: 0 });

    elapsedTimer = setInterval(() => {
        const secs = Math.floor((Date.now() - sessionStart.getTime()) / 1000);
        chrome.storage.local.set({ [KEY_SCAN_ELAPSED]: secs });
    }, 1000);
}

function stopElapsedTicker() {
    if (elapsedTimer) { clearInterval(elapsedTimer); elapsedTimer = null; }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

    // ── Start live scan session ───────────────────────────────────────────────
    if (message?.action === "startLiveScan") {
        (async () => {
            if (scanActive) { sendResponse({ started: false, reason: "Already scanning." }); return; }

            const backendOk = await isBackendReachable();
            if (!backendOk) {
                sendResponse({ started: false, reason: "Backend offline. Start the Flask backend before scanning." });
                return;
            }

            scanActive = true;
            scannedUrls.clear();

            chrome.storage.local.set({
                [KEY_SCAN_STATUS] : "active",
                [KEY_SCAN_RESULTS]: [],
            });
            startElapsedTicker();

            // Also immediately scan whichever tab is currently open
            chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                if (tabs[0]?.url) handleNewUrl(tabs[0].url);
            });

            sendResponse({ started: true });
        })();
        return true;
    }

    // ── Stop live scan session ────────────────────────────────────────────────
    if (message?.action === "stopLiveScan") {
        scanActive = false;
        stopElapsedTicker();
        chrome.storage.local.set({ [KEY_SCAN_STATUS]: "stopped" });
        sendResponse({ stopped: true });
        return true;
    }

    // ── Clear scan results & history ──────────────────────────────────────────
    if (message?.action === "clearScan") {
        scanActive = false;
        stopElapsedTicker();
        scannedUrls.clear();
        chrome.storage.local.set({
            [KEY_SCAN_STATUS] : "idle",
            [KEY_SCAN_RESULTS]: [],
            [KEY_SCAN_ELAPSED]: 0,
        });
        sendResponse({ success: true });
        return true;
    }

    // ── Clear malware download history ────────────────────────────────────────
    if (message?.action === "clearMalwareResults") {
        chrome.storage.local.set({ [KEY_MALWARE_RESULTS]: [] });
        sendResponse({ success: true });
        return true;
    }

    // ── Legacy single-URL phishing alert ─────────────────────────────────────
    if (message?.action === "phishingDetected") {
        storeAndNotify(message.url, message.result);
        sendResponse({ success: true });
        return true;
    }

    return false;
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. Restore state after service-worker restart
//    (SW can be killed by the browser at any time; we re-sync from storage)
// ─────────────────────────────────────────────────────────────────────────────
chrome.storage.local.get([KEY_SCAN_STATUS, KEY_SCAN_START], (res) => {
    if (res[KEY_SCAN_STATUS] === "active") {
        // Session was running before SW restarted — resume ticker from saved start
        scanActive   = true;
        sessionStart = res[KEY_SCAN_START] ? new Date(res[KEY_SCAN_START]) : new Date();
        startElapsedTicker();
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. Notifications
// ─────────────────────────────────────────────────────────────────────────────
function storeAndNotify(url, resultText) {
    chrome.storage.local.set({
        [KEY_PHISH_ALERT]: { url, result: resultText, timestamp: new Date().toISOString() }
    });
    chrome.alarms.create("phishing-alert", { delayInMinutes: 0.01 });
}

chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name !== "phishing-alert") return;
    chrome.storage.local.get([KEY_PHISH_ALERT], (res) => {
        const alert = res[KEY_PHISH_ALERT];
        if (!alert?.url) return;
        chrome.notifications.create({
            type    : "basic",
            iconUrl : "img/logo.png",
            title   : "🚨 Phishing Detected",
            message : `${alert.url}\n${alert.result}`,
        });
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// 7. Helpers
// ─────────────────────────────────────────────────────────────────────────────
function extractDomain(url) {
    try { return new URL(url).hostname.replace(/^www\./i, "").toLowerCase(); }
    catch { return url; }
}

async function fetchJSON(url) {
    const res = await fetch(url);
    return res.json();
}

async function postJSON(url, body) {
    const res = await fetch(url, {
        method : "POST",
        headers: { "Content-Type": "application/json" },
        body   : JSON.stringify(body),
    });
    return res.json();
}