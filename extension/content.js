// content.js  —  Cyber Defense Toolbox
// Detects password input fields and evaluates strength in real time
// by calling the Flask RNN backend instead of using local heuristics.

const CDT_API_BASE = "https://cyber-defense-toolbox.onrender.com";

// ─────────────────────────────────────────────────────────────────────────────
// Debounce: only fire the API call after the user pauses typing (350 ms)
// ─────────────────────────────────────────────────────────────────────────────
function debounce(fn, delay) {
    let timer;
    return (...args) => {
        clearTimeout(timer);
        timer = setTimeout(() => fn(...args), delay);
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Call the backend and return { label, name, confidence }
// Falls back to local heuristic if the backend is unreachable.
// ─────────────────────────────────────────────────────────────────────────────
async function evaluatePasswordStrength(password) {
    try {
        const response = await fetch(`${CDT_API_BASE}/api/password-check`, {
            method : "POST",
            headers: { "Content-Type": "application/json" },
            body   : JSON.stringify({ password }),
        });

        if (!response.ok) throw new Error("bad response");

        const data = await response.json();

        if (data.error) throw new Error(data.error);

        // data = { result, label (0|1|2), name, confidence }
        return {
            label     : data.label,       // 0 = Weak, 1 = Moderate, 2 = Strong
            name      : data.name,        // "Weak" | "Moderate" | "Strong"
            text      : `${data.name} Password`,
            color     : labelToColor(data.label),
            confidence: data.confidence,  // { weak, moderate, strong }
            fromModel : true,
        };
        

    } catch {
        // Backend unreachable — degrade gracefully to local heuristic
        return localFallback(password);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Local heuristic fallback (used only when backend is offline)
// ─────────────────────────────────────────────────────────────────────────────
function localFallback(password) {
    let score = 0;
    if (password.length >= 8)           score++;
    if (/[A-Z]/.test(password))         score++;
    if (/[a-z]/.test(password))         score++;
    if (/[0-9]/.test(password))         score++;
    if (/[^A-Za-z0-9]/.test(password))  score++;

    const label = score <= 2 ? 0 : score <= 4 ? 1 : 2;
    return {
        label,
        name      : ["Weak", "Moderate", "Strong"][label],
        text      : `${["Weak", "Moderate", "Strong"][label]} Password (offline)`,
        color     : labelToColor(label),
        confidence: null,
        fromModel : false,
    };
}

function labelToColor(label) {
    return ["#ef4444", "#f59e0b", "#22c55e"][label] ?? "#8ca0b8";
}

// ─────────────────────────────────────────────────────────────────────────────
// Show/hide indicator helpers
// ─────────────────────────────────────────────────────────────────────────────
function showIndicator(indicator) {
    indicator.style.display = "block";
}

function hideIndicator(indicator) {
    indicator.style.display = "none";
}

// ─────────────────────────────────────────────────────────────────────────────
// Floating indicator element anchored below the password input
// ─────────────────────────────────────────────────────────────────────────────
function createIndicator(input) {
    const box = document.createElement("div");
    box.style.cssText = `
        position:       absolute;
        padding:        5px 10px;
        border-radius:  8px;
        font-size:      12px;
        font-weight:    bold;
        z-index:        999999;
        color:          white;
        background:     #111827;
        box-shadow:     0 4px 10px rgba(0,0,0,0.25);
        pointer-events: none;
        white-space:    nowrap;
        transition:     background 0.2s ease;
        display:        none;
    `;
    document.body.appendChild(box);

    function reposition() {
        const rect     = input.getBoundingClientRect();
        box.style.top  = `${window.scrollY + rect.bottom + 8}px`;
        box.style.left = `${window.scrollX + rect.left}px`;
    }

    window.addEventListener("scroll", reposition, { passive: true });
    window.addEventListener("resize", reposition, { passive: true });
    reposition();

    return box;
}

// ─────────────────────────────────────────────────────────────────────────────
// Attach real-time checker to a single <input type="password">
// ─────────────────────────────────────────────────────────────────────────────
function attachPasswordChecker(input) {
    if (input.dataset.cdtAttached === "true") return;
    input.dataset.cdtAttached = "true";

    const indicator = createIndicator(input);

    // Show a "typing…" cue instantly; debounce the API call
    const debouncedEval = debounce(async (password) => {
        const result = await evaluatePasswordStrength(password);

        // Update floating indicator
        indicator.textContent      = result.text;
        indicator.style.background = result.color;

        // Persist for the popup panel
        chrome.storage.local.set({ detectedStrength: result.text });
    }, 350);

    input.addEventListener("input", function () {
        const password = input.value;

        if (!password) {
            hideIndicator(indicator);
            chrome.storage.local.set({ detectedStrength: "No password detected" });
            return;
        }

        // Show indicator and provide immediate optimistic feedback while the API call is in-flight
        showIndicator(indicator);
        indicator.textContent      = "Evaluating…";
        indicator.style.background = "#334155";

        debouncedEval(password);
    });

    // Clean up indicator if the input is removed from the DOM
    const removalObserver = new MutationObserver(() => {
        if (!document.body.contains(input)) {
            indicator.remove();
            removalObserver.disconnect();
        }
    });
    removalObserver.observe(document.body, { childList: true, subtree: true });
}

// ─────────────────────────────────────────────────────────────────────────────
// Scan for password fields — initial pass + watch for dynamic additions
// ─────────────────────────────────────────────────────────────────────────────
function detectPasswordFields() {
    document.querySelectorAll('input[type="password"]')
            .forEach(attachPasswordChecker);
}

detectPasswordFields();

const domObserver = new MutationObserver(() => detectPasswordFields());
if (document.body) {
    domObserver.observe(document.body, { childList: true, subtree: true });
}