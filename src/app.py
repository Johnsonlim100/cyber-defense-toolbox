import re
import sys
import json
import tldextract
import numpy as np
import joblib
import torch
import torch.nn as nn

from pathlib import Path
from urllib.parse import urlparse
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)   

BASE_DIR = Path(__file__).resolve().parent

# must be absolute path 
phishing_model_path = BASE_DIR / "phishing" / "phishing_rf_model.joblib"
phishing_model = joblib.load(phishing_model_path)

# ── Malware detection model (RandomForest trained on filename/size/URL features) ──
sys.path.insert(0, str(BASE_DIR / "malware"))
from malware_features import (          # noqa: E402  (import after sys.path tweak)
    extract_malware_features,
    DOUBLE_EXT_PATTERN,
    SUSPICIOUS_KEYWORDS,
    LURE_KEYWORDS,
    HEX_RANDOM_PATTERN,
    EXECUTABLE_EXTS,
    MACRO_OFFICE_EXTS,
)

malware_model_path = BASE_DIR / "malware" / "malware_rf_model.joblib"
malware_model = joblib.load(malware_model_path)


def explain_malware_flags(filename: str, file_size: int | None, source_url: str | None) -> list[str]:
    """Human-readable reasons behind a malware verdict, for UI transparency."""
    reasons = []
    ext_match = re.search(r"\.([a-z0-9]+)$", filename, re.IGNORECASE)
    ext = ext_match.group(1).lower() if ext_match else ""

    if DOUBLE_EXT_PATTERN.search(filename):
        reasons.append("Double file extension detected (e.g. photo.jpg.exe) — a classic disguise trick.")
    if SUSPICIOUS_KEYWORDS.search(filename):
        reasons.append("Filename contains a known malicious keyword (crack, keygen, loader, etc.).")
    if LURE_KEYWORDS.search(filename) and ext in EXECUTABLE_EXTS:
        reasons.append("Looks like a document/invoice lure but is actually an executable.")
    if HEX_RANDOM_PATTERN.search(filename):
        reasons.append("Filename looks like a randomly generated string, typical of dropped payloads.")
    if ext in MACRO_OFFICE_EXTS:
        reasons.append("Macro-enabled Office file — a common vector for malicious macros.")
    if file_size is not None and ext in EXECUTABLE_EXTS and file_size < 51_200:
        reasons.append("Unusually small executable (<50KB) for a real installer — typical of a loader.")
    if source_url and SUSPICIOUS_KEYWORDS.search(source_url):
        reasons.append("Source URL itself contains suspicious keywords.")
    if not reasons:
        reasons.append("No strong individual red flags — verdict is based on the overall feature pattern.")
    return reasons

whitelist_path = BASE_DIR / "phishing" / "whitelistDomain.txt"


def load_whitelist_entries() -> list[str]:
    if not whitelist_path.exists():
        return []
    with whitelist_path.open("r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def save_whitelist_entries(entries: list[str]) -> None:
    with whitelist_path.open("w", encoding="utf-8") as f:
        for entry in entries:
            if entry.strip():
                f.write(entry.strip() + "\n")


def normalize_whitelist_entry(value: str) -> str:
    value = str(value).strip().strip("/")
    if not value:
        return ""

    hostname = normalize_hostname(value)
    if hostname.startswith("www."):
        hostname = hostname[4:]
    return hostname.lower().strip(".")


def add_whitelist_entry(domain: str) -> tuple[bool, str]:
    normalized = normalize_whitelist_entry(domain)
    if not normalized:
        return False, "Please provide a valid domain."

    global whitelist_entries
    if normalized in whitelist_entries:
        return False, f"{normalized} is already in the whitelist."

    whitelist_entries.append(normalized)
    save_whitelist_entries(whitelist_entries)
    return True, normalized


def remove_whitelist_entry(domain: str) -> tuple[bool, str]:
    normalized = normalize_whitelist_entry(domain)
    if not normalized:
        return False, "Please provide a valid domain."

    global whitelist_entries
    if normalized not in whitelist_entries:
        return False, f"{normalized} is not in the whitelist."

    whitelist_entries = [entry for entry in whitelist_entries if entry != normalized]
    save_whitelist_entries(whitelist_entries)
    return True, normalized


whitelist_entries = load_whitelist_entries()


def normalize_hostname(url: str) -> str:
    """Return the hostname for a URL, handling missing schemes safely."""
    url = str(url).strip()
    if not url:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = f"https://{url}"
    parsed = urlparse(url)
    return (parsed.hostname or "").lower()


def is_whitelisted_domain(url: str) -> tuple[bool, str | None]:
    """Check whether the URL's hostname matches a whitelist entry."""
    hostname = normalize_hostname(url)
    if not hostname:
        return False, None

    for entry in whitelist_entries:
        if not entry or entry.startswith("#"):
            continue

        if entry.startswith("ALL "):
            suffix = entry[4:].strip().lstrip(".").lower()
            if hostname == suffix or hostname.endswith(f".{suffix}"):
                return True, entry
            continue

        if entry.startswith("REG "):
            pattern = entry[4:].strip()
            try:
                if re.search(pattern, hostname, re.IGNORECASE):
                    return True, entry
            except re.error:
                continue
            continue

        if entry.startswith("RZD "):
            value = entry[4:].strip().lower()
            if hostname == value or hostname.endswith(f".{value}"):
                return True, entry
            continue

        candidate = entry.lower().lstrip(".")
        if hostname == candidate or hostname.endswith(f".{candidate}"):
            return True, entry

    return False, None


def extract_url_features(url: str) -> list:
    """Extract the same 30+ lexical features used during training."""
    url = str(url)
    ext = tldextract.extract(url)

    features = [
        len(url),
        len(ext.domain),
        len(url.split("/", 3)[-1]) if "/" in url else 0,
        len(ext.subdomain),
        len(ext.suffix),
        url.count("."),
        url.count("-"),
        url.count("_"),
        url.count("/"),
        url.count("?"),
        url.count("="),
        url.count("@"),
        url.count("&"),
        url.count("!"),
        url.count(" "),
        url.count("~"),
        url.count(","),
        url.count("+"),
        url.count("*"),
        url.count("#"),
        url.count("$"),
        url.count("%"),
        sum(c.isdigit() for c in url),
        sum(c.isdigit() for c in url) / max(len(url), 1),   # digit_ratio
        sum(c.isalpha() for c in url) / max(len(url), 1),   # letter_ratio
        int(url.startswith("https")),
        int(url.startswith("http://")),
        int(bool(re.search(r"(\d{1,3}\.){3}\d{1,3}", url))),
        int("@" in url),
        int("//" in url[7:]),
        int("%" in url),
        int(bool(re.search(r":\d{2,5}/", url))),
        len(ext.subdomain.split(".")) if ext.subdomain else 0,
        int(ext.domain in {
            "bit", "tinyurl", "goo", "t", "ow",
            "is", "cli", "yfrog", "migre"
        }),
        len(re.split(r"[\W_]+", url)),
        int(bool(re.search(
            r"login|verify|update|secure|account|banking|confirm"
            r"|password|signin|ebayisapi|webscr|paypal|free|lucky"
            r"|service|bonus",
            url, re.IGNORECASE
        ))),
    ]
    return features


with open(BASE_DIR / "password" / "char2idx.json", "r") as f:
    char2idx: dict = json.load(f)

class PasswordRNN(nn.Module):
    def __init__(self, vocab_size, embed_dim, hidden_dim,
                 num_layers, num_classes, dropout):
        super().__init__()
        self.embedding = nn.Embedding(
            num_embeddings=vocab_size,
            embedding_dim=embed_dim,
            padding_idx=0
        )
        self.lstm = nn.LSTM(
            input_size=embed_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0,
            bidirectional=True
        )
        self.dropout    = nn.Dropout(dropout)
        self.layer_norm = nn.LayerNorm(hidden_dim * 2)
        self.fc = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, num_classes)
        )

    def forward(self, x):
        emb = self.embedding(x)
        _, (hidden, _) = self.lstm(emb)
        fwd = hidden[-2]
        bwd = hidden[-1]
        combined = torch.cat([fwd, bwd], dim=1)
        combined = self.layer_norm(combined)
        combined = self.dropout(combined)
        return self.fc(combined)


_pw_device    = torch.device("cuda" if torch.cuda.is_available() else "cpu")
_pw_checkpoint = torch.load(
    BASE_DIR / "password" / "password_rnn_full.pt",
    map_location=_pw_device
)
_cfg = _pw_checkpoint["config"]

password_model = PasswordRNN(
    vocab_size  = _cfg["vocab_size"],
    embed_dim   = _cfg["embed_dim"],
    hidden_dim  = _cfg["hidden_dim"],
    num_layers  = _cfg["num_layers"],
    num_classes = _cfg["num_classes"],
    dropout     = _cfg["dropout"],
).to(_pw_device)

password_model.load_state_dict(_pw_checkpoint["model_state_dict"])
password_model.eval()

MAX_LEN       = _cfg["max_len"]
LABEL_NAMES   = ["Weak", "Moderate", "Strong"]
LABEL_CLASSES = {0: "weak", 1: "moderate", 2: "strong"}


def encode_password(pw: str) -> list:
    encoded = [char2idx.get(ch, 0) for ch in str(pw)[:MAX_LEN]]
    return encoded + [0] * (MAX_LEN - len(encoded))


def predict_password_strength(password: str) -> dict:
    """Return label index (0/1/2), label name, and confidence dict."""
    tensor = torch.tensor([encode_password(password)],
                          dtype=torch.long).to(_pw_device)
    with torch.no_grad():
        logits = password_model(tensor)
        probs  = torch.softmax(logits, dim=1).cpu().numpy()[0]
    label = int(np.argmax(probs))
    return {
        "label"      : label,
        "name"       : LABEL_NAMES[label],
        "confidence" : {
            "weak"    : round(float(probs[0]) * 100, 1),
            "moderate": round(float(probs[1]) * 100, 1),
            "strong"  : round(float(probs[2]) * 100, 1),
        }
    }



@app.route("/api/dashboard", methods=["GET"])
def dashboard():
    return jsonify({
        "status" : "online",
        "models" : {
            "phishing" : "RandomForest (joblib)",
            "password" : "BiLSTM (PyTorch)",
            "malware"  : "RandomForest (joblib)",
            "device"   : str(_pw_device)
        }
    })


@app.route("/api/phishing-check", methods=["POST"])
def phishing_check():
    data = request.get_json(silent=True) or {}
    url  = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "No URL provided."}), 400

    try:
        whitelisted, matched_rule = is_whitelisted_domain(url)
        if whitelisted:
            return jsonify({
                "result"      : "✅ Safe — This domain is in the whitelist.",
                "label"       : 1,
                "confidence"  : 100.0,
                "source"      : "whitelist",
                "matched_rule": matched_rule,
            })

        features = np.array([extract_url_features(url)], dtype=float)
        pred     = phishing_model.predict(features)[0]
        proba    = phishing_model.predict_proba(features)[0]

        if pred == 1:
            result     = "✅ Safe — This website appears legitimate."
            confidence = round(float(proba[1]) * 100, 1)
        else:
            confidence = round(float(proba[0]) * 100, 1)
            result = (
                "🚨 Likely phishing — This website appears to be a phishing attempt."
                if confidence >= 70.0
                else "⚠️ Maybe phishing — This website could be a phishing attempt."
            )

        return jsonify({
            "result"    : result,
            "label"     : int(pred),
            "confidence": confidence,
            "source"    : "model"
        })

    except Exception as e:
        return jsonify({"error": f"Prediction failed: {str(e)}"}), 500


@app.route("/api/whitelist-domains", methods=["GET"])
def whitelist_domains():
    return jsonify({"domains": whitelist_entries})


@app.route("/api/whitelist-domains", methods=["POST"])
def add_whitelist_domain():
    data = request.get_json(silent=True) or {}
    domain = data.get("domain", "").strip()

    success, message = add_whitelist_entry(domain)
    status_code = 200 if success else 400
    return jsonify({
        "success": success,
        "message": message,
        "domains": whitelist_entries,
    }), status_code


@app.route("/api/whitelist-domains/<path:domain>", methods=["DELETE"])
def remove_whitelist_domain(domain: str):
    success, message = remove_whitelist_entry(domain)
    status_code = 200 if success else 404
    return jsonify({
        "success": success,
        "message": message,
        "domains": whitelist_entries,
    }), status_code


@app.route("/api/password-check", methods=["POST"])
def password_check():
    data     = request.get_json(silent=True) or {}
    password = data.get("password", "")

    if not password:
        return jsonify({"error": "No password provided."}), 400

    try:
        info = predict_password_strength(password)
        label_map = {
            0: "🔴 Weak Password — easily guessable.",
            1: "🟡 Moderate Password — could be stronger.",
            2: "🟢 Strong Password — well done!",
        }
        return jsonify({
            "result"    : label_map[info["label"]],
            "label"     : info["label"],
            "name"      : info["name"],
            "confidence": info["confidence"],
        })
    except Exception as e:
        return jsonify({"error": f"Prediction failed: {str(e)}"}), 500


@app.route("/api/password-verify", methods=["POST"])
def password_verify():
    """
    Lightweight endpoint used by the generator.
    Returns { "strong": true/false, "label": 0|1|2, "name": "..." }
    so the frontend can loop until a strong password is produced.
    """
    data     = request.get_json(silent=True) or {}
    password = data.get("password", "")

    if not password:
        return jsonify({"error": "No password provided."}), 400

    try:
        info = predict_password_strength(password)
        return jsonify({
            "strong": info["label"] == 2,
            "label" : info["label"],
            "name"  : info["name"],
        })
    except Exception as e:
        return jsonify({"error": f"Prediction failed: {str(e)}"}), 500


@app.route("/api/malware-check", methods=["POST"])
def malware_check():
    """
    ML-based malware detector (RandomForest trained on filename, file-size,
    and source-URL derived features — see src/malware/train_malware_model.py).

    Accepts:
      filename    (required) — e.g. "invoice_2024.pdf.exe"
      fileSize    (optional) — bytes, from chrome.downloads for auto-scans
      sourceUrl   (optional) — the URL the file was downloaded from

    Works with filename only (manual check) or with the extra signals
    supplied automatically when a real download is intercepted.
    """
    data       = request.get_json(silent=True) or {}
    filename   = (data.get("filename") or "").strip()
    source_url = (data.get("sourceUrl") or "").strip() or None

    raw_size = data.get("fileSize")
    try:
        file_size = int(raw_size) if raw_size not in (None, "", -1) else None
    except (TypeError, ValueError):
        file_size = None

    if not filename:
        return jsonify({"error": "No filename provided."}), 400

    try:
        features   = np.array([extract_malware_features(filename, file_size, source_url)], dtype=float)
        pred       = int(malware_model.predict(features)[0])
        proba      = malware_model.predict_proba(features)[0]
        confidence = round(float(proba[pred]) * 100, 1)
        reasons    = explain_malware_flags(filename, file_size, source_url)

        if pred == 1:
            result = (
                "🚨 Likely malicious — This file shows strong malware indicators."
                if confidence >= 75.0
                else "⚠️ Suspicious — This file has some risk indicators, review before opening."
            )
        else:
            result = "✅ No threat detected — File appears safe."

        return jsonify({
            "result"    : result,
            "label"     : pred,
            "confidence": confidence,
            "reasons"   : reasons,
            "source"    : "model",
        })
    except Exception as e:
        return jsonify({"error": f"Prediction failed: {str(e)}"}), 500


# ══════════════════════════════════════════════════════════════════════════════
# 4.  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import os
    port  = int(os.environ.get("PORT", 5000))
    host  = "0.0.0.0" if os.environ.get("PORT") else "127.0.0.1"
    print("🚀  Cyber Defense Toolbox backend starting…")
    print(f"    Phishing model : phishing/phishing_rf_model.joblib")
    print(f"    Password model : password/password_rnn_full.pt  (device={_pw_device})")
    print(f"    Listening on   : {host}:{port}")
    app.run(host=host, port=port, debug=False)