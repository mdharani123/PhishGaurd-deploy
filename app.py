import os, re, json, ipaddress
from datetime import datetime
from urllib.parse import urlparse
from flask import Flask, render_template, request, jsonify
import requests

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

HISTORY_FILE = os.getenv("HISTORY_FILE", os.path.join("/tmp", "phishguard_scan_history.json"))
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()

SUSPICIOUS_WORDS = {
    "login", "verify", "verification", "secure", "account", "update",
    "password", "signin", "wallet", "banking", "confirm", "support",
    "bonus", "free", "gift", "invoice", "payment", "recover"
}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy"}
TRUSTED_EXAMPLES = {"google.com", "www.google.com", "microsoft.com", "www.microsoft.com"}

def load_history():
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return []

def save_history(history):
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(history[:30], f, indent=2)
    except OSError:
        pass

def normalize_url(raw):
    raw = raw.strip()
    if not raw:
        raise ValueError("Enter a URL to scan.")
    if len(raw) > 2048:
        raise ValueError("URL is too long.")
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a valid http:// or https:// URL.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded usernames or passwords are not accepted.")
    return raw, parsed

def heuristic_scan(url, parsed):
    host = (parsed.hostname or "").lower().rstrip(".")
    findings = []
    score = 0

    try:
        ipaddress.ip_address(host.strip("[]"))
        findings.append("The hostname is a raw IP address.")
        score += 2
    except ValueError:
        pass

    if host.startswith("xn--") or ".xn--" in host:
        findings.append("The domain uses internationalized/punycode characters.")
        score += 2

    if host in SHORTENERS:
        findings.append("The URL uses a link-shortening service, which hides the destination.")
        score += 1

    if "@" in url:
        findings.append("The URL contains an @ symbol that may disguise its destination.")
        score += 2

    if len(url) > 120:
        findings.append("The URL is unusually long.")
        score += 1

    if host.count("-") >= 3:
        findings.append("The hostname contains several hyphens.")
        score += 1

    labels = host.split(".")
    if len(labels) >= 5:
        findings.append("The hostname has many subdomain levels.")
        score += 1

    words = set(re.findall(r"[a-z]+", (host + " " + parsed.path + " " + parsed.query).lower()))
    matched = sorted(words & SUSPICIOUS_WORDS)
    if matched:
        findings.append("Contains terms often used in deceptive links: " + ", ".join(matched[:6]) + ".")
        score += min(2, len(matched))

    if parsed.scheme != "https":
        findings.append("The URL does not use HTTPS.")
        score += 1

    # Heuristic verdicts are intentionally conservative.
    if score >= 4:
        verdict, risk, color = "Potentially Phishing", "High", "danger"
    elif score >= 2:
        verdict, risk, color = "Suspicious — Review Carefully", "Medium", "warning"
    else:
        verdict, risk, color = "No Obvious Warning Signs", "Low", "safe"

    if not findings:
        findings.append("No obvious URL-pattern warning signs were detected.")
    return {
        "verdict": verdict, "risk": risk, "color": color,
        "score": score, "findings": findings,
        "domain": host, "scheme": parsed.scheme,
        "method": "Local URL-pattern heuristics"
    }

def virustotal_scan(url):
    if not VT_API_KEY:
        return None
    # VirusTotal's URL submission endpoint may add submitted indicators to its shared dataset.
    response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers={"x-apikey": VT_API_KEY, "accept": "application/json"},
        data={"url": url},
        timeout=12
    )
    response.raise_for_status()
    analysis_id = response.json().get("data", {}).get("id")
    if not analysis_id:
        return None
    # Poll briefly; some analyses take longer, so "pending" is a valid result.
    import time
    report = None
    for _ in range(3):
        time.sleep(2)
        r = requests.get(
            "https://www.virustotal.com/api/v3/analyses/" + analysis_id,
            headers={"x-apikey": VT_API_KEY, "accept": "application/json"},
            timeout=12
        )
        r.raise_for_status()
        report = r.json().get("data", {}).get("attributes", {})
        if report.get("status") == "completed":
            break
    if not report or report.get("status") != "completed":
        return {"status": "pending", "message": "Threat-intelligence analysis is still processing."}
    stats = report.get("stats", {})
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    if malicious:
        verdict, risk, color = "Potentially Phishing", "High", "danger"
    elif suspicious:
        verdict, risk, color = "Suspicious — Review Carefully", "Medium", "warning"
    else:
        verdict, risk, color = "No Threat Detected by Available Engines", "Low", "safe"
    return {
        "status": "completed", "verdict": verdict, "risk": risk, "color": color,
        "malicious": malicious, "suspicious": suspicious,
        "harmless": int(stats.get("harmless", 0)),
        "undetected": int(stats.get("undetected", 0)),
        "method": "VirusTotal API"
    }

@app.get("/")
def home():
    return render_template("index.html", history=load_history())

@app.post("/api/scan")
def scan():
    body = request.get_json(silent=True) or {}
    try:
        url, parsed = normalize_url(str(body.get("url", "")))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    result = heuristic_scan(url, parsed)
    vt_error = None
    if body.get("use_virustotal") and VT_API_KEY:
        try:
            vt = virustotal_scan(url)
            if vt and vt.get("status") == "completed":
                # Preserve heuristic indicators while using the threat-intel verdict.
                result.update(vt)
                result["findings"] = result.get("findings", [])
            elif vt:
                result["threat_intel"] = vt
        except requests.RequestException:
            vt_error = "Threat-intelligence service could not be reached; showing local analysis only."
        except (ValueError, KeyError, TypeError):
            vt_error = "Threat-intelligence response could not be interpreted; showing local analysis only."

    result["url"] = url
    result["scanned_at"] = datetime.now().astimezone().strftime("%b %d, %Y %H:%M")
    result["notice"] = "This is a screening result, not a guarantee. Do not open links you do not trust."
    if vt_error:
        result["threat_intel_note"] = vt_error

    history = load_history()
    history.insert(0, {
        "url": url, "verdict": result["verdict"], "risk": result["risk"],
        "scanned_at": result["scanned_at"], "color": result["color"]
    })
    save_history(history)
    return jsonify(result)

@app.post("/api/clear-history")
def clear_history():
    save_history([])
    return jsonify({"ok": True})

if __name__ == "__main__":
    # Local-only development server. Do not expose this debug-free app directly to the internet.
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False)
