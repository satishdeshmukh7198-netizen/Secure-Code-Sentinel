import os
import re
import json
from pathlib import Path
from datetime import datetime, timezone

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI(
    title="SecureCode Sentinel",
    description="AI-assisted source code security scanner",
    version="1.0.0",
)

# Never execute submitted code. This scanner only analyzes source text.

RULES = [
    {
        "id": "SEC001",
        "title": "Hardcoded secret or API key",
        "severity": "HIGH",
        "pattern": r"""(?i)(api[_-]?key|secret[_-]?key|password|access[_-]?token)\s*[:=]\s*["'][^"']{8,}["']""",
        "recommendation": "Move secrets into environment variables or a secrets manager.",
    },
    {
        "id": "SEC002",
        "title": "Possible SQL injection",
        "severity": "HIGH",
        "pattern": r"""(?i)(execute|executemany)\s*\(\s*["'][^"']*%s""",
        "recommendation": "Use parameterized queries instead of building SQL with string formatting.",
    },
    {
        "id": "SEC003",
        "title": "Use of eval()",
        "severity": "HIGH",
        "pattern": r"\beval\s*\(",
        "recommendation": "Avoid eval() on untrusted input. Use safer parsing methods.",
    },
    {
        "id": "SEC004",
        "title": "Use of exec()",
        "severity": "MEDIUM",
        "pattern": r"\bexec\s*\(",
        "recommendation": "Avoid dynamically executing strings, especially when they contain user input.",
    },
    {
        "id": "SEC005",
        "title": "Disabled TLS certificate verification",
        "severity": "HIGH",
        "pattern": r"""(?i)(verify\s*=\s*False|CERT_NONE)""",
        "recommendation": "Enable TLS certificate verification.",
    },
    {
        "id": "SEC006",
        "title": "Potentially unsafe deserialization",
        "severity": "HIGH",
        "pattern": r"\bpickle\.loads?\s*\(",
        "recommendation": "Never deserialize untrusted pickle data. Use a safer data format.",
    },
    {
        "id": "SEC007",
        "title": "Possible command injection",
        "severity": "HIGH",
        "pattern": r"""(?i)(os\.system|subprocess\.Popen|subprocess\.call)\s*\(""",
        "recommendation": "Avoid shell execution with user-controlled input. Prefer argument lists and validate inputs.",
    },
    {
        "id": "SEC008",
        "title": "Weak hash algorithm",
        "severity": "MEDIUM",
        "pattern": r"""(?i)(hashlib\.)?(md5|sha1)\s*\(""",
        "recommendation": "Use SHA-256 or a suitable modern cryptographic algorithm.",
    },
    {
        "id": "SEC009",
        "title": "Wildcard CORS configuration",
        "severity": "MEDIUM",
        "pattern": r"""(?i)(allow_origins\s*=\s*\[\s*["']\*["']\s*\]|Access-Control-Allow-Origin["']?\s*[:,=]\s*["']\*["'])""",
        "recommendation": "Restrict cross-origin requests to trusted origins.",
    },
    {
        "id": "SEC010",
        "title": "Debug mode enabled",
        "severity": "LOW",
        "pattern": r"""(?i)\bdebug\s*=\s*True\b""",
        "recommendation": "Disable debug mode in production.",
    },
]


class ScanRequest(BaseModel):
    code: str
    filename: str = "source.py"


def scan_source(code: str, filename: str = "source.py") -> dict:
    findings = []

    for rule in RULES:
        for match in re.finditer(rule["pattern"], code):
            line_number = code.count("\n", 0, match.start()) + 1

            findings.append({
                "id": rule["id"],
                "title": rule["title"],
                "severity": rule["severity"],
                "line": line_number,
                "matched_text": match.group(0)[:100],
                "recommendation": rule["recommendation"],
            })

    severity_counts = {
        "HIGH": sum(f["severity"] == "HIGH" for f in findings),
        "MEDIUM": sum(f["severity"] == "MEDIUM" for f in findings),
        "LOW": sum(f["severity"] == "LOW" for f in findings),
    }

    # A simple heuristic, not a formal security rating.
    deductions = {"HIGH": 20, "MEDIUM": 10, "LOW": 5}
    score = max(
        0,
        100 - sum(deductions[f["severity"]] for f in findings),
    )

    return {
        "filename": filename,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "security_score": score,
        "risk_level": (
            "CRITICAL" if severity_counts["HIGH"] >= 3
            else "HIGH" if severity_counts["HIGH"] > 0
            else "MEDIUM" if severity_counts["MEDIUM"] > 0
            else "LOW" if severity_counts["LOW"] > 0
            else "NO PATTERNS DETECTED"
        ),
        "summary": {
            "total_findings": len(findings),
            "high": severity_counts["HIGH"],
            "medium": severity_counts["MEDIUM"],
            "low": severity_counts["LOW"],
        },
        "findings": findings,
        "limitations": (
            "Pattern-based analysis only. Results may include false positives "
            "and false negatives; this is not a substitute for a full security audit."
        ),
    }


@app.get("/", response_class=HTMLResponse)
async def home():
    return """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecureCode Sentinel</title>
<style>
body {
    margin: 0;
    font-family: Arial, sans-serif;
    background: #0b1020;
    color: #edf2ff;
}
header {
    padding: 28px;
    text-align: center;
    background: #141c33;
    border-bottom: 1px solid #293552;
}
header h1 { margin: 0 0 10px; color: #71e6c1; }
main { max-width: 1000px; margin: 30px auto; padding: 20px; }
.panel {
    background: #141c33;
    padding: 22px;
    border: 1px solid #293552;
    border-radius: 12px;
    margin-bottom: 20px;
}
textarea {
    width: 100%;
    min-height: 260px;
    box-sizing: border-box;
    padding: 14px;
    background: #090e1b;
    color: #e7edff;
    border: 1px solid #354361;
    border-radius: 8px;
    font-family: Consolas, monospace;
    resize: vertical;
}
input, button {
    padding: 12px;
    border-radius: 7px;
    margin: 8px 5px 8px 0;
}
input {
    background: #090e1b;
    color: white;
    border: 1px solid #354361;
}
button {
    background: #71e6c1;
    border: none;
    font-weight: bold;
    cursor: pointer;
}
button:hover { background: #4ec9a4; }
.stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 12px;
}
.stat {
    padding: 16px;
    border-radius: 8px;
    background: #202b47;
}
.stat strong { font-size: 26px; display: block; }
.finding {
    padding: 15px;
    margin: 12px 0;
    border-radius: 8px;
    background: #202b47;
    border-left: 5px solid #71e6c1;
    overflow-wrap: anywhere;
}
.HIGH { border-color: #ff647c; }
.MEDIUM { border-color: #ffca68; }
.LOW { border-color: #71e6c1; }
.muted { color: #aab6d2; }
#error { color: #ff8a9c; }
pre { white-space: pre-wrap; overflow-wrap: anywhere; }
</style>
</head>
<body>
<header>
    <h1>🛡 SecureCode Sentinel</h1>
    <p>Source Code Security Scanner</p>
    <span class="muted">Identify potentially risky coding patterns before deployment.</span>
</header>
<main>
    <section class="panel">
        <h2>Analyze Your Code</h2>
        <label for="filename">Filename</label><br>
        <input id="filename" value="source.py" aria-label="Filename">
        <textarea id="code" spellcheck="false"
placeholder="Paste your Python, JavaScript, or other source code here..."></textarea>
        <br>
        <button onclick="scanCode()">Scan Code</button>
        <button onclick="document.getElementById('file').click()">Upload File</button>
        <button onclick="downloadReport()">Export JSON Report</button>
        <input id="file" type="file" hidden onchange="loadFile(event)">
        <p id="error"></p>
    </section>
    <section id="results" class="panel" hidden>
        <h2>Scan Results</h2>
        <div class="stats">
            <div class="stat">Security Score<strong id="score">—</strong></div>
            <div class="stat">Total Findings<strong id="total">0</strong></div>
            <div class="stat">High<strong id="high">0</strong></div>
            <div class="stat">Medium<strong id="medium">0</strong></div>
            <div class="stat">Low<strong id="low">0</strong></div>
        </div>
        <h3 id="risk"></h3>
        <div id="findings"></div>
        <p class="muted" id="limitations"></p>
    </section>
</main>
<script>
let latestReport = null;

async function scanCode() {
    const code = document.getElementById("code").value;
    const filename = document.getElementById("filename").value || "source.py";
    const error = document.getElementById("error");
    error.textContent = "";

    if (!code.trim()) {
        error.textContent = "Please enter or upload source code first.";
        return;
    }

    try {
        const response = await fetch("/api/scan", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({code, filename})
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || "Scan failed.");
        }

        latestReport = data;
        renderResults(data);
    } catch (err) {
        error.textContent = err.message || "Could not connect to the scanner.";
    }
}

function renderResults(data) {
    document.getElementById("results").hidden = false;
    document.getElementById("score").textContent = data.security_score + "/100";
    document.getElementById("total").textContent = data.summary.total_findings;
    document.getElementById("high").textContent = data.summary.high;
    document.getElementById("medium").textContent = data.summary.medium;
    document.getElementById("low").textContent = data.summary.low;
    document.getElementById("risk").textContent = "Risk Level: " + data.risk_level;
    document.getElementById("limitations").textContent = data.limitations;

    const container = document.getElementById("findings");
    container.replaceChildren();

    if (data.findings.length === 0) {
        const message = document.createElement("p");
        message.textContent = "No configured risky patterns were detected. This does not guarantee that the code is secure.";
        container.appendChild(message);
        return;
    }

    for (const finding of data.findings) {
        const card = document.createElement("article");
        card.className = "finding " + finding.severity;

        const title = document.createElement("h3");
        title.textContent = finding.title + " (" + finding.severity + ")";

        const location = document.createElement("p");
        location.textContent = "Rule: " + finding.id + " | Line: " + finding.line;

        const matched = document.createElement("pre");
        matched.textContent = "Matched text: " + finding.matched_text;

        const recommendation = document.createElement("p");
        recommendation.textContent = "Recommendation: " + finding.recommendation;

        card.append(title, location, matched, recommendation);
        container.appendChild(card);
    }
}

function loadFile(event) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = () => {
        document.getElementById("code").value = reader.result;
        document.getElementById("filename").value = file.name;
    };
    reader.readAsText(file);
}

function downloadReport() {
    if (!latestReport) {
        document.getElementById("error").textContent = "Run a scan before exporting.";
        return;
    }

    const blob = new Blob(
        [JSON.stringify(latestReport, null, 2)],
        {type: "application/json"}
    );

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "securecode-report.json";
    link.click();
    URL.revokeObjectURL(url);
}
</script>
</body>
</html>
"""


@app.post("/api/scan")
async def scan_api(request: ScanRequest):
    if not request.code.strip():
        raise HTTPException(status_code=400, detail="Code cannot be empty.")

    if len(request.code) > 1_000_000:
        raise HTTPException(status_code=413, detail="Code exceeds the 1 MB limit.")

    return scan_source(request.code, request.filename)


@app.post("/api/scan-file")
async def scan_file(file: UploadFile = File(...)):
    allowed_extensions = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".java",
        ".php", ".go", ".rb", ".c", ".cpp", ".cs",
        ".html", ".css", ".json", ".yaml", ".yml",
    }

    filename = Path(file.filename or "source.txt").name

    if Path(filename).suffix.lower() not in allowed_extensions:
        raise HTTPException(status_code=400, detail="Unsupported file extension.")

    content = await file.read(1_000_001)

    if len(content) > 1_000_000:
        raise HTTPException(status_code=413, detail="File exceeds the 1 MB limit.")

    try:
        code = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be UTF-8 text.")

    return scan_source(code, filename)


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "service": "SecureCode Sentinel",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8001)