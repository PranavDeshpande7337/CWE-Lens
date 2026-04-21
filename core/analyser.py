"""
core/analyser.py
Sends code chunks to a locally running Ollama model and parses
the structured vulnerability findings back out.

The analyser is the core of the tool — it:
  1. Builds a security-focused prompt for each chunk
  2. Calls the Ollama REST API (localhost:11434)
  3. Parses the JSON findings the model returns
  4. Normalises them into Finding objects
"""

import json
import requests
from dataclasses import dataclass, field
from core.chunker import CodeChunk


# ── Data model ─────────────────────────────────────────────────────────────

@dataclass
class Finding:
    """A single security vulnerability finding."""
    file_path:   str
    chunk_name:  str
    line_number: int          # best-effort line number from the model
    cwe_id:      str          # e.g. "CWE-89"
    cwe_name:    str          # e.g. "SQL Injection"
    severity:    str          # critical | high | medium | low | info
    title:       str          # short description
    description: str          # detailed explanation
    code_snippet: str         # the vulnerable code the model identified
    recommendation: str       # how to fix it
    confidence:  str          # high | medium | low


# Severity ordering for sorting findings
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ── Ollama client ──────────────────────────────────────────────────────────

OLLAMA_URL    = "http://localhost:11434/api/generate"
DEFAULT_MODEL = "codellama"
TIMEOUT       = 120  # seconds — local models can be slow on first run


def check_ollama_running() -> tuple[bool, str]:
    """
    Check whether Ollama is running and the model is available.
    Returns (True, model_name) or (False, error_message).
    """
    try:
        resp = requests.get("http://localhost:11434/api/tags", timeout=5)
        if resp.status_code == 200:
            models = [m["name"] for m in resp.json().get("models", [])]
            # Check for codellama in any variant (codellama, codellama:13b, etc.)
            available = [m for m in models if "codellama" in m.lower() or "llama" in m.lower()]
            if available:
                return True, available[0]
            else:
                return False, f"No suitable model found. Available: {models}. Run: ollama pull codellama"
        return False, f"Ollama returned HTTP {resp.status_code}"
    except requests.ConnectionError:
        return False, "Ollama is not running. Start it with: ollama serve"
    except Exception as e:
        return False, str(e)


def analyse_chunk(chunk: CodeChunk, model: str = DEFAULT_MODEL) -> list[Finding]:
    """
    Send a single code chunk to Ollama for vulnerability analysis.

    Returns a list of Finding objects (may be empty if no issues found).
    """
    prompt = _build_prompt(chunk)

    payload = {
        "model":  model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.1,   # low temperature = more consistent, less creative
            "num_predict": 2048,
        }
    }

    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=TIMEOUT)
        response.raise_for_status()
        raw_text = response.json().get("response", "")
        return _parse_findings(raw_text, chunk)
    except requests.Timeout:
        print(f"  [WARN] Timeout analysing {chunk.name} — skipping")
        return []
    except requests.RequestException as e:
        print(f"  [WARN] Request error: {e}")
        return []


def analyse_chunks(
    chunks: list[CodeChunk],
    model: str = DEFAULT_MODEL,
    verbose: bool = True,
) -> list[Finding]:
    """
    Analyse a list of chunks and return all findings, sorted by severity.
    """
    all_findings = []

    for i, chunk in enumerate(chunks, 1):
        if verbose:
            print(f"  Analysing [{i}/{len(chunks)}] {chunk.name} "
                  f"(lines {chunk.start_line}–{chunk.end_line})", end="", flush=True)

        findings = analyse_chunk(chunk, model)

        if verbose:
            if findings:
                severities = [f.severity for f in findings]
                print(f" → {len(findings)} finding(s): {', '.join(severities)}")
            else:
                print(" → clean")

        all_findings.extend(findings)

    # Sort by severity (critical first)
    all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity.lower(), 99))
    return all_findings


# ── Prompt engineering ─────────────────────────────────────────────────────

def _build_prompt(chunk: CodeChunk) -> str:
    """
    Build a structured security analysis prompt for a code chunk.
    The prompt is carefully designed to get consistent JSON output.
    """
    return f"""You are a senior application security engineer performing a code security review.
Analyse the following Python code for security vulnerabilities.

FILE: {chunk.file_path}
FUNCTION/SECTION: {chunk.name}
LINES: {chunk.start_line} to {chunk.end_line}

```python
{chunk.content}
```

Identify ALL security vulnerabilities present. For each vulnerability found, classify it using the CWE (Common Weakness Enumeration) taxonomy.

Focus on these vulnerability categories:
- CWE-89: SQL Injection
- CWE-78: OS Command Injection
- CWE-22: Path Traversal
- CWE-798: Hardcoded Credentials
- CWE-502: Insecure Deserialization
- CWE-327: Weak Cryptography
- CWE-306: Missing Authentication
- CWE-200: Sensitive Data Exposure
- CWE-20: Improper Input Validation
- CWE-352: Cross-Site Request Forgery
- CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes
- CWE-732: Incorrect Permission Assignment

Respond ONLY with a valid JSON array. Each element must have exactly these fields:
{{
  "cwe_id": "CWE-XX",
  "cwe_name": "vulnerability name",
  "severity": "critical|high|medium|low|info",
  "title": "short title",
  "description": "detailed explanation of the vulnerability and how it could be exploited",
  "line_number": <approximate line number within the file>,
  "code_snippet": "the specific vulnerable code",
  "recommendation": "how to fix this vulnerability",
  "confidence": "high|medium|low"
}}

If there are NO vulnerabilities, respond with exactly: []

Do not include any text before or after the JSON array.
"""


# ── Response parser ────────────────────────────────────────────────────────

def _parse_findings(raw_text: str, chunk: CodeChunk) -> list[Finding]:
    """
    Parse the model's JSON response into Finding objects.
    Handles common LLM output quirks — markdown fences, extra text, etc.
    """
    # Strip markdown code fences if present
    text = raw_text.strip()
    if "```json" in text:
        text = text.split("```json")[1].split("```")[0].strip()
    elif "```" in text:
        text = text.split("```")[1].split("```")[0].strip()

    # Find the JSON array in the response
    start = text.find("[")
    end   = text.rfind("]") + 1
    if start == -1 or end == 0:
        return []  # model returned no array

    json_str = text[start:end]

    try:
        raw_findings = json.loads(json_str)
    except json.JSONDecodeError:
        return []

    findings = []
    for raw in raw_findings:
        if not isinstance(raw, dict):
            continue
        try:
            finding = Finding(
                file_path       = chunk.file_path,
                chunk_name      = chunk.name,
                line_number     = int(raw.get("line_number", chunk.start_line)),
                cwe_id          = raw.get("cwe_id", "CWE-?").upper(),
                cwe_name        = raw.get("cwe_name", "Unknown"),
                severity        = raw.get("severity", "medium").lower(),
                title           = raw.get("title", "Security Issue"),
                description     = raw.get("description", ""),
                code_snippet    = raw.get("code_snippet", ""),
                recommendation  = raw.get("recommendation", ""),
                confidence      = raw.get("confidence", "medium").lower(),
            )
            findings.append(finding)
        except (ValueError, TypeError):
            continue

    return findings