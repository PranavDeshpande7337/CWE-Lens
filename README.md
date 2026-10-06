# CWE-Lens

An LLM-powered static vulnerability scanner that runs entirely locally using Ollama. No API keys, no cloud, no cost.

Analyses Python codebases for security vulnerabilities classified by CWE ID — the industry standard taxonomy used by NIST, MITRE, and every major security team.

---

## What it detects

| CWE | Vulnerability |
|-----|--------------|
| CWE-89 | SQL Injection |
| CWE-78 | OS Command Injection |
| CWE-22 | Path Traversal |
| CWE-798 | Hardcoded Credentials |
| CWE-502 | Insecure Deserialization |
| CWE-327 | Weak Cryptography |
| CWE-200 | Sensitive Data Exposure |
| CWE-915 | Mass Assignment |
| CWE-20 | Improper Input Validation |

---

## Quickstart

```bash
# 1. Install Ollama from ollama.com, then pull a model
ollama pull codellama

# 2. Set up the project
python -m venv venv
source venv/bin/activate    # Windows: venv\Scripts\activate
pip install -r requirements.txt

# 3. Verify Ollama is running
python scanner.py --check

# 4. Run against sample targets
python scanner.py sample_targets/vulnerable_app.py
python scanner.py sample_targets/clean_app.py

# 5. Scan a directory
python scanner.py myproject/

# 6. Run tests (no Ollama needed)
python tests/test_chunker.py
```

---

## Usage

```
python scanner.py <target> [options]

Arguments:
  target              File or directory to scan

Options:
  --model, -m         Ollama model (default: codellama)
  --no-json           Skip writing JSON report
  --quiet, -q         Suppress per-chunk progress
  --check             Verify Ollama is running
```

---

## Output

**Terminal** — colour-coded report with severity bars, per-finding details, and fix recommendations.

**JSON** — structured report written to `reports/` with full metadata, CWE classifications, line numbers, and recommendations. Suitable for integration with CI pipelines or security dashboards.

---

## Project structure

```
llm-vuln-scan/
├── core/
│   ├── chunker.py        # AST-based code splitter
│   ├── analyser.py       # Ollama client + finding parser
│   └── reporter.py       # terminal + JSON output
├── sample_targets/
│   ├── vulnerable_app.py # intentionally vulnerable (for demo)
│   └── clean_app.py      # secure implementation (verifies no false positives)
├── tests/
│   └── test_chunker.py   # chunker unit tests (no Ollama needed)
├── reports/              # generated JSON reports (gitignored)
├── scanner.py            # CLI entry point
└── requirements.txt
```

---

## Why local LLM over regex scanners

Tools like Bandit use pattern matching — they find `subprocess.call(shell=True)` syntactically. An LLM understands context: it can identify that a string concatenated into a SQL query is dangerous even across variable assignments, or that a path join is vulnerable because the input comes from an untrusted source three functions up. It reasons about code the way a human reviewer does.
