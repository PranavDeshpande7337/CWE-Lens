"""
core/reporter.py
Two output formats:
  1. Colour-coded terminal report — for immediate human reading
  2. Structured JSON report      — for sharing, archiving, or piping to other tools
"""

import json
import os
from datetime import datetime
from core.analyser import Finding, SEVERITY_ORDER


# ── Terminal colours ───────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
GRAY   = "\033[90m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

SEVERITY_COLOURS = {
    "critical": RED,
    "high":     RED,
    "medium":   YELLOW,
    "low":      BLUE,
    "info":     GRAY,
}

SEVERITY_BADGES = {
    "critical": f"{RED}[CRITICAL]{RESET}",
    "high":     f"{RED}[HIGH]    {RESET}",
    "medium":   f"{YELLOW}[MEDIUM]  {RESET}",
    "low":      f"{BLUE}[LOW]     {RESET}",
    "info":     f"{GRAY}[INFO]    {RESET}",
}

RISK_BARS = {
    "critical": f"{RED}{'█' * 20}  CRITICAL{RESET}",
    "high":     f"{RED}{'█' * 15}       HIGH{RESET}",
    "medium":   f"{YELLOW}{'█' * 10}         MEDIUM{RESET}",
    "low":      f"{BLUE}{'█' * 5}              LOW{RESET}",
    "clean":    f"{GREEN}{'█' * 3}                CLEAN{RESET}",
}


def print_terminal_report(
    findings: list[Finding],
    target: str,
    elapsed: float,
    model: str,
):
    """Print a colour-coded vulnerability report to the terminal."""

    counts = _count_by_severity(findings)
    overall_risk = _overall_risk(counts)

    print(f"\n{'━' * 62}")
    print(f"{BOLD}  LLM Vulnerability Scan Report{RESET}")
    print(f"{'━' * 62}")
    print(f"  Target  : {target}")
    print(f"  Model   : {model}")
    print(f"  Scanned : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Time    : {elapsed:.1f}s")
    print(f"  Risk    : {RISK_BARS.get(overall_risk, overall_risk)}")
    print()

    # Summary counts
    print(f"  {BOLD}Finding summary{RESET}")
    for sev in ["critical", "high", "medium", "low", "info"]:
        count  = counts.get(sev, 0)
        colour = SEVERITY_COLOURS.get(sev, RESET)
        bar    = "█" * count if count <= 20 else "█" * 20 + f"(+{count - 20})"
        print(f"    {sev.capitalize():<10} {colour}{bar}{RESET} {count}")

    if not findings:
        print(f"\n  {GREEN}No vulnerabilities detected.{RESET}")
        print(f"{'━' * 62}\n")
        return

    # Individual findings
    print(f"\n  {BOLD}Findings ({len(findings)} total){RESET}")
    print()

    for i, f in enumerate(findings, 1):
        badge  = SEVERITY_BADGES.get(f.severity, f"[{f.severity.upper()}]")
        colour = SEVERITY_COLOURS.get(f.severity, RESET)

        print(f"  {BOLD}#{i}{RESET} {badge} {colour}{f.cwe_id}{RESET} — {f.title}")
        print(f"     File  : {f.file_path}")
        print(f"     Line  : ~{f.line_number}  |  Function: {f.chunk_name}  |  Confidence: {f.confidence}")
        print(f"     {f.description[:200]}{'...' if len(f.description) > 200 else ''}")
        if f.code_snippet:
            snippet = f.code_snippet[:120].replace("\n", " ")
            print(f"     {GRAY}Code  : {snippet}{RESET}")
        print(f"     {CYAN}Fix   : {f.recommendation[:180]}{RESET}")
        print()

    print(f"{'━' * 62}\n")


def write_json_report(
    findings: list[Finding],
    target: str,
    elapsed: float,
    model: str,
    output_dir: str = "reports",
) -> str:
    """
    Write a structured JSON report to disk.
    Returns the path to the written file.
    """
    os.makedirs(output_dir, exist_ok=True)

    counts       = _count_by_severity(findings)
    overall_risk = _overall_risk(counts)
    timestamp    = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target  = os.path.basename(target).replace(".", "_").replace("/", "_")
    filename     = f"{output_dir}/scan_{safe_target}_{timestamp}.json"

    report = {
        "meta": {
            "target":       target,
            "model":        model,
            "scan_time":    datetime.now().isoformat(),
            "elapsed_secs": round(elapsed, 2),
            "overall_risk": overall_risk,
            "total_findings": len(findings),
        },
        "summary": counts,
        "findings": [
            {
                "id":             i + 1,
                "file":           f.file_path,
                "function":       f.chunk_name,
                "line_number":    f.line_number,
                "cwe_id":         f.cwe_id,
                "cwe_name":       f.cwe_name,
                "severity":       f.severity,
                "confidence":     f.confidence,
                "title":          f.title,
                "description":    f.description,
                "code_snippet":   f.code_snippet,
                "recommendation": f.recommendation,
            }
            for i, f in enumerate(findings)
        ],
    }

    with open(filename, "w", encoding="utf-8") as fp:
        json.dump(report, fp, indent=2)

    return filename


# ── Helpers ────────────────────────────────────────────────────────────────

def _count_by_severity(findings: list[Finding]) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.severity.lower()
        if sev in counts:
            counts[sev] += 1
        else:
            counts["info"] += 1
    return counts


def _overall_risk(counts: dict) -> str:
    if counts["critical"] > 0:
        return "critical"
    if counts["high"] > 0:
        return "high"
    if counts["medium"] > 0:
        return "medium"
    if counts["low"] > 0:
        return "low"
    return "clean"