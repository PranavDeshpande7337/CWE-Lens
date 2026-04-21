"""
scanner.py
CLI entry point for llm-vuln-scan.

Usage:
    python scanner.py sample_targets/vulnerable_app.py
    python scanner.py sample_targets/
    python scanner.py sample_targets/vulnerable_app.py --model codellama
    python scanner.py sample_targets/vulnerable_app.py --no-json
    python scanner.py --check          # verify Ollama is running
"""

import argparse
import os
import sys
import time

from core.chunker  import chunk_file, chunk_directory
from core.analyser import analyse_chunks, check_ollama_running, DEFAULT_MODEL
from core.reporter import print_terminal_report, write_json_report

BOLD  = "\033[1m"
GREEN = "\033[92m"
RED   = "\033[91m"
RESET = "\033[0m"


def main():
    parser = argparse.ArgumentParser(
        description="LLM-powered vulnerability scanner using Ollama",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py sample_targets/vulnerable_app.py
  python scanner.py sample_targets/
  python scanner.py myproject/ --model codellama:13b
  python scanner.py myfile.py --no-json
  python scanner.py --check
        """
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="File or directory to scan",
    )
    parser.add_argument(
        "--model", "-m",
        default=DEFAULT_MODEL,
        help=f"Ollama model to use (default: {DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--no-json",
        action="store_true",
        help="Skip writing JSON report to disk",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check whether Ollama is running and a model is available",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress per-chunk progress output",
    )

    args = parser.parse_args()

    print(f"\n{BOLD}llm-vuln-scan{RESET} — LLM-powered vulnerability scanner")
    print(f"Model: {args.model}  |  Backend: Ollama (local)\n")

    # ── Check mode ─────────────────────────────────────────────────────────
    if args.check:
        print("Checking Ollama...")
        ok, msg = check_ollama_running()
        if ok:
            print(f"{GREEN}Ollama is running. Model available: {msg}{RESET}")
        else:
            print(f"{RED}Ollama check failed: {msg}{RESET}")
        sys.exit(0 if ok else 1)

    if not args.target:
        parser.print_help()
        sys.exit(1)

    # ── Verify Ollama before scanning ──────────────────────────────────────
    print("Checking Ollama...", end=" ", flush=True)
    ok, msg = check_ollama_running()
    if not ok:
        print(f"\n{RED}Error: {msg}{RESET}")
        print("Start Ollama with:  ollama serve")
        print("Pull a model with:  ollama pull codellama")
        sys.exit(1)
    model = msg  # use the detected model name (may include tag e.g. codellama:13b)
    print(f"{GREEN}OK{RESET} ({model})\n")

    # ── Chunk the target ───────────────────────────────────────────────────
    target = os.path.abspath(args.target)

    if not os.path.exists(target):
        print(f"{RED}Error: path not found: {target}{RESET}")
        sys.exit(1)

    print("Chunking source code...", end=" ", flush=True)
    if os.path.isfile(target):
        chunks = chunk_file(target)
    else:
        chunks = chunk_directory(target)

    if not chunks:
        print(f"\n{RED}No Python files found in: {target}{RESET}")
        sys.exit(1)

    print(f"{len(chunks)} chunk(s) from "
          f"{len(set(c.file_path for c in chunks))} file(s)\n")

    # ── Analyse ────────────────────────────────────────────────────────────
    print(f"Scanning with {model}...")
    start_time = time.time()

    findings = analyse_chunks(chunks, model=model, verbose=not args.quiet)

    elapsed = time.time() - start_time

    # ── Report ─────────────────────────────────────────────────────────────
    print_terminal_report(findings, target, elapsed, model)

    if not args.no_json:
        report_path = write_json_report(findings, target, elapsed, model)
        print(f"JSON report saved to: {report_path}\n")


if __name__ == "__main__":
    main()