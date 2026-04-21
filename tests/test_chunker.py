"""
tests/test_chunker.py
Tests for the code chunker — runs without Ollama or any API.
Run with: python tests/test_chunker.py
"""

import sys
import os
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from core.chunker import chunk_file, CodeChunk

GREEN = "\033[92m"
RED   = "\033[91m"
BOLD  = "\033[1m"
RESET = "\033[0m"


def run(label: str, condition: bool, detail: str = "") -> bool:
    icon = f"{GREEN}PASS{RESET}" if condition else f"{RED}FAIL{RESET}"
    print(f"  [{icon}] {label}")
    if not condition and detail:
        print(f"         {detail}")
    return condition


def write_temp(content: str) -> str:
    f = tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False)
    f.write(content)
    f.close()
    return f.name


TESTS_PASSED = 0
TESTS_TOTAL  = 0


def test(label, condition, detail=""):
    global TESTS_PASSED, TESTS_TOTAL
    TESTS_TOTAL += 1
    ok = run(label, condition, detail)
    TESTS_PASSED += int(ok)


def main():
    print(f"\n{BOLD}Chunker Test Suite{RESET}")
    print("─" * 50)

    # ── Test 1: Single function ────────────────────────────────────────────
    src = '''
def greet(name):
    return f"Hello {name}"
'''
    path   = write_temp(src)
    chunks = chunk_file(path)
    test("Single function produces one chunk", len(chunks) == 1)
    test("Chunk type is function", chunks[0].chunk_type == "function")
    test("Chunk name is 'greet'", chunks[0].name == "greet")
    os.unlink(path)

    # ── Test 2: Multiple functions ─────────────────────────────────────────
    src = '''
def foo():
    return 1

def bar():
    return 2

def baz():
    return 3
'''
    path   = write_temp(src)
    chunks = chunk_file(path)
    names  = [c.name for c in chunks]
    test("Three functions produce three chunks", len(chunks) == 3,
         f"Got {len(chunks)} chunks: {names}")
    test("All chunk types are function", all(c.chunk_type == "function" for c in chunks))
    os.unlink(path)

    # ── Test 3: Class definition ───────────────────────────────────────────
    src = '''
class MyService:
    def __init__(self):
        self.x = 1

    def run(self):
        return self.x
'''
    path   = write_temp(src)
    chunks = chunk_file(path)
    class_chunks = [c for c in chunks if c.chunk_type == "class"]
    test("Class produces at least one class chunk", len(class_chunks) >= 1)
    test("Class chunk name is 'MyService'", class_chunks[0].name == "MyService")
    os.unlink(path)

    # ── Test 4: Line numbers ───────────────────────────────────────────────
    src = '''def alpha():
    pass

def beta():
    pass
'''
    path   = write_temp(src)
    chunks = chunk_file(path)
    test("First chunk starts at line 1", chunks[0].start_line == 1,
         f"Got start_line={chunks[0].start_line}")
    test("Second chunk starts after first", chunks[1].start_line > chunks[0].end_line,
         f"chunk[0].end={chunks[0].end_line}, chunk[1].start={chunks[1].start_line}")
    os.unlink(path)

    # ── Test 5: Syntax error falls back gracefully ─────────────────────────
    src  = "def broken(\n    this is not valid python!!!\n"
    path = write_temp(src)
    chunks = chunk_file(path)
    test("Syntax error falls back to line-based chunks", len(chunks) >= 1)
    test("Fallback chunk type is block", chunks[0].chunk_type == "block")
    os.unlink(path)

    # ── Test 6: Empty file ─────────────────────────────────────────────────
    src  = ""
    path = write_temp(src)
    chunks = chunk_file(path)
    test("Empty file produces no chunks", len(chunks) == 0)
    os.unlink(path)

    # ── Test 7: Content preserved ──────────────────────────────────────────
    src = '''def important():
    secret = "do_not_lose_this"
    return secret
'''
    path   = write_temp(src)
    chunks = chunk_file(path)
    test("Chunk content contains the source code",
         "secret" in chunks[0].content and "do_not_lose_this" in chunks[0].content)
    os.unlink(path)

    # ── Summary ────────────────────────────────────────────────────────────
    failed = TESTS_TOTAL - TESTS_PASSED
    colour = GREEN if failed == 0 else RED
    print(f"\n{'─'*50}")
    print(f"  {colour}{BOLD}{TESTS_PASSED}/{TESTS_TOTAL} passed{RESET}  ({failed} failed)\n")


if __name__ == "__main__":
    main()