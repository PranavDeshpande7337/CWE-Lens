"""
core/chunker.py
Splits source code files into chunks suitable for LLM analysis.

Why chunking matters:
  - LLMs have a context window limit — large files need to be split
  - Splitting by function/class boundaries gives the LLM coherent units
    to reason about rather than arbitrary line cuts
  - Each chunk retains its starting line number so findings can be
    mapped back to the original file accurately
"""

import ast
import os
from dataclasses import dataclass


@dataclass
class CodeChunk:
    """A single unit of code to be analysed."""
    file_path:  str       # absolute path to the source file
    chunk_id:   int       # sequential chunk number within the file
    content:    str       # the actual source code text
    start_line: int       # line number where this chunk starts in the file
    end_line:   int       # line number where this chunk ends
    chunk_type: str       # 'function' | 'class' | 'module' | 'block'
    name:       str       # function/class name, or filename for module chunks


# Maximum lines per chunk — if a single function exceeds this,
# it gets split at this boundary to stay within context limits
MAX_CHUNK_LINES = 80


def chunk_file(file_path: str) -> list[CodeChunk]:
    """
    Read a Python source file and split it into coherent chunks.
    Attempts AST-based splitting first (by function/class boundaries).
    Falls back to line-based splitting if the file isn't valid Python.

    Args:
        file_path: Path to the .py file to chunk

    Returns:
        List of CodeChunk objects ready for analysis
    """
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        source = f.read()

    lines = source.splitlines()

    # Try AST-based splitting — preferred because it respects code structure
    try:
        tree = ast.parse(source)
        chunks = _ast_chunks(file_path, source, lines, tree)
        if chunks:
            return chunks
    except SyntaxError:
        pass  # fall through to line-based splitting

    # Fallback: split by fixed line count
    return _line_chunks(file_path, lines)


def chunk_directory(directory: str, extensions: tuple = (".py",)) -> list[CodeChunk]:
    """
    Recursively find all source files in a directory and chunk them.

    Args:
        directory:  Root directory to scan
        extensions: File extensions to include (default: Python only)

    Returns:
        All chunks from all matching files, in file order
    """
    all_chunks = []
    for root, dirs, files in os.walk(directory):
        # Skip common non-source directories
        dirs[:] = [d for d in dirs if d not in {
            ".git", "__pycache__", "venv", ".venv",
            "node_modules", ".mypy_cache", "dist", "build"
        }]
        for filename in sorted(files):
            if filename.endswith(extensions):
                full_path = os.path.join(root, filename)
                try:
                    chunks = chunk_file(full_path)
                    all_chunks.extend(chunks)
                except Exception:
                    pass  # skip unreadable files silently
    return all_chunks


# ── Internal helpers ───────────────────────────────────────────────────────

def _ast_chunks(file_path: str, source: str, lines: list[str], tree: ast.AST) -> list[CodeChunk]:
    """
    Extract function and class definitions as individual chunks.
    Module-level code that isn't inside a function/class becomes its own chunk.
    """
    chunks    = []
    chunk_id  = 0
    covered   = set()  # line numbers already assigned to a chunk

    top_level = [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        and isinstance(getattr(node, "col_offset", 0), int)
        and node.col_offset == 0  # top-level only — skip nested functions
    ]

    for node in sorted(top_level, key=lambda n: n.lineno):
        start = node.lineno - 1      # convert to 0-indexed
        end   = node.end_lineno      # ast end_lineno is 1-indexed, exclusive when sliced

        chunk_lines = lines[start:end]

        # If the function/class is very long, split it further
        if len(chunk_lines) > MAX_CHUNK_LINES:
            sub_chunks = _split_long_chunk(
                file_path, chunk_lines, start + 1,
                chunk_id,
                chunk_type="function" if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) else "class",
                name=node.name,
            )
            chunks.extend(sub_chunks)
            chunk_id += len(sub_chunks)
        else:
            chunks.append(CodeChunk(
                file_path  = file_path,
                chunk_id   = chunk_id,
                content    = "\n".join(chunk_lines),
                start_line = start + 1,
                end_line   = end,
                chunk_type = "function" if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) else "class",
                name       = node.name,
            ))
            chunk_id += 1

        covered.update(range(start, end))

    # Collect module-level lines not covered by any function/class
    module_lines = [
        (i, line) for i, line in enumerate(lines)
        if i not in covered and line.strip() and not line.strip().startswith("#")
    ]

    if module_lines:
        content = "\n".join(line for _, line in module_lines)
        chunks.append(CodeChunk(
            file_path  = file_path,
            chunk_id   = chunk_id,
            content    = content,
            start_line = module_lines[0][0] + 1,
            end_line   = module_lines[-1][0] + 1,
            chunk_type = "module",
            name       = os.path.basename(file_path),
        ))

    return chunks


def _line_chunks(file_path: str, lines: list[str]) -> list[CodeChunk]:
    """Fallback: split by fixed line count when AST parsing fails."""
    chunks   = []
    chunk_id = 0
    for i in range(0, len(lines), MAX_CHUNK_LINES):
        block = lines[i : i + MAX_CHUNK_LINES]
        chunks.append(CodeChunk(
            file_path  = file_path,
            chunk_id   = chunk_id,
            content    = "\n".join(block),
            start_line = i + 1,
            end_line   = i + len(block),
            chunk_type = "block",
            name       = os.path.basename(file_path),
        ))
        chunk_id += 1
    return chunks


def _split_long_chunk(
    file_path: str,
    lines: list[str],
    base_line: int,
    base_id: int,
    chunk_type: str,
    name: str,
) -> list[CodeChunk]:
    """Split an oversized function/class into MAX_CHUNK_LINES blocks."""
    sub_chunks = []
    for i in range(0, len(lines), MAX_CHUNK_LINES):
        block = lines[i : i + MAX_CHUNK_LINES]
        sub_chunks.append(CodeChunk(
            file_path  = file_path,
            chunk_id   = base_id + len(sub_chunks),
            content    = "\n".join(block),
            start_line = base_line + i,
            end_line   = base_line + i + len(block) - 1,
            chunk_type = chunk_type,
            name       = f"{name} (part {len(sub_chunks) + 1})",
        ))
    return sub_chunks