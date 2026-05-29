import os
import re

# Extensions to INCLUDE (Add or remove as needed)
VALID_EXTENSIONS = {
    # C / C++
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx",
    # Python
    ".py", ".pyx",
    # Java / JVM
    ".java", ".kt", ".scala", ".groovy",
    # Web / JS / TS
    ".js", ".jsx", ".ts", ".tsx",
    # Systems / Modern
    ".go", ".rs", ".swift", ".zig",
    # Scripting / Shell
    ".sh", ".bash", ".rb", ".pl", ".php",
    # Config / Markup (useful for context)
    ".yaml", ".yml", ".toml", ".xml", ".lua",
}

# Directories to EXCLUDE completely
IGNORE_DIRS = {
    ".git", ".svn", ".hg",
    "node_modules", "venv", ".venv", "env", "__pycache__",
    "build", "dist", "out", "target", "bin", "obj",
    "vendor", "third_party", "external", "deps",
    ".idea", ".vscode",
}

# Skip individual files larger than this (avoids auto-generated blobs)
MAX_FILE_BYTES = 512 * 1024  # 512 KB

# Dangerous C/C++ patterns that indicate security-relevant code
HOTSPOT_PATTERNS = [
    # Memory operations
    r'\bmemcpy\b', r'\bmemmove\b', r'\bmemset\b', r'\bmalloc\b',
    r'\bcalloc\b', r'\brealloc\b', r'\bfree\b',
    # Unsafe string ops
    r'\bstrcpy\b', r'\bstrncpy\b', r'\bstrcat\b', r'\bstrncat\b',
    r'\bsprintf\b', r'\bvsprintf\b', r'\bsnprintf\b',
    # Format strings
    r'\bprintf\b', r'\bfprintf\b', r'\bsyslog\b',
    # Network I/O
    r'\brecv\b', r'\brecvfrom\b', r'\bread\b', r'\bfread\b',
    r'\bsend\b', r'\bsendto\b', r'\bwrite\b',
    # Buffer / pointer arithmetic
    r'\bbuffer\b', r'\bbuf\[', r'\blen\b', r'\bsize\b',
    # Dangerous casts and pointer ops
    r'\(char\s*\*\)', r'\(void\s*\*\)', r'\(uint8_t\s*\*\)',
    # Command execution
    r'\bsystem\b', r'\bexec\b', r'\bpopen\b',
]
HOTSPOT_RE = re.compile('|'.join(HOTSPOT_PATTERNS), re.IGNORECASE)

# Regex for C/C++ block comments, line comments, and blank lines
_C_BLOCK_COMMENT = re.compile(r'/\*.*?\*/', re.DOTALL)
_C_LINE_COMMENT = re.compile(r'//.*$', re.MULTILINE)
_BLANK_LINES = re.compile(r'\n\s*\n+', re.MULTILINE)
_LICENSE_BLOCK = re.compile(
    r'/\*.*?(license|copyright|permission|warranty|redistribute).*?\*/',
    re.DOTALL | re.IGNORECASE
)

# Regex for C/C++ function signatures (simplified but effective)
_FUNC_SIG = re.compile(
    r'^[ \t]*'
    r'(?:static\s+|inline\s+|extern\s+|virtual\s+|const\s+|unsigned\s+|signed\s+)*'
    r'[\w:*&<>]+\s+'
    r'\*{0,2}\s*'
    r'(\w+)\s*'
    r'\([^)]*\)',
    re.MULTILINE
)
# Regex for struct/class/enum/typedef declarations
_STRUCT_SIG = re.compile(
    r'^[ \t]*(?:typedef\s+)?(?:struct|class|enum|union)\s+(\w+)',
    re.MULTILINE
)


def _walk_source_files(repo_path: str):
    """Yield (relative_path, content) for every valid source file."""
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        for fname in sorted(files):
            ext = os.path.splitext(fname)[1].lower()
            if ext not in VALID_EXTENSIONS:
                continue
            file_path = os.path.join(root, fname)
            if os.path.getsize(file_path) > MAX_FILE_BYTES:
                continue
            relative_path = os.path.relpath(file_path, repo_path)
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                yield relative_path, content
            except (UnicodeDecodeError, PermissionError):
                continue


def collect_to_dict(repo_path: str) -> dict:
    """Collect source files into a dict: {relative_path: content}.
    Used by app.py to populate analysis_state['files'] directly."""
    result = {}
    for rel_path, content in _walk_source_files(repo_path):
        result[rel_path] = content
    return result


def collect_to_single_text(repo_path: str) -> str:
    """Collect all source files into a single formatted string.
    Each file is delimited with clear headers for the LLM."""
    parts = []
    for rel_path, content in _walk_source_files(repo_path):
        parts.append(
            f"=== FILE: {rel_path} ===\n"
            f"{content}\n"
            f"=== END: {rel_path} ==="
        )
    return "\n\n".join(parts)


def collect_source_code(repo_path: str, output_file: str = "ai_context.txt"):
    """Collect source files and write them to a single text file on disk."""
    total_files = 0
    total_bytes = 0

    with open(output_file, "w", encoding="utf-8") as outfile:
        for rel_path, content in _walk_source_files(repo_path):
            outfile.write(f"// ==========================================\n")
            outfile.write(f"// FILE: {rel_path}\n")
            outfile.write(f"// ==========================================\n\n")
            outfile.write(content)
            outfile.write("\n\n")
            total_files += 1
            total_bytes += len(content)

    print(f"[+] Collection Complete!")
    print(f"[+] Processed {total_files} source files.")
    print(f"[+] Output generated at {output_file} ({(total_bytes / 1024 / 1024):.2f} MB)")
    return output_file


def estimate_tokens(text) -> int:
    """Rough token estimate: ~1 token per 4 chars for code."""
    if isinstance(text, int):
        return text // 4
    return len(text) // 4


def minify_code(source: str) -> str:
    """Strip comments, license blocks, and collapse blank lines from C/C++ source."""
    text = _LICENSE_BLOCK.sub('', source)
    text = _C_BLOCK_COMMENT.sub('', text)
    text = _C_LINE_COMMENT.sub('', text)
    text = _BLANK_LINES.sub('\n', text)
    return text.strip()


def hotspot_filter(files_dict: dict) -> dict:
    """Filter a files dict to only files containing dangerous C/C++ patterns.
    Returns {path: content} for files with at least one hotspot match."""
    result = {}
    for path, content in files_dict.items():
        if HOTSPOT_RE.search(content):
            result[path] = content
    return result


def extract_signatures(content: str) -> list:
    """Extract function signatures and struct/class declarations from source code."""
    sigs = []
    for m in _FUNC_SIG.finditer(content):
        line = m.group(0).strip()
        if line and not line.startswith('#'):
            sigs.append(line.split('{')[0].rstrip() + ';')
    for m in _STRUCT_SIG.finditer(content):
        sigs.append(m.group(0).strip() + ' { ... };')
    return sigs


def extract_repo_map(files_dict: dict) -> str:
    """Build a repo map: file paths with their function/struct signatures.
    This is a compact representation for the LLM triage pass."""
    parts = []
    for path in sorted(files_dict.keys()):
        sigs = extract_signatures(files_dict[path])
        if sigs:
            sig_text = '\n  '.join(sigs)
            parts.append(f"── {path} ──\n  {sig_text}")
        else:
            parts.append(f"── {path} ── (no extractable signatures)")
    return '\n\n'.join(parts)


def build_optimized_context(files_dict: dict, selected_files: list) -> str:
    """Build the final code context from selected files, minified."""
    blocks = []
    for path in selected_files:
        if path in files_dict:
            minified = minify_code(files_dict[path])
            blocks.append(f"=== FILE: {path} ===\n{minified}\n=== END: {path} ===")
    return '\n\n'.join(blocks)


if __name__ == "__main__":
    target_repo = "./snort3"
    if os.path.exists(target_repo):
        collect_source_code(target_repo, "snort3_ai_context.txt")
    else:
        print(f"Directory {target_repo} does not exist. Please clone the repo first.")
