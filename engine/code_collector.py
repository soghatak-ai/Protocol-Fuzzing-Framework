import os

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


if __name__ == "__main__":
    target_repo = "./snort3"
    if os.path.exists(target_repo):
        collect_source_code(target_repo, "snort3_ai_context.txt")
    else:
        print(f"Directory {target_repo} does not exist. Please clone the repo first.")
