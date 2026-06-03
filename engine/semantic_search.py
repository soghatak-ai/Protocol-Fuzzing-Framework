"""
Phase 1 of the Agentic Analysis Pipeline — Semantic Graph & Vectorizer.

Responsibilities:
  1. Parse source files into discrete AST nodes (functions, structs, classes)
     using tree-sitter, with auto-detected language grammars.
  2. Embed each code chunk via Azure OpenAI's embedding model.
  3. Store/retrieve chunks in a local ChromaDB collection so the Orchestrator
     and Explorers can do precision semantic queries instead of dumping the
     entire codebase into a single LLM context window.
"""

import os
import hashlib
import time
from typing import Optional

import tiktoken
import chromadb
from openai import AzureOpenAI

# ---------------------------------------------------------------------------
# tree-sitter language registry
# ---------------------------------------------------------------------------
# Maps file-extension → (module, language-name).  We import lazily so a
# missing grammar is a soft error, not a crash.
_TS_LANG_MAP = {
    ".c":    ("tree_sitter_c",          "c"),
    ".h":    ("tree_sitter_c",          "c"),
    ".cc":   ("tree_sitter_cpp",        "cpp"),
    ".cpp":  ("tree_sitter_cpp",        "cpp"),
    ".cxx":  ("tree_sitter_cpp",        "cpp"),
    ".hh":   ("tree_sitter_cpp",        "cpp"),
    ".hpp":  ("tree_sitter_cpp",        "cpp"),
    ".py":   ("tree_sitter_python",     "python"),
    ".java": ("tree_sitter_java",       "java"),
    ".js":   ("tree_sitter_javascript", "javascript"),
    ".jsx":  ("tree_sitter_javascript", "javascript"),
    ".ts":   ("tree_sitter_typescript", "typescript"),
    ".tsx":  ("tree_sitter_typescript", "tsx"),
    ".go":   ("tree_sitter_go",         "go"),
    ".rs":   ("tree_sitter_rust",       "rust"),
}

# Node types we extract as discrete "chunks" per language family.
_EXTRACT_TYPES = {
    "c":          {"function_definition", "struct_specifier", "enum_specifier",
                   "preproc_function_def"},
    "cpp":        {"function_definition", "class_specifier", "struct_specifier",
                   "enum_specifier", "template_declaration", "namespace_definition",
                   "preproc_function_def"},
    "python":     {"function_definition", "class_definition"},
    "java":       {"method_declaration", "class_declaration", "constructor_declaration",
                   "enum_declaration", "interface_declaration"},
    "javascript": {"function_declaration", "class_declaration", "method_definition",
                   "arrow_function", "function"},
    "typescript": {"function_declaration", "class_declaration", "method_definition",
                   "arrow_function", "function", "interface_declaration",
                   "type_alias_declaration"},
    "tsx":        {"function_declaration", "class_declaration", "method_definition",
                   "arrow_function", "function", "interface_declaration",
                   "type_alias_declaration"},
    "go":         {"function_declaration", "method_declaration", "type_declaration"},
    "rust":       {"function_item", "impl_item", "struct_item", "enum_item",
                   "trait_item"},
}

# Lazy cache of tree-sitter Language objects.
_lang_cache: dict = {}


def _get_language(ext: str):
    """Return a tree_sitter.Language for the given file extension, or None."""
    if ext in _lang_cache:
        return _lang_cache[ext]
    spec = _TS_LANG_MAP.get(ext)
    if not spec:
        return None
    mod_name, lang_name = spec
    try:
        import importlib
        import tree_sitter
        mod = importlib.import_module(mod_name)
        capsule = mod.language()
        lang = tree_sitter.Language(capsule) if not isinstance(capsule, tree_sitter.Language) else capsule
        _lang_cache[ext] = lang
        return lang
    except Exception as e:
        print(f"[SemanticSearch] WARNING: cannot load grammar for {ext}: {e}")
        _lang_cache[ext] = None
        return None


def _lang_family(ext: str) -> str:
    """Return the language family string (e.g. 'cpp') for an extension."""
    spec = _TS_LANG_MAP.get(ext)
    return spec[1] if spec else "unknown"


# ---------------------------------------------------------------------------
# AST Parsing — extract discrete code chunks from source
# ---------------------------------------------------------------------------
def parse_file_to_chunks(filename: str, source: str, max_chunk_tokens: int = 6000):
    """Parse *source* (string) using tree-sitter for *filename*'s language.

    Returns a list of dicts, each representing a discrete code chunk:
        {
            "id":        deterministic hash,
            "file":      filename,
            "language":  language family,
            "node_type": tree-sitter node type (e.g. "function_definition"),
            "name":      extracted symbol name or "(anonymous)",
            "start_line": 1-indexed,
            "end_line":  1-indexed,
            "code":      the raw source text of the chunk,
            "tokens_est": rough token estimate,
        }

    If the file's language is not supported, falls back to a simple
    line-window chunker so we never silently drop content.
    """
    ext = os.path.splitext(filename)[1].lower()
    lang = _get_language(ext)
    family = _lang_family(ext)

    if lang is None:
        # Fallback: chunk by fixed line windows with overlap.
        return _fallback_chunk(filename, source, max_chunk_tokens)

    import tree_sitter
    parser = tree_sitter.Parser(lang)
    tree = parser.parse(source.encode("utf-8", errors="replace"))

    extract_types = _EXTRACT_TYPES.get(family, set())
    chunks = []
    source_lines = source.split("\n")

    def _visit(node):
        if node.type in extract_types:
            start = node.start_point[0]
            end = node.end_point[0]
            code = "\n".join(source_lines[start:end + 1])
            name = _extract_name(node)
            tokens_est = _estimate_tokens(code)

            if tokens_est > max_chunk_tokens:
                # If a single node is too big (e.g. huge class), recurse into
                # children to get finer granularity.
                for child in node.children:
                    _visit(child)
                return

            chunk_id = hashlib.sha256(
                f"{filename}:{name}:{start}:{end}".encode()
            ).hexdigest()[:16]
            chunks.append({
                "id": chunk_id,
                "file": filename,
                "language": family,
                "node_type": node.type,
                "name": name,
                "start_line": start + 1,
                "end_line": end + 1,
                "code": code,
                "tokens_est": tokens_est,
            })
            return  # don't recurse further into this node

        for child in node.children:
            _visit(child)

    _visit(tree.root_node)

    # If AST extraction found nothing (e.g. header with only macros), fallback
    if not chunks:
        return _fallback_chunk(filename, source, max_chunk_tokens)

    return chunks


def _extract_name(node) -> str:
    """Best-effort extraction of the symbol name from a tree-sitter node."""
    # Most languages: look for a child named 'name' or 'declarator'
    for child in node.children:
        if child.type in ("identifier", "field_identifier", "type_identifier"):
            return child.text.decode("utf-8", errors="replace")
        if child.type == "function_declarator":
            return _extract_name(child)
        if child.type == "declarator":
            return _extract_name(child)
    return "(anonymous)"


def _fallback_chunk(filename: str, source: str, max_chunk_tokens: int):
    """Simple line-window chunker for unsupported languages."""
    lines = source.split("\n")
    # Aim for windows of ~max_chunk_tokens; rough 4 chars/token heuristic
    window = max(50, int(max_chunk_tokens * 4 / max(1, len(max(lines, key=len, default="")))))
    window = min(window, 300)  # cap
    overlap = min(20, window // 5)
    chunks = []
    i = 0
    while i < len(lines):
        end = min(i + window, len(lines))
        code = "\n".join(lines[i:end])
        chunk_id = hashlib.sha256(f"{filename}:L{i+1}-{end}".encode()).hexdigest()[:16]
        chunks.append({
            "id": chunk_id,
            "file": filename,
            "language": _lang_family(os.path.splitext(filename)[1].lower()),
            "node_type": "block",
            "name": f"lines_{i+1}_{end}",
            "start_line": i + 1,
            "end_line": end,
            "code": code,
            "tokens_est": _estimate_tokens(code),
        })
        i = end - overlap if end < len(lines) else len(lines)
    return chunks


_enc = None

def _estimate_tokens(text: str) -> int:
    global _enc
    if _enc is None:
        try:
            _enc = tiktoken.get_encoding("cl100k_base")
        except Exception:
            return len(text) // 4
    return len(_enc.encode(text))


# ---------------------------------------------------------------------------
# Embedding via Azure OpenAI
# ---------------------------------------------------------------------------
_embed_client: Optional[AzureOpenAI] = None


def _get_embed_client() -> AzureOpenAI:
    global _embed_client
    if _embed_client is None:
        endpoint = os.environ.get("AZURE_EMBEDDING_ENDPOINT", "")
        api_key = os.environ.get("AZURE_EMBEDDING_API_KEY", "")
        api_version = os.environ.get("AZURE_EMBEDDING_API_VERSION", "2024-02-01")
        if not endpoint or not api_key:
            raise RuntimeError(
                "AZURE_EMBEDDING_ENDPOINT and AZURE_EMBEDDING_API_KEY must be "
                "set in .env to use semantic search."
            )
        _embed_client = AzureOpenAI(
            azure_endpoint=endpoint,
            api_key=api_key,
            api_version=api_version,
        )
    return _embed_client


def embed_texts(texts: list[str], batch_size: int = 16) -> list[list[float]]:
    """Embed a list of texts using the Azure OpenAI embedding model.
    Returns a list of float vectors, one per input text.
    Handles batching and basic retry on rate-limit (429)."""
    model = os.environ.get("AZURE_EMBEDDING_DEPLOYMENT", "text-embedding-3-large")
    client = _get_embed_client()
    all_embeddings = []
    total_batches = (len(texts) + batch_size - 1) // batch_size

    for batch_idx, i in enumerate(range(0, len(texts), batch_size)):
        batch = texts[i:i + batch_size]
        if total_batches > 10 and (batch_idx % 10 == 0 or batch_idx == total_batches - 1):
            print(f"[SemanticSearch] Embedding batch {batch_idx+1}/{total_batches} "
                  f"({len(all_embeddings)}/{len(texts)} done)")
        retries = 0
        while retries < 8:
            try:
                response = client.embeddings.create(model=model, input=batch)
                all_embeddings.extend([d.embedding for d in response.data])
                break
            except Exception as e:
                err_str = str(e)
                if "429" in err_str or "rate" in err_str.lower():
                    wait = min(2 ** retries, 60)
                    print(f"[SemanticSearch] Rate limited, waiting {wait}s (attempt {retries+1}/8)...")
                    time.sleep(wait)
                    retries += 1
                else:
                    raise

    return all_embeddings


# ---------------------------------------------------------------------------
# ChromaDB — local vector store
# ---------------------------------------------------------------------------
_chroma_client: Optional[chromadb.ClientAPI] = None
COLLECTION_NAME = "fuzzer_code_graph"


def _get_chroma() -> chromadb.ClientAPI:
    global _chroma_client
    if _chroma_client is None:
        persist_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                   ".chromadb")
        _chroma_client = chromadb.PersistentClient(path=persist_dir)
    return _chroma_client


def get_or_create_collection(name: str = COLLECTION_NAME):
    """Return a ChromaDB collection, creating it if needed."""
    return _get_chroma().get_or_create_collection(
        name=name,
        metadata={"hnsw:space": "cosine"},
    )


def reset_collection(name: str = COLLECTION_NAME):
    """Delete and recreate the collection (fresh index)."""
    client = _get_chroma()
    try:
        client.delete_collection(name)
    except Exception:
        pass
    return client.create_collection(
        name=name,
        metadata={"hnsw:space": "cosine"},
    )


# ---------------------------------------------------------------------------
# High-level API: index a codebase, query it
# ---------------------------------------------------------------------------
def index_codebase(files: dict[str, str],
                   collection_name: str = COLLECTION_NAME,
                   fresh: bool = True,
                   max_chunk_tokens: int = 6000) -> dict:
    """Parse, embed, and index all uploaded files.

    Args:
        files: {filename: source_code_string, ...}
        collection_name: ChromaDB collection name
        fresh: if True, wipe the collection before indexing
        max_chunk_tokens: max tokens per AST chunk

    Returns:
        {"total_files": N, "total_chunks": M, "chunks": [...]}
    """
    print(f"[SemanticSearch] Indexing {len(files)} files...")

    # 1. Parse all files into chunks
    all_chunks = []
    verbose = len(files) <= 50  # suppress per-file noise for large codebases
    parsed_count = 0
    for fname, source in files.items():
        chunks = parse_file_to_chunks(fname, source, max_chunk_tokens)
        all_chunks.extend(chunks)
        parsed_count += 1
        if verbose:
            print(f"[SemanticSearch]   {fname}: {len(chunks)} chunks, "
                  f"~{sum(c['tokens_est'] for c in chunks)} tokens")
        elif parsed_count % 200 == 0 or parsed_count == len(files):
            print(f"[SemanticSearch] Parsed {parsed_count}/{len(files)} files "
                  f"({len(all_chunks)} chunks so far)")

    if not all_chunks:
        print("[SemanticSearch] WARNING: 0 chunks extracted from all files.")
        return {"total_files": len(files), "total_chunks": 0, "chunks": []}

    # 2. Embed all chunks (with progress for large codebases)
    print(f"[SemanticSearch] Embedding {len(all_chunks)} chunks...")
    code_texts = [c["code"] for c in all_chunks]
    batch_sz = 64 if len(code_texts) > 500 else 16
    embeddings = embed_texts(code_texts, batch_size=batch_sz)
    print(f"[SemanticSearch] Embedding complete ({len(embeddings)} vectors).")

    # 3. Store in ChromaDB
    collection = reset_collection(collection_name) if fresh else get_or_create_collection(collection_name)

    ids = [c["id"] for c in all_chunks]
    documents = [c["code"] for c in all_chunks]
    metadatas = [{
        "file": c["file"],
        "language": c["language"],
        "node_type": c["node_type"],
        "name": c["name"],
        "start_line": c["start_line"],
        "end_line": c["end_line"],
        "tokens_est": c["tokens_est"],
    } for c in all_chunks]

    # ChromaDB add() has a batch limit; chunk if needed
    BATCH = 500
    for i in range(0, len(ids), BATCH):
        collection.add(
            ids=ids[i:i + BATCH],
            embeddings=embeddings[i:i + BATCH],
            documents=documents[i:i + BATCH],
            metadatas=metadatas[i:i + BATCH],
        )

    print(f"[SemanticSearch] Indexed {len(all_chunks)} chunks into '{collection_name}'.")
    return {"total_files": len(files), "total_chunks": len(all_chunks), "chunks": all_chunks}


def query_codebase(query: str,
                   n_results: int = 20,
                   collection_name: str = COLLECTION_NAME,
                   where: Optional[dict] = None) -> list[dict]:
    """Semantic search over the indexed codebase.

    Args:
        query: natural-language or code query string
        n_results: max results to return
        collection_name: ChromaDB collection name
        where: optional ChromaDB where-filter (e.g. {"language": "cpp"})

    Returns:
        List of dicts: [{id, file, name, node_type, language,
                         start_line, end_line, code, distance}, ...]
    """
    collection = get_or_create_collection(collection_name)
    if collection.count() == 0:
        return []

    # Embed the query
    query_vec = embed_texts([query])[0]

    kwargs = {
        "query_embeddings": [query_vec],
        "n_results": min(n_results, collection.count()),
    }
    if where:
        kwargs["where"] = where

    results = collection.query(**kwargs)

    hits = []
    for i in range(len(results["ids"][0])):
        meta = results["metadatas"][0][i]
        hits.append({
            "id": results["ids"][0][i],
            "file": meta.get("file", ""),
            "name": meta.get("name", ""),
            "node_type": meta.get("node_type", ""),
            "language": meta.get("language", ""),
            "start_line": meta.get("start_line", 0),
            "end_line": meta.get("end_line", 0),
            "code": results["documents"][0][i],
            "distance": results["distances"][0][i] if results.get("distances") else None,
        })
    return hits


def get_all_chunks(collection_name: str = COLLECTION_NAME) -> list[dict]:
    """Return every chunk stored in the collection (for the Orchestrator's
    full view). Limited to 10000 to prevent memory issues."""
    collection = get_or_create_collection(collection_name)
    count = collection.count()
    if count == 0:
        return []
    results = collection.get(limit=min(count, 10000), include=["metadatas", "documents"])
    chunks = []
    for i in range(len(results["ids"])):
        meta = results["metadatas"][i]
        chunks.append({
            "id": results["ids"][i],
            "file": meta.get("file", ""),
            "name": meta.get("name", ""),
            "node_type": meta.get("node_type", ""),
            "language": meta.get("language", ""),
            "start_line": meta.get("start_line", 0),
            "end_line": meta.get("end_line", 0),
            "code": results["documents"][i],
        })
    return chunks
