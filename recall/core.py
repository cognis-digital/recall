"""RECALL — local privacy-first RAG index over a folder."""
from __future__ import annotations
import re, time, hashlib, json, math
from pathlib import Path
from collections import Counter
from cognis_core import Finding, ScanResult, score

TOOL_NAME = "RECALL"
TOOL_VERSION = "0.1.0"

def _tokenize(text): return re.findall(r"[a-z0-9]{2,}", text.lower())

def scan(target: str, query: str = "", **opts) -> ScanResult:
    """Builds a tiny in-memory TF-IDF index over `target` and returns top hits for `query`.
    If query is empty, audits the folder for ingest-readiness."""
    t0 = time.time()
    result = ScanResult(tool_name=TOOL_NAME, tool_version=TOOL_VERSION, target=str(target))
    p = Path(target)
    files = [f for f in p.rglob("*") if f.is_file() and f.suffix.lower() in (".md",".txt",".rst",".csv",".log")]
    result.items_scanned = len(files)
    if not files:
        result.add(Finding(id="RC-EMPTY-001", severity="medium", weight=2.0,
                           title="NO_INGESTABLE_FILES",
                           description="No supported text files found in target folder.",
                           location=str(p), remediation="Add .md/.txt/.rst/.csv/.log files; PDF/docx need a converter.",
                           category="rag-readiness"))
    docs = {}
    for f in files:
        try:
            docs[str(f)] = _tokenize(f.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
    if query and docs:
        q = _tokenize(query)
        df = Counter()
        for toks in docs.values():
            for w in set(toks): df[w]+=1
        n = len(docs) or 1
        scores = {}
        for path, toks in docs.items():
            tf = Counter(toks); s=0.0
            for w in q:
                s += tf[w] * math.log(1 + n/(1+df.get(w,0)))
            scores[path]=s
        top = sorted(scores.items(), key=lambda kv:-kv[1])[:5]
        for path, sc in top:
            if sc > 0:
                result.add(Finding(
                    id="RC-HIT-"+hashlib.sha1(path.encode()).hexdigest()[:6],
                    severity="info", weight=0.5,
                    title="RAG_HIT",
                    description=f"Match for query {query!r} (tf-idf={sc:.2f})",
                    location=path, category="rag-hit", remediation="",
                ))
    result.composite_score, result.risk_level = score(result.findings)
    result.scan_duration_ms = int((time.time()-t0)*1000)
    return result
