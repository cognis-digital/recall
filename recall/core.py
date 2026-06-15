"""Core engine for RECALL: encrypted vault, TF-IDF retrieval, audit log.

Design goals:
- Privacy-first: documents encrypted at rest with a key derived from a
  passphrase via scrypt. Confidentiality + integrity (HMAC-SHA256).
- Local-only: pure stdlib, no network, no external services.
- Auditable: every mutating/reading op appends to a hash-chained log so
  tampering is detectable.
- Real retrieval: TF-IDF cosine similarity ranking, not a stub.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import time
from collections import Counter
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

_MAGIC = b"RCL1"
_SCRYPT_N = 1 << 14
_SCRYPT_R = 8
_SCRYPT_P = 1
_KEYLEN = 64  # 32 bytes enc key + 32 bytes mac key

_WORD_RE = re.compile(r"[a-z0-9]+")
_STOP = frozenset(
    "a an and are as at be by for from has he in is it its of on that the to "
    "was were will with this i you we they not or but if then so my your our".split()
)


def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a 64-byte key from a passphrase using scrypt (stdlib hashlib)."""
    return hashlib.scrypt(
        passphrase.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_KEYLEN,
    )


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """CTR-mode keystream built from HMAC-SHA256 (a PRF). Stdlib only."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hmac.new(
            key, nonce + counter.to_bytes(8, "big"), hashlib.sha256
        ).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def _encrypt(enc_key: bytes, mac_key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(16)
    ks = _keystream(enc_key, nonce, len(plaintext))
    ct = bytes(a ^ b for a, b in zip(plaintext, ks))
    tag = hmac.new(mac_key, nonce + ct, hashlib.sha256).digest()
    return nonce + tag + ct


def _decrypt(enc_key: bytes, mac_key: bytes, blob: bytes) -> bytes:
    nonce, tag, ct = blob[:16], blob[16:48], blob[48:]
    expect = hmac.new(mac_key, nonce + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expect):
        raise ValueError("integrity check failed: vault tampered or wrong key")
    ks = _keystream(enc_key, nonce, len(ct))
    return bytes(a ^ b for a, b in zip(ct, ks))


def _tokenize(text: str) -> List[str]:
    return [w for w in _WORD_RE.findall(text.lower()) if w not in _STOP and len(w) > 1]


@dataclass
class Document:
    id: str
    title: str
    text: str
    tags: List[str] = field(default_factory=list)
    created: float = field(default_factory=time.time)


class AuditLog:
    """Hash-chained, append-only audit log. Each entry commits to the prior
    entry's hash, making silent edits/deletions detectable."""

    def __init__(self, path: str):
        self.path = path

    def _last_hash(self) -> str:
        if not os.path.exists(self.path):
            return "0" * 64
        last = "0" * 64
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    last = json.loads(line)["hash"]
                except (json.JSONDecodeError, KeyError):
                    continue
        return last

    def append(self, action: str, detail: Dict) -> str:
        prev = self._last_hash()
        entry = {
            "ts": time.time(),
            "action": action,
            "detail": detail,
            "prev": prev,
        }
        payload = json.dumps(entry, sort_keys=True).encode("utf-8")
        entry["hash"] = hashlib.sha256(prev.encode() + payload).hexdigest()
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry["hash"]

    def verify(self) -> bool:
        """Return True if the chain is intact."""
        if not os.path.exists(self.path):
            return True
        prev = "0" * 64
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    return False
                if entry.get("prev") != prev:
                    return False
                stored = entry.pop("hash", None)
                if stored is None:
                    return False
                payload = json.dumps(entry, sort_keys=True).encode("utf-8")
                calc = hashlib.sha256(prev.encode() + payload).hexdigest()
                if calc != stored:
                    return False
                prev = stored
        return True

    def entries(self) -> List[Dict]:
        out: List[Dict] = []
        if not os.path.exists(self.path):
            return out
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return out


class Vault:
    """Encrypted document store with local TF-IDF retrieval."""

    def __init__(self, path: str, passphrase: str, audit: Optional[AuditLog] = None):
        self.path = path
        self.passphrase = passphrase
        self.audit = audit or AuditLog(path + ".audit")
        self._docs: List[Document] = []
        self._enc_key = b""
        self._mac_key = b""
        self._salt = b""
        self._load()

    # --- persistence -----------------------------------------------------
    def _split_keys(self, key: bytes) -> Tuple[bytes, bytes]:
        return key[:32], key[32:]

    def _load(self) -> None:
        if not os.path.exists(self.path):
            self._salt = os.urandom(16)
            self._enc_key, self._mac_key = self._split_keys(
                derive_key(self.passphrase, self._salt)
            )
            self._docs = []
            return
        with open(self.path, "rb") as fh:
            raw = fh.read()
        if len(raw) < 20:
            raise ValueError("vault file is too short to be valid")
        if raw[:4] != _MAGIC:
            raise ValueError("not a RECALL vault file")
        self._salt = raw[4:20]
        self._enc_key, self._mac_key = self._split_keys(
            derive_key(self.passphrase, self._salt)
        )
        plaintext = _decrypt(self._enc_key, self._mac_key, raw[20:])
        try:
            data = json.loads(plaintext.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError(f"vault contents could not be decoded: {exc}") from exc
        if "docs" not in data or not isinstance(data["docs"], list):
            raise ValueError("vault is missing required 'docs' field")
        self._docs = [Document(**d) for d in data["docs"]]

    def save(self) -> None:
        vault_dir = os.path.dirname(os.path.abspath(self.path))
        if not os.path.isdir(vault_dir):
            raise OSError(
                f"vault directory does not exist: {vault_dir!r} -- create it first"
            )
        plaintext = json.dumps(
            {"docs": [asdict(d) for d in self._docs]}, sort_keys=True
        ).encode("utf-8")
        blob = _encrypt(self._enc_key, self._mac_key, plaintext)
        tmp = self.path + ".tmp"
        with open(tmp, "wb") as fh:
            fh.write(_MAGIC + self._salt + blob)
        os.replace(tmp, self.path)

    # --- mutation --------------------------------------------------------
    def add(self, title: str, text: str, tags: Optional[List[str]] = None) -> Document:
        title = title.strip() if title else ""
        if not title:
            raise ValueError("document title must not be empty")
        if not isinstance(text, str):
            raise TypeError(
                f"document text must be a string, got {type(text).__name__}"
            )
        doc_id = hashlib.sha256(
            (title + text + str(time.time())).encode("utf-8")
        ).hexdigest()[:12]
        doc = Document(id=doc_id, title=title, text=text, tags=tags or [])
        self._docs.append(doc)
        self.save()
        self.audit.append("add", {"id": doc_id, "title": title, "chars": len(text)})
        return doc

    def documents(self) -> List[Document]:
        return list(self._docs)

    # --- retrieval (real TF-IDF cosine) ----------------------------------
    def _idf(self) -> Dict[str, float]:
        n = len(self._docs)
        df: Counter = Counter()
        for d in self._docs:
            for term in set(_tokenize(d.title + " " + d.text)):
                df[term] += 1
        return {t: math.log((1 + n) / (1 + c)) + 1.0 for t, c in df.items()}

    def _vector(self, tokens: List[str], idf: Dict[str, float]) -> Dict[str, float]:
        tf = Counter(tokens)
        if not tf:
            return {}
        maxf = max(tf.values())
        return {t: (0.5 + 0.5 * c / maxf) * idf.get(t, 0.0) for t, c in tf.items()}

    @staticmethod
    def _cosine(a: Dict[str, float], b: Dict[str, float]) -> float:
        if not a or not b:
            return 0.0
        common = set(a) & set(b)
        dot = sum(a[t] * b[t] for t in common)
        na = math.sqrt(sum(v * v for v in a.values()))
        nb = math.sqrt(sum(v * v for v in b.values()))
        if na == 0 or nb == 0:
            return 0.0
        return dot / (na * nb)

    def query(self, text: str, k: int = 5) -> List[Tuple[Document, float]]:
        if not isinstance(k, int) or isinstance(k, bool):
            raise TypeError(f"k must be an integer, got {type(k).__name__}")
        if k < 1:
            raise ValueError(f"k must be at least 1, got {k}")
        idf = self._idf()
        qvec = self._vector(_tokenize(text), idf)
        scored: List[Tuple[Document, float]] = []
        for d in self._docs:
            dvec = self._vector(_tokenize(d.title + " " + d.text), idf)
            score = self._cosine(qvec, dvec)
            if score > 0:
                scored.append((d, score))
        scored.sort(key=lambda x: x[1], reverse=True)
        top = scored[:k]
        self.audit.append(
            "query", {"q": text, "k": k, "hits": [d.id for d, _ in top]}
        )
        return top


def add_document(
    vault_path: str, passphrase: str, title: str, text: str, tags: Optional[List[str]] = None
) -> Document:
    return Vault(vault_path, passphrase).add(title, text, tags)


def relevant(
    vault_path: str, passphrase: str, query_text: str, k: int = 5
) -> List[Dict]:
    """Return the k most relevant documents to query_text from the vault."""
    if not isinstance(k, int) or isinstance(k, bool):
        raise TypeError(f"k must be an integer, got {type(k).__name__}")
    if k < 1:
        raise ValueError(f"k must be at least 1, got {k}")
    vault = Vault(vault_path, passphrase)
    results = vault.query(query_text, k=k)
    return [
        {
            "id": d.id,
            "title": d.title,
            "score": round(score, 4),
            "snippet": d.text[:200],
            "tags": d.tags,
        }
        for d, score in results
    ]
