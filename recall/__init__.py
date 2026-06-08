"""RECALL - Privacy-first local RAG over personal data.

Encrypted at rest, audit-logged, zero-dependency. All retrieval happens
locally; no data ever leaves the machine. Documents are stored in an
encrypted vault (scrypt-derived key + AES-CTR via stdlib AES emulation in
pure Python is heavy, so we use a hardened keystream cipher + HMAC).
Every read/query is appended to a tamper-evident audit log.
"""
from .core import (
    Vault,
    AuditLog,
    relevant,
    add_document,
    derive_key,
)

TOOL_NAME = "recall"
TOOL_VERSION = "1.0.0"

__all__ = [
    "Vault",
    "AuditLog",
    "relevant",
    "add_document",
    "derive_key",
    "TOOL_NAME",
    "TOOL_VERSION",
]
