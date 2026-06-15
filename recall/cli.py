"""Command-line interface for RECALL.

Subcommands:
  relevant   Retrieve the most relevant documents for a query.
  add        Add a document to the encrypted vault.
  audit      Show / verify the tamper-evident audit log.

Global: --version, --format {table,json}.
Passphrase comes from --passphrase or the RECALL_PASSPHRASE env var.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import AuditLog, Vault, relevant


def _passphrase(args) -> str:
    pw = args.passphrase or os.environ.get("RECALL_PASSPHRASE")
    if not pw:
        raise SystemExit("error: passphrase required (--passphrase or RECALL_PASSPHRASE)")
    return pw


def _emit(obj, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(obj, indent=2, sort_keys=True))
        return
    # table
    if isinstance(obj, list):
        if not obj:
            print("(no results)")
            return
        cols = ["score", "id", "title", "snippet"]
        if cols[0] not in obj[0]:
            cols = list(obj[0].keys())
        widths = {c: len(c) for c in cols}
        for row in obj:
            for c in cols:
                widths[c] = max(widths[c], len(str(row.get(c, ""))[:60]))
        header = "  ".join(c.ljust(widths[c]) for c in cols)
        print(header)
        print("  ".join("-" * widths[c] for c in cols))
        for row in obj:
            print("  ".join(str(row.get(c, ""))[:60].ljust(widths[c]) for c in cols))
    else:
        for k, v in obj.items():
            print(f"{k}: {v}")


def _cmd_relevant(args) -> int:
    pw = _passphrase(args)
    results = relevant(args.vault, pw, args.query, k=args.k)
    _emit(results, args.format)
    return 0 if results else 1


def _cmd_add(args) -> int:
    pw = _passphrase(args)
    text = args.text
    if args.file:
        if not os.path.isfile(args.file):
            print(f"error: file not found: {args.file!r}", file=sys.stderr)
            return 2
        try:
            with open(args.file, "r", encoding="utf-8") as fh:
                text = fh.read()
        except OSError as exc:
            print(f"error: cannot read file {args.file!r}: {exc}", file=sys.stderr)
            return 2
    if not text:
        raise SystemExit("error: provide --text or --file")
    doc = Vault(args.vault, pw).add(args.title, text, args.tag)
    _emit({"id": doc.id, "title": doc.title, "chars": len(text)}, args.format)
    return 0


def _cmd_audit(args) -> int:
    log = AuditLog(args.vault + ".audit")
    intact = log.verify()
    if args.format == "json":
        _emit({"intact": intact, "entries": log.entries()}, "json")
    else:
        print(f"chain intact: {intact}")
        for e in log.entries():
            print(f"{e['ts']:.0f}  {e['action']:<8}  {json.dumps(e['detail'])}")
    return 0 if intact else 2



def _positive_int(value: str) -> int:
    """argparse type: integer that must be >= 1."""
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not a valid integer")
    if n < 1:
        raise argparse.ArgumentTypeError(f"k must be at least 1, got {n}")
    return n

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME, description="Privacy-first local RAG over personal data."
    )
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    p.add_argument("--format", choices=["table", "json"], default="table")
    p.add_argument("--vault", default=os.environ.get("RECALL_VAULT", "recall.vault"))
    p.add_argument("--passphrase", default=None)
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("relevant", help="retrieve most relevant documents")
    r.add_argument("query")
    r.add_argument("-k", type=_positive_int, default=5, metavar="K",
                   help="number of results to return (default: 5)")
    r.set_defaults(func=_cmd_relevant)

    a = sub.add_parser("add", help="add a document to the vault")
    a.add_argument("title")
    a.add_argument("--text", default="")
    a.add_argument("--file", default=None)
    a.add_argument("--tag", action="append", default=[])
    a.set_defaults(func=_cmd_add)

    au = sub.add_parser("audit", help="show / verify the audit log")
    au.set_defaults(func=_cmd_audit)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - surface as non-zero exit
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
