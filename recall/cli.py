"""RECALL command-line interface."""
from cognis_core import build_cli
from recall.core import scan, TOOL_NAME, TOOL_VERSION

main = build_cli(
    tool_name=TOOL_NAME,
    tool_version=TOOL_VERSION,
    description="Privacy-first local RAG over personal data — encrypted, audit-logged",
    scan_fn=scan,
)

if __name__ == "__main__":
    import sys
    sys.exit(main())
