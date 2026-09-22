#!/usr/bin/env python3
"""PostToolUse oversized-output guard — kills the autocompact-thrash refiller.

Context thrash ("context refilled to the limit within 3 turns") is caused by
tool RESULTS flooding the window: uncapped Bash dumps (grep/cat/sed of huge
files, 200-line lists), full-page MCP snapshots, oversized WebFetch/Read
payloads. PreToolUse guards cannot see result size — this PostToolUse hook is
the deterministic catch: it measures every tool result and warns the model
immediately, with the exact smaller-scope recipe, so the next turn stops
re-importing the same class of bytes.

Contract (Claude Code PostToolUse):
  stdin  -> JSON {tool_name, tool_response: <any>, ...}
  always exit 0 (warn-only — the bytes are already in context; blocking here
  would only break the turn). stderr is returned to the model as feedback.

Thresholds are env-tunable:
  OUTPUT_GUARD_MAX_BYTES   default 30000  (30 KB)
  OUTPUT_GUARD_MAX_LINES   default 500
"""

import json
import os
import sys

MAX_BYTES = int(os.environ.get("OUTPUT_GUARD_MAX_BYTES", "30000"))
MAX_LINES = int(os.environ.get("OUTPUT_GUARD_MAX_LINES", "500"))

# Tools whose size is inherent and already chunked — don't warn (noise).
QUIET = {"TodoWrite", "Task", "Read"}

WARNING = """⚠ CONTEXT-THRASH GUARD: {tool} returned {kb:.0f} KB / {lines} lines.

Oversized tool outputs are the #1 autocompact-thrash cause (context refills
within 3 turns). This result is already in context — do NOT re-request it.
Next time, shrink BEFORE the bytes land:

  - Bash:  pipe through head/tail/python filters, e.g.
       grep -n '<anchor>' file | head -20
       python3 -c "print(open(f).read()[:1500])"
  - Files >200 KB (index.html, styles.css, app.js): NEVER read wholesale —
       targeted grep/sed or a Python extraction with capped output.
  - MCP snapshots: prefer browser_evaluate() with a small JSON return over
       take_snapshot/browser_navigate results.
  - Trackers/ledgers: delegate to a fresh Explore agent, <=150-line cap.

If an autocompact-thrash notice already fired: checkpoint + fresh session.
"""


def measure(response) -> tuple[int, int]:
    """Best-effort (bytes, lines) of a tool result."""
    if response is None:
        return 0, 0
    if isinstance(response, str):
        return len(response.encode("utf-8", "replace")), response.count("\n")
    if isinstance(response, (dict, list)):
        try:
            text = json.dumps(response, default=str)
            return len(text.encode("utf-8", "replace")), text.count("\n")
        except Exception:
            return 0, 0
    try:
        text = str(response)
        return len(text.encode("utf-8", "replace")), text.count("\n")
    except Exception:
        return 0, 0


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0  # fail open — never break a turn on a parse miss

    tool = payload.get("tool_name", "")
    if tool in QUIET:
        return 0

    kb, lines = measure(payload.get("tool_response"))
    if kb > MAX_BYTES or lines > MAX_LINES:
        sys.stderr.write(
            WARNING.format(tool=tool, kb=kb / 1024, lines=lines)
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
