#!/usr/bin/env python3
"""PreToolUse read guard — deterministic enforcement against context thrash.

The autocompact-thrashing class is caused by the orchestrator ingesting files it
cannot act on: subagent JSONL transcripts, whole ledgers, whole lockfiles. Prose
did not stop it — the rule + memory file written 2026-09-21 were violated within
the same session (a 257.9KB `tasks/*.output` Read). This hook is the gate: it
fires BEFORE the read, so the bytes never enter context.

Contract (Claude Code PreToolUse):
  stdin  -> JSON {tool_name, tool_input:{file_path, offset?, limit?}, ...}
  exit 0 -> allow
  exit 2 -> BLOCK; stderr is returned to the model as the reason + redirect.

Thresholds are env-tunable:
  READ_GUARD_MAX_BYTES       default 65536  (unwindowed reads)
  READ_GUARD_TASK_OUT_BYTES  default  8192  (*/tasks/*.output, window or not)
  READ_GUARD_MIN_WINDOW      default  2000  (limit >= this is not a real window)
"""

import json
import os
import sys

MAX_BYTES = int(os.environ.get("READ_GUARD_MAX_BYTES", "65536"))
TASK_OUT_BYTES = int(os.environ.get("READ_GUARD_TASK_OUT_BYTES", "8192"))
MIN_WINDOW = int(os.environ.get("READ_GUARD_MIN_WINDOW", "2000"))

TASK_OUT_HELP = """BLOCKED: `{path}` is a task output file ({kb:.1f} KB).

`tasks/*.output` for a local_agent is a symlink to the FULL subagent conversation
transcript (JSONL). Reading it overflows the context window — the single largest
cause of autocompact thrashing.

Use instead:
  - The Agent tool result (returned inline) or the task-notification <result> block.
  - Resume the agent: SendMessage asking for a <=200-word summary.
  - Bash-task output only:  tail -c 4000 {path}   |   sed -n '1,120p' {path}
"""

OVERSIZE_HELP = """BLOCKED: `{path}` is {kb:.1f} KB (guard limit {limit_kb:.0f} KB).

Reading a file this large in the orchestration thread burns the budget subagents
need and produces zero forward motion.

Use instead:
  - Windowed read: Read(file_path=..., offset=N, limit=200) — an explicit window
    under {min_window} lines unblocks this guard.
  - Targeted extract:  grep -n '<anchor>' {path} | head -40
  - Delegate to a fresh-context Explore agent with a <=150-line output cap.
  - Trackers/ledgers (SCOPE.md, DECISIONS.md, _LOOP_LEDGER.md, progress.md,
    CLAUDE.md): NEVER read in the main thread — delegate; hold conclusions only.
"""


def is_windowed(tool_input: dict) -> bool:
    """True only for a genuinely narrow window.

    `offset` alone is not enough — `offset=0` is a no-op window. And `limit`
    only counts when it is small; `limit=99999` is the whole file wearing a
    window's clothes (this was a live bypass of the first cut of this guard).
    """
    limit = tool_input.get("limit")
    return isinstance(limit, int) and 0 < limit < MIN_WINDOW


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0  # never block on a parse failure — fail open

    if payload.get("tool_name") != "Read":
        return 0

    tool_input = payload.get("tool_input") or {}
    path = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
    if not path:
        return 0

    try:
        size = os.path.getsize(path)
    except OSError:
        return 0  # missing file — let the Read tool report it

    # 1. Task output transcripts — hard block above a small floor (so tiny bash
    #    task outputs stay readable); the local_agent transcript class is the target.
    #    A "window" does NOT rescue these: a line-window into JSONL is still junk.
    if "/tasks/" in path and path.endswith(".output") and size > TASK_OUT_BYTES:
        sys.stderr.write(TASK_OUT_HELP.format(path=path, kb=size / 1024))
        return 2

    # 2. Oversized reads without a genuinely narrow window.
    if size > MAX_BYTES and not is_windowed(tool_input):
        sys.stderr.write(
            OVERSIZE_HELP.format(
                path=path,
                kb=size / 1024,
                limit_kb=MAX_BYTES / 1024,
                min_window=MIN_WINDOW,
            )
        )
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
