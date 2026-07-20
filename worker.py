#!/usr/bin/env python3
"""MXFS Director Worker — spawns a Claude Code subprocess for grunt work.

Loads a layered context system:
  1. worker-system.md   — environment, tools, absolute rules (always loaded)
  2. worker-methodology.md — how to work: instrument→prove→fix (always loaded)
  3. Task brief          — specific work item (passed via --task or --task-file)

Based on ~trader/bin/opus_reviewer pattern. Unsets CLAUDECODE to allow nesting.
Runs in bypassPermissions mode.

Usage:
    worker.py --task "Investigate the 1/40 missing dir in concurrent mkdir"
    worker.py --task-file .claude/director/tasks/fix-shortform-race.md
    worker.py --task "..." --effort max

v0.2.0
"""

import json
import os
import subprocess
import sys
import threading
import time

CLAUDE_BIN = os.path.expanduser("~/.local/bin/claude")
MAX_OUTPUT_TOKENS = 64000
DIRECTOR_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            ".claude", "director")


def load_system_prompt():
    """Load the layered system context from director docs."""
    parts = []
    for doc in ["worker-system.md", "worker-methodology.md"]:
        path = os.path.join(DIRECTOR_DIR, doc)
        if os.path.exists(path):
            with open(path) as f:
                parts.append(f.read())
        else:
            print(f"WARNING: {path} not found", file=sys.stderr)
    return "\n\n---\n\n".join(parts)


def main():
    import argparse

    parser = argparse.ArgumentParser(description="MXFS Director Worker")
    parser.add_argument("--task", help="Task description (inline)")
    parser.add_argument("--task-file", help="Path to file containing task brief")
    parser.add_argument("--system-prompt-file",
                        help="Override system prompt (skip auto-load)")
    parser.add_argument("--effort", default=None,
                        choices=["low", "medium", "high", "max"],
                        help="Override reasoning effort (default: use settings.json)")
    parser.add_argument("--timeout", type=int, default=600,
                        help="Timeout in seconds (default 600)")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    # Load task
    if args.task_file:
        with open(args.task_file) as f:
            task = f.read()
    elif args.task:
        task = args.task
    else:
        print("ERROR: --task or --task-file required", file=sys.stderr)
        sys.exit(1)

    # Load system prompt
    if args.system_prompt_file:
        with open(args.system_prompt_file) as f:
            system_prompt = f.read()
    else:
        system_prompt = load_system_prompt()

    # Build command
    argv = [
        CLAUDE_BIN, "-p",
        "--verbose",
        "--output-format", "stream-json",
        "--permission-mode", "bypassPermissions",
    ]
    if args.effort:
        argv.extend(["--effort", args.effort])
    argv.extend([
        "--system-prompt", system_prompt,
        task,
    ])

    env = dict(os.environ)
    env.pop("CLAUDECODE", None)
    env["CLAUDE_CODE_MAX_OUTPUT_TOKENS"] = str(MAX_OUTPUT_TOKENS)

    if args.debug:
        print(f"System prompt: {len(system_prompt)} chars", flush=True)
        print(f"Task: {len(task)} chars", flush=True)
        print(f"CMD: {argv[:6]}...", flush=True)

    collected_text = []
    tool_count = 0
    start = time.time()

    proc = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def drain_stderr():
        for line in proc.stderr:
            pass  # suppress stderr noise
    threading.Thread(target=drain_stderr, daemon=True).start()

    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
            etype = event.get("type")

            if etype == "assistant":
                for block in event.get("message", {}).get("content", []):
                    kind = block.get("type")
                    if kind == "text":
                        text = block.get("text", "")
                        if text.strip():
                            collected_text.append(text)
                    elif kind == "tool_use":
                        tool_count += 1
                        name = block.get("name", "")
                        inp = block.get("input", {})
                        desc = (inp.get("description")
                                or inp.get("command", "")[:80]
                                or inp.get("file_path", "")
                                or inp.get("pattern", "")
                                or "")
                        elapsed = time.time() - start
                        print(f"  [{elapsed:5.0f}s] {name}: {desc}",
                              flush=True)

            elif etype == "result":
                cost = event.get("total_cost_usd", 0)
                turns = event.get("num_turns", 0)
                duration = event.get("duration_ms", 0) / 1000
                print(f"  Done: {turns} turns, {tool_count} tools, "
                      f"{duration:.0f}s, ${cost:.2f}", flush=True)

        except json.JSONDecodeError:
            pass

    proc.wait(timeout=30)

    result = "".join(collected_text)
    print("\n--- WORKER OUTPUT ---")
    print(result)
    print("--- END ---")

    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
