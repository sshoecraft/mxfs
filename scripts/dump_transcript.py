#!/usr/bin/env python3
"""Generic Claude Code session-transcript (.jsonl) raw-evidence dumper.

Extracts, without interpretation: file metadata, compaction summaries,
user-typed messages, assistant text blocks, file writes/edits, Bash
commands+results, and defects.py invocations. Every section prints the
exact filter applied and the pre-truncation total count.

Usage: python3 scripts/dump_transcript.py <path-to-jsonl>
"""
import json
import sys

def load(path):
    recs = []
    bad = 0
    with open(path, "r", errors="replace") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                recs.append(json.loads(line))
            except json.JSONDecodeError:
                bad += 1
    return recs, bad

def get_ts(rec):
    return rec.get("timestamp", "")

def text_of_content_item(item):
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        if item.get("type") == "text":
            return item.get("text", "")
    return None

def main():
    path = sys.argv[1]
    recs, bad = load(path)
    print(f"=== LOAD: {path} ===")
    print(f"total lines parsed as JSON: {len(recs)}, malformed/skipped lines: {bad}")

    # Section 1
    import os
    size = os.path.getsize(path)
    print("\n=== SECTION 1: file size / line count / timestamps / compaction summaries ===")
    print(f"file size (bytes): {size}")
    with open(path, "r", errors="replace") as f:
        nlines = sum(1 for _ in f)
    print(f"raw line count (wc -l equivalent): {nlines}")
    ts_list = [get_ts(r) for r in recs if get_ts(r)]
    print(f"first timestamp: {ts_list[0] if ts_list else 'NONE'}")
    print(f"last timestamp: {ts_list[-1] if ts_list else 'NONE'}")

    summaries = [r for r in recs if r.get("type") == "summary" or r.get("isCompactSummary")]
    print(f"records with type=='summary' or isCompactSummary truthy: {len(summaries)}")
    for i, s in enumerate(summaries, 1):
        print(f"--- summary #{i} (raw json) ---")
        print(json.dumps(s, indent=2))

    # Section 2: user-typed messages
    print("\n=== SECTION 2: user-typed messages (role=user, string content or text blocks; excludes tool_result and system-reminder) ===")
    user_msgs = []
    for r in recs:
        if r.get("type") != "user":
            continue
        msg = r.get("message", {})
        if msg.get("role") != "user":
            continue
        content = msg.get("content")
        ts = get_ts(r)
        if isinstance(content, str):
            if "<system-reminder>" in content and content.strip().startswith("<system-reminder>"):
                continue
            user_msgs.append((ts, content))
        elif isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and item.get("type") == "tool_result":
                    continue
                t = text_of_content_item(item)
                if t is None:
                    continue
                stripped = t.strip()
                if stripped.startswith("<system-reminder>"):
                    continue
                if stripped == "":
                    continue
                user_msgs.append((ts, t))
    total_user = len(user_msgs)
    print(f"total qualifying user-typed message blocks: {total_user}")
    def show_user(idx, ts, t):
        print(f"--- user msg #{idx} [{ts}] ---")
        print(t)
    if total_user > 40:
        print(f"(>40, showing first 5 and last 30 of {total_user})")
        for i, (ts, t) in enumerate(user_msgs[:5], 1):
            show_user(i, ts, t)
        print("... [middle omitted] ...")
        start_idx = total_user - 30 + 1
        for offset, (ts, t) in enumerate(user_msgs[-30:]):
            show_user(start_idx + offset, ts, t)
    else:
        for i, (ts, t) in enumerate(user_msgs, 1):
            show_user(i, ts, t)

    # Section 3: last 15 assistant text blocks
    print("\n=== SECTION 3: final 15 assistant text blocks (not tool calls) ===")
    asst_texts = []
    for r in recs:
        if r.get("type") != "assistant":
            continue
        msg = r.get("message", {})
        if msg.get("role") != "assistant":
            continue
        content = msg.get("content")
        ts = get_ts(r)
        if isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    t = item.get("text", "")
                    if t.strip() == "":
                        continue
                    asst_texts.append((ts, t))
    total_asst = len(asst_texts)
    print(f"total assistant text blocks found: {total_asst}")
    last15 = asst_texts[-15:]
    for i, (ts, t) in enumerate(last15, total_asst - len(last15) + 1):
        print(f"--- assistant text #{i} [{ts}] ---")
        print(t)

    # Section 4: files written/edited
    print("\n=== SECTION 4: files written/edited (Write/Edit tool_use inputs' file_path) ===")
    file_events = []
    for r in recs:
        if r.get("type") != "assistant":
            continue
        msg = r.get("message", {})
        content = msg.get("content")
        if not isinstance(content, list):
            continue
        for item in content:
            if isinstance(item, dict) and item.get("type") == "tool_use" and item.get("name") in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
                fp = item.get("input", {}).get("file_path") or item.get("input", {}).get("notebook_path")
                file_events.append((get_ts(r), item.get("name"), fp))
    print(f"total Write/Edit/MultiEdit/NotebookEdit tool_use events: {len(file_events)}")
    from collections import Counter
    counts = Counter(fp for _, _, fp in file_events if fp)
    print(f"distinct file paths touched: {len(counts)}")
    for fp, c in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"  {c:4d}  {fp}")
    print("--- chronological list (tool, timestamp, path) ---")
    for ts, name, fp in file_events:
        print(f"  [{ts}] {name}: {fp}")

    # Section 5: last 25 Bash tool commands + results
    print("\n=== SECTION 5: last 25 Bash tool commands with results ===")
    bash_uses = []  # (ts, tool_use_id, command)
    for r in recs:
        if r.get("type") != "assistant":
            continue
        msg = r.get("message", {})
        content = msg.get("content")
        if not isinstance(content, list):
            continue
        for item in content:
            if isinstance(item, dict) and item.get("type") == "tool_use" and item.get("name") == "Bash":
                bash_uses.append((get_ts(r), item.get("id"), item.get("input", {}).get("command", "")))
    print(f"total Bash tool_use events in transcript: {len(bash_uses)}")

    # build tool_result index by tool_use_id
    results_by_id = {}
    for r in recs:
        if r.get("type") != "user":
            continue
        msg = r.get("message", {})
        content = msg.get("content")
        if not isinstance(content, list):
            continue
        for item in content:
            if isinstance(item, dict) and item.get("type") == "tool_result":
                tuid = item.get("tool_use_id")
                c = item.get("content")
                is_error = item.get("is_error", False)
                text = ""
                if isinstance(c, str):
                    text = c
                elif isinstance(c, list):
                    for ci in c:
                        if isinstance(ci, dict) and ci.get("type") == "text":
                            text += ci.get("text", "")
                results_by_id[tuid] = (is_error, text)

    last25 = bash_uses[-25:]
    start_idx = len(bash_uses) - len(last25) + 1
    for i, (ts, tuid, cmd) in enumerate(last25, start_idx):
        is_error, result_text = results_by_id.get(tuid, (None, ""))
        print(f"--- bash #{i} [{ts}] is_error={is_error} ---")
        print(f"CMD: {cmd[:300]}")
        print(f"RESULT (first 300 chars): {result_text[:300]}")

    # Section 6: defects.py add/update/remove mentions
    print("\n=== SECTION 6: defects.py add|update|remove mentions ===")
    import re
    pat = re.compile(r"defects\.py\s+(add|update|remove)\b")
    matches = []
    for r in recs:
        if r.get("type") != "assistant":
            continue
        msg = r.get("message", {})
        content = msg.get("content")
        if not isinstance(content, list):
            continue
        for item in content:
            if isinstance(item, dict) and item.get("type") == "tool_use" and item.get("name") == "Bash":
                cmd = item.get("input", {}).get("command", "")
                if pat.search(cmd):
                    matches.append((get_ts(r), cmd))
    print(f"total Bash commands matching /defects\\.py (add|update|remove)/: {len(matches)}")
    for i, (ts, cmd) in enumerate(matches, 1):
        print(f"--- defects.py call #{i} [{ts}] ---")
        print(cmd)

if __name__ == "__main__":
    main()
