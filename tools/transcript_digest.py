#!/usr/bin/env python3
"""Digest a Claude Code session transcript (.jsonl) into sanitised, readable text.

    python3 tools/transcript_digest.py TRANSCRIPT OUT FIRST LAST MODE

  TRANSCRIPT   the session transcript: one JSON event per physical line
  OUT          output path; "-" writes to stdout and sends the run summary to stderr
  FIRST, LAST  inclusive 1-based physical line numbers (what `wc -l` counts) to
               digest.  "L<n>" in the output is always line n of the transcript,
               whatever range was asked for.
  MODE         text | results | survey

text      Every assistant "text" block, verbatim and in order, under a header
          line "### L<line>", and one line per assistant tool_use:

              - L<line> TOOL <name>: <summary>

          Bash              desc: <description> -- cmd: <first 200 chars of command>
          Edit/Write/Read   <file_path> [offset=N] [limit=N]  (MultiEdit and
                            NotebookEdit the same way)
          Agent/Task        <subagent_type> -- <description>
          every other tool  the first 150 chars of the tool input as JSON
                            (this is the rule for mcp__ tools too)

          Newlines inside a summary become " \u23ce ".  A command or JSON cut at its
          limit says how many characters were cut.  Thinking blocks, tool results
          and every event that is not an assistant event are not emitted.  An
          assistant event holding several text blocks gets "block=i/n" on each
          header.

results   Every tool_result block as "#### L<line> RESULT len=<chars>" followed
          by the first 1500 characters of its text, and every user event whose
          content is a plain string as "#### L<line> USER" followed by its first
          1500 characters.  A user event that carries text blocks beside or
          instead of tool results emits each text block as "#### L<line> USER
          block=text".

          len= is the length of the raw result text before the kernel-log filter
          (several text blocks are joined with a newline; a non-text block such as
          an image is one placeholder line).  The 1500 characters are counted
          after the filter, so log noise does not use up the budget.  The RESULT
          header also names the tool_use it answers (use=L<line> <tool>) and, when
          the filter removed lines, how many (dropped=N, counted over the whole
          text including the part past the cut).  A cut text is followed by a
          "[truncated: ...]" line.

survey    Counts only: event and block shapes, what the kernel-log filter does to
          each source, and whether any kernel-log shape survives into what the two
          digest modes would emit.  It prints no transcript content beyond a few
          short masked samples.

Kernel-log filter, applied to everything the two digest modes emit: a line that
looks like kernel log output or a stack trace is dropped, and each run of
consecutive such lines is replaced by one "[N kernel-log lines dropped]" line.
A raw dmesg dump pasted into a reader's context floods it, so the filter errs
toward dropping.  KERNEL_PATTERNS names every shape; the run summary reports how
many lines each one dropped, per source.

Lines of the digest that start with "@@" describe the run and are not transcript
content.
"""
import collections
import io
import json
import os
import re
import sys

RESULT_CAP = 1500
COMMAND_CAP = 200
JSON_CAP = 150
NEWLINE_MARK = " \u23ce "
DROP_MARKER = "[%d kernel-log lines dropped]"
USAGE = ("usage: python3 tools/transcript_digest.py TRANSCRIPT OUT FIRST LAST MODE"
         "   (MODE: text | results | survey; OUT '-' = stdout)\n")

# The first five are the definition the digests were asked to apply.  The rest are
# the same shapes as the kernel really prints them: dmesg pads the stamp with
# spaces, dmesg -T prints a wall-clock stamp, pstore prefixes a priority, an
# indented frame is " ? sym+0x1a/0x50", a frame is sym+0xOFF/0xSIZE with no
# space before the plus, and journalctl -k or syslog print a kernel line as
# "Sep 28 22:30:10 host kernel: text" (or with an epoch stamp for short-unix)
# with no bracket stamp at all; those two are not anchored to the line start so
# a label or node name in front of the line does not hide it.
KERNEL_PATTERNS = (
    ("bracket-literal", re.compile(r"^\[\d+\.")),
    ("call-trace", re.compile(r"Call Trace")),
    ("rip", re.compile(r"RIP:")),
    ("qmark", re.compile(r"^\? ")),
    ("plus0x", re.compile(r" \+0x")),
    ("bracket-padded", re.compile(r"^\s*(?:<\d+>)?\[\s*\d+\.\d+\]")),
    ("bracket-dmesg-T", re.compile(
        r"^\s*\[[A-Z][a-z]{2} [A-Z][a-z]{2} +\d+ \d\d:\d\d:\d\d \d{4}\]")),
    ("qmark-indented", re.compile(r"^\s+\? ")),
    ("sym-offset", re.compile(r"\w\+0x[0-9a-fA-F]+/0x[0-9a-fA-F]+")),
    ("journal-kernel", re.compile(
        r"\d\d:\d\d:\d\d(?:[.,]\d+)?(?:[+-]\d\d:?\d\d|Z)? \S+ kernel: ")),
    ("journal-kernel-unix", re.compile(r"\b\d{9,}\.\d+ \S+ kernel: ")),
)

# Survey only: wider shapes than the filter names.  A line that matches one of
# these in what would be emitted is a kernel-log shape the filter let through.
LEAK_DETECTORS = (
    ("stamp-anywhere", re.compile(r"\d+\.\d{6}\]")),
    ("syslog-kernel", re.compile(r"\bkernel: ")),
    ("mxfs-prefix", re.compile(r"^\s*mxfs: ")),
    ("node-prefixed", re.compile(r"^\s*(?:test\d+|clyde)\s*[:|] ")),
    ("oops-words", re.compile(
        r"BUG:|Oops[: ]|WARNING: |cut here|end trace|Modules linked in|"
        r"Hardware name:|Workqueue:|Tainted:")),
    ("register-dump", re.compile(
        r"^\s*(?:RSP|RAX|RBX|RCX|RDX|RSI|RDI|RBP|R\d\d|CR2|Code):")),
)

FILE_TOOLS = {"Edit": "file_path", "Write": "file_path", "Read": "file_path",
              "MultiEdit": "file_path", "NotebookEdit": "notebook_path"}
AGENT_TOOLS = ("Agent", "Task")


def kernel_kind(line):
    """Name of the first kernel-log pattern the line matches, or None."""
    for name, pattern in KERNEL_PATTERNS:
        if pattern.search(line):
            return name
    return None


class KernelFilter:
    """Drops kernel-log lines, one count line per run, and keeps the tally."""

    def __init__(self):
        self.dropped = collections.Counter()          # (source, pattern) -> lines
        self.markers = collections.Counter()          # source -> count lines emitted
        self.events = collections.defaultdict(list)   # source -> transcript lines

    def apply(self, source, number, text):
        kept = []
        run = 0
        lost = 0
        for line in text.split("\n"):
            name = kernel_kind(line)
            if name:
                run += 1
                lost += 1
                self.dropped[(source, name)] += 1
                continue
            if run:
                kept.append(DROP_MARKER % run)
                self.markers[source] += 1
                run = 0
            kept.append(line)
        if run:
            kept.append(DROP_MARKER % run)
            self.markers[source] += 1
        if lost:
            self.events[source].append(number)
        return "\n".join(kept), lost


class Output:
    """A file, stdout ("-"), or an in-memory sink (path None) that counts lines."""

    def __init__(self, path):
        self.to_stdout = path == "-"
        if path is None:
            self.handle = io.StringIO()
        elif self.to_stdout:
            self.handle = sys.stdout
        else:
            self.handle = open(path, "w", encoding="utf-8",
                               errors="backslashreplace", newline="\n")
        self.lines = 0

    def write(self, text):
        self.lines += text.count("\n")
        self.handle.write(text)

    def line(self, text=""):
        self.write(text + "\n")

    def close(self):
        if not self.to_stdout:
            self.handle.close()


def load(path):
    """Every event as (physical line number, dict); blank and malformed lines
    are returned by number so nothing is skipped silently."""
    records = []
    blank = []
    malformed = []
    total = 0
    with open(path, "r", encoding="utf-8", errors="replace", newline="\n") as handle:
        for number, raw in enumerate(handle, 1):
            total = number
            text = raw.strip()
            if not text:
                blank.append(number)
                continue
            try:
                event = json.loads(text)
            except json.JSONDecodeError:
                malformed.append(number)
                continue
            if isinstance(event, dict):
                records.append((number, event))
            else:
                malformed.append(number)
    return records, blank, malformed, total


def index_tool_uses(records):
    """tool_use id -> (transcript line, tool name), over the whole file."""
    found = {}
    for number, event in records:
        if event.get("type") != "assistant":
            continue
        for block in message_blocks(event)[0]:
            if block.get("type") == "tool_use":
                found[block.get("id")] = (number, str(block.get("name")))
    return found


def message_blocks(event):
    """The event's message content as a list of dict blocks, and its shape.  A
    plain string becomes one text block (shape "string")."""
    message = event.get("message")
    if not isinstance(message, dict):
        return [], "no-message"
    content = message.get("content")
    if isinstance(content, str):
        return [{"type": "text", "text": content}], "string"
    if isinstance(content, list):
        return [b for b in content if isinstance(b, dict)], "list"
    return [], "no-content"


def result_text(block):
    """Text of a tool_result block: a string as is, text blocks joined with a
    newline, any other block as a one-line placeholder."""
    content = block.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict) and item.get("type") == "text":
                parts.append(str(item.get("text", "")))
            elif isinstance(item, dict):
                parts.append("[%s block omitted]" % item.get("type"))
        return "\n".join(parts)
    return ""


def one_line(text):
    return text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", NEWLINE_MARK)


def cut_note(count):
    return " ...[+%d chars]" % count if count > 0 else ""


def summarise(name, data, number, kfilter):
    """One-line summary of a tool_use input.  Every free-text piece goes through
    the kernel-log filter before it is cut and joined."""
    if name == "Bash":
        description = kfilter.apply("tool-use", number, str(data.get("description") or ""))[0]
        command = kfilter.apply("tool-use", number, str(data.get("command") or ""))[0]
        head = command[:COMMAND_CAP]
        return "desc: %s -- cmd: %s%s" % (one_line(description) or "(none)",
                                          one_line(head),
                                          cut_note(len(command) - len(head)))
    if name in FILE_TOOLS:
        parts = [str(data.get(FILE_TOOLS[name]))]
        for key in ("offset", "limit"):
            if key in data:
                parts.append("%s=%s" % (key, data[key]))
        return " ".join(parts)
    if name in AGENT_TOOLS:
        description = kfilter.apply("tool-use", number, str(data.get("description") or ""))[0]
        return "%s -- %s" % (data.get("subagent_type") or "(none)",
                             one_line(description) or "(none)")
    dumped = json.dumps(data, ensure_ascii=False, default=str)
    head = dumped[:JSON_CAP]
    clean = kfilter.apply("tool-use", number, head)[0]
    return one_line(clean) + cut_note(len(dumped) - len(head))


def emit_capped(out, kfilter, source, number, header, text):
    """Header, then the first RESULT_CAP characters of the filtered text."""
    clean, lost = kfilter.apply(source, number, text)
    if lost:
        header += " dropped=%d" % lost
    out.line(header)
    shown = clean[:RESULT_CAP]
    out.write(shown if shown.endswith("\n") else shown + "\n")
    if len(clean) > RESULT_CAP:
        out.line("[truncated: %d of %d chars shown]" % (RESULT_CAP, len(clean)))


def digest_text(records, first, last, kfilter, out, stats):
    for number, event in records:
        if number < first or number > last or event.get("type") != "assistant":
            continue
        blocks = message_blocks(event)[0]
        texts = sum(1 for b in blocks if b.get("type") == "text")
        seen = 0
        for block in blocks:
            kind = block.get("type")
            if kind == "text":
                seen += 1
                body = block.get("text")
                clean, lost = kfilter.apply("assistant-text", number,
                                            body if isinstance(body, str) else "")
                header = "### L%d" % number
                if texts > 1:
                    header += " block=%d/%d" % (seen, texts)
                out.line(header)
                out.write(clean if clean.endswith("\n") else clean + "\n")
                out.line()
                stats["text_blocks"] += 1
                if event.get("isSidechain"):
                    stats["text_blocks_from_sidechain_events"] += 1
            elif kind == "tool_use":
                name = str(block.get("name"))
                data = block.get("input") if isinstance(block.get("input"), dict) else {}
                out.line("- L%d TOOL %s: %s" % (number, name,
                                                summarise(name, data, number, kfilter)))
                stats["tool_use"] += 1
                stats["tool_use:" + name] += 1
            elif kind in ("thinking", "redacted_thinking"):
                stats["thinking_skipped"] += 1
            else:
                stats["other_assistant_block:%s" % kind] += 1


def digest_results(records, first, last, tool_uses, kfilter, out, stats):
    for number, event in records:
        if number < first or number > last or event.get("type") != "user":
            continue
        blocks, shape = message_blocks(event)
        if shape == "string":
            emit_capped(out, kfilter, "user-string", number,
                        "#### L%d USER" % number, blocks[0]["text"])
            stats["user_string_events"] += 1
            continue
        results = sum(1 for b in blocks if b.get("type") == "tool_result")
        seen = 0
        for block in blocks:
            kind = block.get("type")
            if kind == "tool_result":
                seen += 1
                text = result_text(block)
                header = "#### L%d RESULT len=%d" % (number, len(text))
                answered = tool_uses.get(block.get("tool_use_id"))
                if answered:
                    header += " use=L%d %s" % answered
                if results > 1:
                    header += " block=%d/%d" % (seen, results)
                emit_capped(out, kfilter, "tool-result", number, header, text)
                stats["tool_result_blocks"] += 1
                if block.get("is_error"):
                    stats["tool_result_is_error"] += 1
            elif kind == "text":
                body = block.get("text")
                emit_capped(out, kfilter, "user-text-block", number,
                            "#### L%d USER block=text" % number,
                            body if isinstance(body, str) else "")
                stats["user_text_blocks"] += 1
            else:
                stats["other_user_block:%s" % kind] += 1


def fmt(counter):
    items = sorted(counter.items(), key=lambda kv: (-kv[1], str(kv[0])))
    return ", ".join("%s=%d" % kv for kv in items) or "-"


def mask(line):
    return re.sub(r"\d", "#", line[:60])


def survey(records, blank, malformed, total, first, last, tool_uses, out):
    inrange = [(n, e) for n, e in records if first <= n <= last]
    out.line("lines: total=%d range=%d..%d parsed_in_range=%d blank=%d malformed=%d %s"
             % (total, first, min(last, total), len(inrange), len(blank), len(malformed),
                malformed[:20]))
    types = collections.Counter()
    subtypes = collections.Counter()
    flags = collections.Counter()
    shapes = collections.Counter()
    block_types = collections.Counter()
    blocks_per_event = collections.Counter()
    models = collections.Counter()
    message_ids = collections.Counter()
    texts = collections.Counter()
    tools = collections.Counter()
    text_per_event = collections.Counter()
    results_per_event = collections.Counter()
    result_shapes = collections.Counter()
    nondict = 0
    unmatched_results = 0
    for number, event in inrange:
        kind = event.get("type")
        types[kind] += 1
        if kind == "system":
            subtypes[str(event.get("subtype"))] += 1
        for flag in ("isSidechain", "isMeta", "isCompactSummary", "isApiErrorMessage"):
            if event.get(flag):
                flags["%s/%s" % (kind, flag)] += 1
        blocks, shape = message_blocks(event)
        shapes["%s/%s" % (kind, shape)] += 1
        message = event.get("message")
        if isinstance(message, dict):
            content = message.get("content")
            if isinstance(content, list):
                nondict += len(content) - len(blocks)
            if kind == "assistant":
                models[str(message.get("model"))] += 1
                message_ids[str(message.get("id"))] += 1
        blocks_per_event["%s:%d" % (kind, len(blocks))] += 1
        for block in blocks:
            block_types["%s/%s" % (kind, block.get("type"))] += 1
        if kind == "assistant":
            text_per_event[sum(1 for b in blocks if b.get("type") == "text")] += 1
            for block in blocks:
                if block.get("type") == "tool_use":
                    tools[str(block.get("name"))] += 1
                elif block.get("type") == "text":
                    texts[str(block.get("text"))] += 1
        elif kind == "user":
            results = [b for b in blocks if b.get("type") == "tool_result"]
            results_per_event[len(results)] += 1
            for block in results:
                content = block.get("content")
                if isinstance(content, str):
                    result_shapes["str"] += 1
                elif isinstance(content, list):
                    items = sorted({str(i.get("type")) if isinstance(i, dict) else "str"
                                    for i in content})
                    result_shapes["list[%s]x%s" % (",".join(items),
                                                   "1" if len(content) == 1 else "n")] += 1
                else:
                    result_shapes[type(content).__name__] += 1
                if block.get("tool_use_id") not in tool_uses:
                    unmatched_results += 1
    out.line("event types: %s" % fmt(types))
    out.line("system subtypes: %s" % fmt(subtypes))
    out.line("flags: %s" % fmt(flags))
    out.line("event shapes: %s" % fmt(shapes))
    out.line("block types: %s" % fmt(block_types))
    out.line("blocks per event: %s" % fmt(blocks_per_event))
    out.line("non-dict entries in content lists: %d" % nondict)
    out.line("assistant models: %s" % fmt(models))
    out.line("assistant events=%d distinct message ids=%d; text blocks=%d distinct texts=%d"
             % (sum(message_ids.values()), len(message_ids), sum(texts.values()), len(texts)))
    out.line("assistant text blocks per event: %s" % fmt(text_per_event))
    out.line("tool_use names: %s" % fmt(tools))
    out.line("tool_result blocks per user event: %s" % fmt(results_per_event))
    out.line("tool_result content shapes: %s" % fmt(result_shapes))
    out.line("tool_result blocks whose tool_use id is not in the file: %d" % unmatched_results)

    # Dry run of both digests: what the filter drops, per source and pattern, and
    # whether a wider kernel-log shape survives into what would be emitted.
    for mode in ("text", "results"):
        sink = Output(None)
        kfilter = KernelFilter()
        stats = collections.Counter()
        if mode == "text":
            digest_text(records, first, last, kfilter, sink, stats)
        else:
            digest_results(records, first, last, tool_uses, kfilter, sink, stats)
        emitted = [l for l in sink.handle.getvalue().split("\n")
                   if not re.fullmatch(r"\[\d+ kernel-log lines dropped\]", l)]
        out.line("[%s dry run] emitted lines=%d; stats: %s" % (mode, len(emitted), fmt(stats)))
        out.line("[%s dry run] dropped by (source, pattern): %s" % (
            mode, fmt(collections.Counter({"%s/%s" % k: v for k, v in kfilter.dropped.items()}))))
        out.line("[%s dry run] count lines emitted by source: %s" % (mode, fmt(kfilter.markers)))
        out.line("[%s dry run] transcript lines that lost lines, by source: %s" % (
            mode, "; ".join("%s: n=%d first=%s" % (s, len(set(v)), sorted(set(v))[:25])
                            for s, v in sorted(kfilter.events.items())) or "-"))
        remaining = [l for l in emitted if kernel_kind(l)]
        out.line("[%s dry run] emitted lines still matching a kernel pattern: %d"
                 % (mode, len(remaining)))
        for name, detector in LEAK_DETECTORS:
            hits = [l for l in emitted if detector.search(l)]
            out.line("[%s dry run] emitted lines matching wider shape %s: %d"
                     % (mode, name, len(hits)))
            for sample in hits[:12]:
                out.line("    sample(masked, 60 chars): %s" % mask(sample))


def main(argv):
    if len(argv) != 6:
        sys.stderr.write(USAGE)
        return 2
    path, outpath, first, last, mode = argv[1:6]
    try:
        first = int(first)
        last = int(last)
    except ValueError:
        sys.stderr.write(USAGE)
        return 2
    if mode not in ("text", "results", "survey") or first < 1 or last < first:
        sys.stderr.write(USAGE)
        return 2
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="backslashreplace")

    records, blank, malformed, total = load(path)
    tool_uses = index_tool_uses(records)
    out = Output(outpath)
    if mode == "survey":
        survey(records, blank, malformed, total, first, last, tool_uses, out)
        out.close()
        return 0

    kfilter = KernelFilter()
    stats = collections.Counter()
    span = "%d..%d" % (first, min(last, total))
    out.line("@@ transcript_digest mode=%s source=%s lines=%s of %d" % (mode, path, span, total))
    if mode == "text":
        out.line("@@ emitted: assistant text blocks verbatim (### L<line>) and one TOOL line per "
                 "tool_use; not emitted: thinking blocks, tool results, non-assistant events")
        digest_text(records, first, last, kfilter, out, stats)
    else:
        out.line("@@ emitted: tool_result blocks and user events with plain-string content, "
                 "first %d chars each after the filter; len= is the raw length" % RESULT_CAP)
        digest_results(records, first, last, tool_uses, kfilter, out, stats)
    total_dropped = sum(kfilter.dropped.values())
    out.line("@@ filter: runs of kernel-log or stack-trace lines are replaced by a count line; "
             "pattern names: %s" % ",".join(n for n, p in KERNEL_PATTERNS))
    out.line("@@ end: %s; kernel_lines_dropped=%d count_lines_emitted=%d"
             % (fmt(stats), total_dropped, sum(kfilter.markers.values())))
    out.close()

    parsed_in_range = sum(1 for n, e in records if first <= n <= last)
    blank_in_range = sum(1 for n in blank if first <= n <= last)
    malformed_in_range = [n for n in malformed if first <= n <= last]
    report = sys.stderr if out.to_stdout else sys.stdout
    report.write("transcript: %s\n" % path)
    report.write("range: %s of %d physical lines; events parsed in range=%d blank=%d malformed=%d %s\n"
                 % (span, total, parsed_in_range, blank_in_range, len(malformed_in_range),
                    malformed_in_range[:20]))
    if not out.to_stdout:
        report.write("output: %s bytes=%d lines=%d\n" % (outpath, os.path.getsize(outpath), out.lines))
    report.write("mode=%s counts: %s\n" % (mode, fmt(stats)))
    report.write("kernel-log lines dropped: total=%d; count lines emitted=%d\n"
                 % (total_dropped, sum(kfilter.markers.values())))
    by_source = collections.Counter()
    by_pattern = collections.Counter()
    for (source, name), count in kfilter.dropped.items():
        by_source[source] += count
        by_pattern[name] += count
    report.write("dropped by source: %s\n" % fmt(by_source))
    report.write("dropped by pattern: %s\n" % fmt(by_pattern))
    report.write("dropped by (source, pattern): %s\n"
                 % fmt(collections.Counter({"%s/%s" % k: v for k, v in kfilter.dropped.items()})))
    for source, numbers in sorted(kfilter.events.items()):
        unique = sorted(set(numbers))
        report.write("transcript lines that lost lines in %s: n=%d first=%s\n"
                     % (source, len(unique), unique[:40]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
