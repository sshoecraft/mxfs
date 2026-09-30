#!/usr/bin/env python3
"""Attribute every guest-kernel crash in a netconsole capture to a listener
segment, a faulting function and a panic reason.

usage: netconsole_crash_table.py LOG OUT [YYYY-MM-DD]

LOG   the capture appended by tools/netconsole_listen.sh
OUT   tab-separated table: a header row, one crash event per row, then a
      summary block.  Only extracted fields are written; no log line is copied.
DATE  analyse only segments whose listener-start marker carries this UTC date
      (default 2026-09-29).  The summary block is also printed on stdout.

The capture.  The listener appends each UDP datagram raw, so lines from several
VMs interleave, nothing names the VM and nothing records when a line arrived.
The one clock on a line is the guest uptime in its leading bracket; the one
boundary between runs is the marker line the listener writes when it starts.
A marker can be glued to the end of a partial line, so it is searched for
anywhere in a line; text before it stays in the earlier segment.

Segments.  Segment 0 is everything before the first marker; it has no marker
time and is never analysed.  A segment's line count is its number of text
lines, not counting the marker line itself.

Events.  A line holding a trigger string (TRIGGERS) starts or joins a window:
the 3-second rule says trigger lines whose uptime is within WINDOW_SECONDS of
the window's first trigger line are one crash.  A trigger line also has to sit
within GUARD_AFTER lines of the window's previous trigger line, so two VMs far
apart in the file are not fused by a coincidence of uptime.

A window is not always one VM.  Two VMs booted together crash with uptimes a
fraction of a second apart, inside one window.  A VM's uptime does not run
backwards in file order, so the lines of a window (every clocked line in the
segment within WINDOW_SECONDS of the window's first trigger line and inside the
GUARD_BEFORE/GUARD_AFTER position bounds) are dealt into streams by uptime
continuity: a line joins the stream whose last uptime is nearest below it, to
within CHAIN_TOLERANCE.  A stream holding a trigger line is one event; a stream
holding none is another VM's ordinary output and is dropped.  The summary gives
the event count under the plain 3-second rule and under the stream split, and a
vm_check column flags a stream that still shows two crashed VMs (two first-oops
die counters, or two panic lines).

Kind.  The first primary trigger line of the event decides it.  "oops" and
"panic" lines are secondary: an event holding only a panic line is panic-only,
one holding an oops line but no primary line is oops-unclassified.

Function.  The symbol on the first "RIP: 0010:" line of the event.  A RIP that
is a bare address has no symbol; the function is then "(no symbol)" and
rip_region says which kernel address range the address is in.

mxfs frames.  Call-trace frame lines whose module tag is [mxfs]; the RIP line is
not a frame.  mxfs_first3 is the first three DISTINCT function names in order of
first appearance over all such frames, mxfs_first3_reliable the same over frames
the kernel did not mark with a leading question mark.

Deliberate.  The string "sysrq" (case-sensitive) anywhere in the event's lines.
The summary also counts events where a case-insensitive match would differ.

A RIP with no symbol.  The kernel prints a bare address when no loaded module
and no part of the kernel image covers it, which is what code of a module that
has been unloaded looks like to the thread still running it.  Three columns say
what can still be said: rip_low12 is the address's offset inside its page (a
module's text starts on a page boundary, so this is the low 12 bits of the
site's offset in the module whatever address the module was loaded at);
modules_mxfs says whether the event's "Modules linked in" list names mxfs, with
the flags the kernel printed beside it; bare_frames lists the call-trace
entries that are bare addresses in the module area, each as its distance from
the RIP, so two events at the same site of the same build agree on all three.
trace_names is the first TRACE_NAMES_KEPT distinct symbols of the call trace,
whatever module they belong to.
"""
import re
import sys
from collections import Counter, OrderedDict
from dataclasses import dataclass, field

DEFAULT_DATE = "2026-09-29"
WINDOW_SECONDS = 3.0
CHAIN_TOLERANCE = 0.010
GUARD_BEFORE = 150
GUARD_AFTER = 400
NAMES_KEPT = 3

MARKER = re.compile(r"-- listener started (\S+) --")
UPTIME_LEAD = re.compile(r"\s*\[\s*(\d+\.\d+)\]")
UPTIME_ANY = re.compile(r"\[\s*(\d+\.\d+)\]")
ISO_DATE = re.compile(r"^(\d{4}-\d{2}-\d{2})")
LISTENER_EXIT = re.compile(r"^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} socat\[\d+\] [A-Z] exiting on signal \d+$")

# (kind, pattern, primary).  A primary trigger names the kind of the event.
TRIGGERS = (
    ("null-deref", re.compile(r"BUG: kernel NULL pointer dereference"), True),
    ("page-fault", re.compile(r"BUG: unable to handle"), True),
    ("GPF", re.compile(r"general protection fault"), True),
    ("kernel-BUG", re.compile(r"kernel BUG at"), True),
    ("oops", re.compile(r"Oops:"), False),
    ("panic", re.compile(r"Kernel panic - not syncing"), False),
    ("soft-lockup", re.compile(r"watchdog: BUG: soft lockup"), True),
    ("rcu-stall", re.compile(r"rcu: INFO: rcu_sched"), True),
    ("hung-task", re.compile(r"INFO: task .* blocked for more than"), True),
)

RIP_SYMBOL = re.compile(
    r"RIP:\s*0010:(?:\[<[0-9a-fA-F]+>\]\s*)?([A-Za-z_.$][\w.$]*)\+0x[0-9a-fA-F]+/0x[0-9a-fA-F]+"
    r"(?:\s+\[([^\]\s]+)\])?")
RIP_RAW = re.compile(r"RIP:\s*0010:(?:\[<)?(?:0x)?([0-9a-fA-F]{5,16})")
COMM = re.compile(r"Comm:\s*(\S+)")
PANIC_START = re.compile(r"(?<!end )Kernel panic - not syncing(?::\s*(.*?))?\s*$")
PANIC_END = re.compile(r"end Kernel panic - not syncing(?::\s*(.*?))?\s*\]---")
FRAME = re.compile(
    r"^\s*(?:\[\s*\d+\.\d+\]\s+)?(?:\[<[0-9a-fA-F]+>\]\s+)?(\?\s+)?([A-Za-z_.$][\w.$]*)"
    r"\+0x[0-9a-fA-F]+/0x[0-9a-fA-F]+(?:\s+\[([^\]\s]+)\])?\s*$")
DIE_COUNTER = re.compile(r":\s*[0-9a-fA-F]{4}\s+\[#(\d+)\]")
OTHER_HEADER = re.compile(
    r"(invalid opcode|divide error|stack segment|double fault|int3|alignment check|invalid TSS|"
    r"segment not present|coprocessor error|simd exception|bounds)\s*:\s*[0-9a-fA-F]{4}\s+\[#\d+\]")
PF_ACCESS = re.compile(r"#PF:\s*(\w+)\s+(instruction fetch|read access|write access)")
FAULT_ADDRESS = re.compile(r"address:\s*([0-9a-fA-F]{4,16})")
HEX_VALUE = re.compile(r"0x[0-9a-fA-F]+")
BARE_FRAME = re.compile(r"^\s*(?:\[\s*\d+\.\d+\]\s+)?(?:\?\s+)?(?:0x)?([0-9a-fA-F]{16})\s*$")
MODULES_LINE = re.compile(r"Modules linked in:(.*)$")
MODULE_MXFS = re.compile(r"(?:^|\s)mxfs(\([^)\s]*\))?(?=\s|$)")
TRACE_NAMES_KEPT = 8
BARE_FRAMES_KEPT = 8

COLUMNS = (
    "segment_marker", "uptime_s", "kind", "function", "module", "comm", "panic_reason",
    "deliberate", "mxfs_in_trace", "mxfs_first3",
    "mxfs_first3_reliable", "segment_index", "first_file_line", "lines_in_event",
    "rip_state", "rip_region", "fault_region", "pf_access", "other_header",
    "dumps", "die_counters", "panic_lines", "rip_functions", "kinds_seen",
    "window", "vms_in_window", "vm_check",
    "rip_low12", "modules_mxfs", "bare_frames", "trace_names",
)


@dataclass
class Row:
    number: int
    text: str
    uptime: object


@dataclass
class Segment:
    index: int
    marker: object
    rows: list = field(default_factory=list)


@dataclass
class Trigger:
    pos: int
    uptime: object
    kinds: list


@dataclass
class Window:
    first_pos: int
    first_uptime: float
    last_pos: int
    triggers: list = field(default_factory=list)


def uptime_of(text):
    match = UPTIME_LEAD.match(text)
    if match:
        return float(match.group(1))
    match = UPTIME_ANY.search(text)
    return float(match.group(1)) if match else None


def split_segments(text):
    """Cut the capture at every listener marker.  Returns (segments, stats)."""
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    segments = [Segment(index=0, marker=None)]
    stats = Counter()
    stats["lines"] = len(lines)
    for number, raw in enumerate(lines, start=1):
        line = raw.rstrip("\r")
        matches = list(MARKER.finditer(line))
        if not matches:
            segments[-1].rows.append(Row(number, line, uptime_of(line)))
            continue
        stats["lines_with_marker"] += 1
        cursor = 0
        for match in matches:
            before = line[cursor:match.start()]
            if before.strip():
                stats["markers_glued_to_text"] += 1
                segments[-1].rows.append(Row(number, before, uptime_of(before)))
            segments.append(Segment(index=len(segments), marker=match.group(1)))
            stats["markers"] += 1
            cursor = match.end()
        after = line[cursor:]
        if after.strip():
            stats["text_after_marker"] += 1
            segments[-1].rows.append(Row(number, after, uptime_of(after)))
    return segments, stats


def trigger_kinds(text):
    found = [(kind, primary) for kind, pattern, primary in TRIGGERS if pattern.search(text)]
    if "NULL pointer dereference" in text:
        found = [("null-deref" if kind == "page-fault" else kind, primary) for kind, primary in found]
    return found


def find_triggers(segment):
    triggers = []
    for pos, row in enumerate(segment.rows):
        kinds = trigger_kinds(row.text)
        if kinds:
            triggers.append(Trigger(pos, row.uptime, kinds))
    return triggers


def literal_windows(triggers):
    """The 3-second rule.  Returns (windows, triggers that carry no uptime)."""
    windows = []
    unclocked = []
    for trigger in triggers:
        if trigger.uptime is None:
            unclocked.append(trigger)
            continue
        home = None
        home_gap = None
        for window in windows:
            gap = abs(trigger.uptime - window.first_uptime)
            if gap <= WINDOW_SECONDS and trigger.pos - window.last_pos <= GUARD_AFTER:
                if home is None or gap < home_gap:
                    home, home_gap = window, gap
        if home is None:
            windows.append(Window(trigger.pos, trigger.uptime, trigger.pos, [trigger]))
        else:
            home.triggers.append(trigger)
            home.last_pos = max(home.last_pos, trigger.pos)
    return windows, unclocked


def deal_streams(members):
    """Deal clocked rows into per-VM streams by uptime continuity."""
    streams = []
    for pos, row in members:
        best = None
        best_gap = None
        for stream in streams:
            if row.uptime >= stream["last"] - CHAIN_TOLERANCE:
                gap = abs(row.uptime - stream["last"])
                if best is None or gap < best_gap:
                    best, best_gap = stream, gap
        if best is None:
            streams.append({"last": row.uptime, "members": [(pos, row)]})
        else:
            best["members"].append((pos, row))
            best["last"] = max(best["last"], row.uptime)
    return streams


def region_of(value):
    if value < 0x1000:
        return "null-page"
    if value < 0x800000000000:
        return "user-space"
    if 0xffff888000000000 <= value < 0xffffc88000000000:
        return "direct-map"
    if 0xffffc90000000000 <= value < 0xffffe90000000000:
        return "vmalloc"
    if 0xffffffff80000000 <= value < 0xffffffffc0000000:
        return "kernel-image-band"
    if 0xffffffffc0000000 <= value < 0xffffffffff000000:
        return "module-area"
    return "other"


def first_names(pairs, keep_unreliable):
    names = []
    for name, unreliable in pairs:
        if unreliable and not keep_unreliable:
            continue
        if name not in names:
            names.append(name)
        if len(names) == NAMES_KEPT:
            break
    return names


def describe(segment, window_id, parts, members, triggers):
    """Turn one stream of rows into the attributes of one crash event."""
    texts = [row.text for pos, row in members]
    first = triggers[0]
    first_row = segment.rows[first.pos]
    kinds_seen = []
    kind = None
    for trigger in triggers:
        for name, primary in trigger.kinds:
            if name not in kinds_seen:
                kinds_seen.append(name)
            if primary and kind is None:
                kind = name
    if kind is None:
        kind = "oops-unclassified" if "oops" in kinds_seen else "panic-only"

    function, module, rip_state, rip_region = "-", "-", "absent", "-"
    rip_count = 0
    rip_functions = []
    for text in texts:
        if "RIP: 0010:" not in text:
            continue
        rip_count += 1
        symbol = RIP_SYMBOL.search(text)
        raw = RIP_RAW.search(text)
        if symbol:
            name, mod, state, region = symbol.group(1), symbol.group(2) or "-", "symbol", "-"
        elif raw:
            name, mod, state, region = "(no symbol)", "-", "raw-address", region_of(int(raw.group(1), 16))
        else:
            name, mod, state, region = "(unparsed)", "-", "unparsed", "-"
        if rip_count == 1:
            function, module, rip_state, rip_region = name, mod, state, region
        if name not in rip_functions:
            rip_functions.append(name)

    comm = "-"
    dumps = 0
    for text in texts:
        match = COMM.search(text)
        if match:
            dumps += 1
            if comm == "-":
                comm = match.group(1)

    panic_reason = "-"
    panic_lines = 0
    for text in texts:
        match = PANIC_START.search(text)
        if match:
            panic_lines += 1
            if panic_reason == "-":
                panic_reason = (match.group(1) or "").strip() or "(none given)"
    if panic_reason == "-":
        for text in texts:
            match = PANIC_END.search(text)
            if match:
                panic_reason = (match.group(1) or "").strip() or "(none given)"
                break

    tagged = []
    for text in texts:
        match = FRAME.match(text)
        if match and match.group(3) == "mxfs":
            tagged.append((match.group(2), bool(match.group(1))))

    dies = []
    for text in texts:
        for counter in DIE_COUNTER.findall(text):
            dies.append(int(counter))
    other_header = "-"
    for text in texts:
        match = OTHER_HEADER.search(text)
        if match:
            other_header = match.group(1)
            break
    pf_access = "-"
    for text in texts:
        match = PF_ACCESS.search(text)
        if match:
            pf_access = match.group(1) + " " + match.group(2)
            break
    fault_region = "-"
    for trigger in triggers:
        if any(primary for name, primary in trigger.kinds):
            match = FAULT_ADDRESS.search(segment.rows[trigger.pos].text)
            if match:
                fault_region = region_of(int(match.group(1), 16))
            break

    vm_check = "ok"
    if dies.count(1) >= 2 or panic_lines >= 2:
        vm_check = "multi-vm-suspected"

    rip_value = None
    for text in texts:
        if "RIP: 0010:" in text and not RIP_SYMBOL.search(text):
            raw = RIP_RAW.search(text)
            if raw:
                rip_value = int(raw.group(1), 16)
                break
    rip_low12 = "%03x" % (rip_value & 0xfff) if rip_value is not None else "-"
    modules_mxfs = "no-modules-line"
    for text in texts:
        listed = MODULES_LINE.search(text)
        if listed:
            named = MODULE_MXFS.search(listed.group(1))
            modules_mxfs = ("present" + (named.group(1) or "")) if named else "absent"
            break
    bare = []
    for text in texts:
        frame = BARE_FRAME.match(text)
        if not frame:
            continue
        value = int(frame.group(1), 16)
        if region_of(value) != "module-area":
            continue
        if rip_value is None:
            bare.append("low12=%03x" % (value & 0xfff))
        else:
            bare.append("%+d" % (value - rip_value))
        if len(bare) == BARE_FRAMES_KEPT:
            break
    trace_names = []
    for text in texts:
        frame = FRAME.match(text)
        if frame and frame.group(2) not in trace_names:
            trace_names.append(frame.group(2))
        if len(trace_names) == TRACE_NAMES_KEPT:
            break
    return OrderedDict([
        ("segment_marker", segment.marker),
        ("uptime_s", str(int(first.uptime)) if first.uptime is not None else "-"),
        ("kind", kind),
        ("function", function),
        ("module", module),
        ("comm", comm),
        ("panic_reason", panic_reason),
        ("deliberate", "yes" if any("sysrq" in text for text in texts) else "no"),
        ("mxfs_in_trace", "yes" if tagged else "no"),
        ("mxfs_first3", ",".join(first_names(tagged, True)) or "-"),
        ("mxfs_first3_reliable", ",".join(first_names(tagged, False)) or "-"),
        ("segment_index", str(segment.index)),
        ("first_file_line", str(first_row.number)),
        ("lines_in_event", str(len(members))),
        ("rip_state", rip_state),
        ("rip_region", rip_region),
        ("fault_region", fault_region),
        ("pf_access", pf_access),
        ("other_header", other_header),
        ("dumps", str(dumps)),
        ("die_counters", ",".join(str(number) for number in sorted(set(dies))) or "-"),
        ("panic_lines", str(panic_lines)),
        ("rip_functions", ",".join(rip_functions) or "-"),
        ("kinds_seen", ",".join(kinds_seen)),
        ("window", "%d.%d" % (segment.index, window_id)),
        ("vms_in_window", str(parts)),
        ("vm_check", vm_check),
        ("rip_low12", rip_low12),
        ("modules_mxfs", modules_mxfs),
        ("bare_frames", ",".join(bare) or "-"),
        ("trace_names", ",".join(trace_names) or "-"),
        ("ci_sysrq", "yes" if any("sysrq" in text.lower() for text in texts) else "no"),
    ])


def events_of_segment(segment):
    """Every crash event of one segment, plus bookkeeping for the summary."""
    triggers = find_triggers(segment)
    windows, unclocked = literal_windows(triggers)
    events = []
    member_numbers = set()
    dropped_streams = 0
    split_windows = []
    for window_id, window in enumerate(windows, start=1):
        low = max(0, window.first_pos - GUARD_BEFORE)
        high = min(len(segment.rows) - 1, window.last_pos + GUARD_AFTER)
        members = [(pos, segment.rows[pos]) for pos in range(low, high + 1)
                   if segment.rows[pos].uptime is not None
                   and abs(segment.rows[pos].uptime - window.first_uptime) <= WINDOW_SECONDS]
        streams = deal_streams(members)
        trigger_by_pos = {trigger.pos: trigger for trigger in window.triggers}
        kept = []
        for stream in streams:
            held = [trigger_by_pos[pos] for pos, row in stream["members"] if pos in trigger_by_pos]
            if held:
                kept.append((stream, held))
            else:
                dropped_streams += 1
        if len(kept) > 1:
            split_windows.append((segment.marker, window_id, len(kept)))
        for stream, held in kept:
            events.append(describe(segment, window_id, len(kept), stream["members"], held))
            for pos, row in stream["members"]:
                member_numbers.add(row.number)
    for trigger in unclocked:
        row = segment.rows[trigger.pos]
        events.append(describe(segment, 0, 1, [(trigger.pos, row)], [trigger]))
        member_numbers.add(row.number)
    return events, {
        "windows": len(windows),
        "unclocked": len(unclocked),
        "dropped_streams": dropped_streams,
        "split_windows": split_windows,
        "member_numbers": member_numbers,
    }


def hex_masked(text):
    return HEX_VALUE.sub("<hex>", text)


def clean(value):
    return str(value).replace("\t", " ").replace("\n", " ")


def clock(marker):
    return marker[11:] if marker and len(marker) > 11 else str(marker)


def main(argv):
    if len(argv) < 3:
        sys.stderr.write("usage: netconsole_crash_table.py LOG OUT [YYYY-MM-DD]\n")
        return 2
    log_path, out_path = argv[1], argv[2]
    date = argv[3] if len(argv) > 3 else DEFAULT_DATE
    try:
        with open(log_path, "rb") as handle:
            raw = handle.read()
    except OSError as error:
        sys.stderr.write("cannot read %s: %s\n" % (log_path, error))
        return 1
    text = raw.decode("utf-8", errors="replace")
    segments, stats = split_segments(text)

    older = []
    newer = []
    target = []
    unparsed = []
    for segment in segments[1:]:
        match = ISO_DATE.match(segment.marker or "")
        if not match:
            unparsed.append(segment)
        elif match.group(1) < date:
            older.append(segment)
        elif match.group(1) > date:
            newer.append(segment)
        else:
            target.append(segment)

    events = []
    per_segment = OrderedDict()
    windows_total = 0
    unclocked_total = 0
    dropped_total = 0
    split_windows = []
    member_numbers = set()
    for segment in target:
        found, book = events_of_segment(segment)
        per_segment[segment.index] = len(found)
        events.extend(found)
        windows_total += book["windows"] + book["unclocked"]
        unclocked_total += book["unclocked"]
        dropped_total += book["dropped_streams"]
        split_windows.extend(book["split_windows"])
        member_numbers |= book["member_numbers"]

    groups = OrderedDict()
    for event in events:
        key = (event["kind"], event["function"], event["module"], hex_masked(event["panic_reason"]),
               event["deliberate"], event["mxfs_in_trace"])
        groups.setdefault(key, []).append(event["segment_marker"])

    def rows_in(segments_list):
        return sum(len(segment.rows) for segment in segments_list)

    target_rows = [row for segment in target for row in segment.rows]
    orphans = Counter()
    for row in target_rows:
        if row.number in member_numbers:
            continue
        for label, needle in (("call-trace header", "Call Trace:"), ("CPU/Comm header", "Comm:"),
                              ("RIP line", "RIP: 0010:"), ("panic line", "Kernel panic - not syncing")):
            if needle in row.text:
                orphans[label] += 1
    unlisted = Counter()
    for row in target_rows:
        if "WARNING: CPU:" in row.text:
            unlisted["kernel WARN splat rows (WARNING: CPU:)"] += 1
        elif "WARNING:" in row.text:
            unlisted["rows containing WARNING: without the CPU: splat form"] += 1
        if re.search(r"rcu: INFO: rcu_(?!sched)", row.text):
            unlisted["rcu stall rows of a flavour other than rcu_sched"] += 1
        if "BUG:" in row.text and not trigger_kinds(row.text):
            unlisted["BUG: rows outside the trigger list"] += 1
        if "soft lockup" in row.text and "watchdog: BUG: soft lockup" not in row.text:
            unlisted["soft lockup rows without the watchdog prefix"] += 1
    unclocked_rows = [row for row in target_rows if row.uptime is None]
    exit_notices = sum(1 for row in unclocked_rows if LISTENER_EXIT.match(row.text))
    multi_stamp = sum(1 for row in target_rows if len(UPTIME_ANY.findall(row.text)) > 1)
    first_oops = 0
    later_oops = 0
    for row in target_rows:
        for counter in DIE_COUNTER.findall(row.text):
            if int(counter) == 1:
                first_oops += 1
            else:
                later_oops += 1
    sysrq_target = sum(1 for row in target_rows if "sysrq" in row.text)
    sysrq_target_ci = sum(1 for row in target_rows if "sysrq" in row.text.lower())
    sysrq_file = sum(1 for line in text.split("\n") if "sysrq" in line.lower())
    ci_differs = sum(1 for event in events if event["ci_sysrq"] != event["deliberate"])

    deliberate = sum(1 for event in events if event["deliberate"] == "yes")
    summary = []

    def add(*fields):
        summary.append("\t".join(clean(item) for item in fields))
    summary.append("# SUMMARY")
    add("input", log_path)
    add("input_bytes", len(raw))
    add("input_lines", stats["lines"])
    add("bytes_not_utf8", text.count("�"))
    add("carriage_returns", raw.count(b"\r"))
    add("markers", stats["markers"])
    add("markers_glued_to_partial_line", stats["markers_glued_to_text"])
    add("segments_total", len(segments))
    add("segment0_no_marker_lines", len(segments[0].rows))
    add("target_date_utc", date)
    add("segments_analysed", len(target), "lines", rows_in(target))
    add("segments_skipped_older", len(older), "lines", rows_in(older))
    add("segments_skipped_newer", len(newer), "lines", rows_in(newer))
    add("segments_skipped_unparsable_marker", len(unparsed), "lines", rows_in(unparsed))
    add("events_plain_3s_rule", windows_total)
    add("events_after_vm_split", len(events))
    add("windows_split_into_several_vms", len(split_windows))
    add("events_deliberate", deliberate)
    add("events_not_deliberate", len(events) - deliberate)
    add("window_streams_dropped_no_trigger", dropped_total)
    add("cross_check_first_oops_headers_in_analysed_segments", first_oops)
    add("cross_check_later_oops_headers_in_analysed_segments", later_oops)
    summary.append("# GROUPS")
    add("kind", "function", "module", "panic_reason(hex masked)", "deliberate", "mxfs_in_trace", "count", "segments")
    for key, markers in groups.items():
        counts = Counter(markers)
        listed = ", ".join(marker if counts[marker] == 1 else "%s x%d" % (marker, counts[marker])
                           for marker in OrderedDict.fromkeys(markers))
        add(*(list(key) + [len(markers), listed]))
    summary.append("# WINDOWS SPLIT BY VM (marker, window, vms)")
    for marker, window_id, count in split_windows:
        add(marker, window_id, count)
    summary.append("# NOT CLASSIFIED OR NOT COVERED (counts within the analysed segments)")
    add("rows_without_uptime", len(unclocked_rows), "of which listener exit notices", exit_notices)
    add("rows_with_several_uptimes", multi_stamp)
    add("trigger_rows_without_uptime", unclocked_total)
    add("events_kind_panic_only", sum(1 for event in events if event["kind"] == "panic-only"))
    add("events_kind_oops_unclassified", sum(1 for event in events if event["kind"] == "oops-unclassified"))
    add("events_rip_raw_address_no_symbol", sum(1 for event in events if event["rip_state"] == "raw-address"))
    add("events_rip_absent", sum(1 for event in events if event["rip_state"] == "absent"))
    add("events_rip_unparsed", sum(1 for event in events if event["rip_state"] == "unparsed"))
    add("events_with_unlisted_header_phrase", sum(1 for event in events if event["other_header"] != "-"),
        ",".join(sorted(set(event["other_header"] for event in events if event["other_header"] != "-"))))
    add("events_without_panic_line", sum(1 for event in events if event["panic_lines"] == "0"))
    add("events_vm_check_multi_vm_suspected", sum(1 for event in events if event["vm_check"] != "ok"))
    add("events_where_case_insensitive_sysrq_differs", ci_differs)
    add("rows_with_sysrq_case_sensitive_in_analysed_segments", sysrq_target)
    add("rows_with_sysrq_any_case_in_analysed_segments", sysrq_target_ci)
    add("lines_with_sysrq_any_case_whole_file", sysrq_file)
    for label in ("call-trace header", "CPU/Comm header", "RIP line", "panic line"):
        add("rows_outside_every_event: " + label, orphans[label])
    for label, count in sorted(unlisted.items()):
        add("rows_not_in_trigger_list: " + label, count)
    summary.append("# SEGMENTS ANALYSED (marker, lines, events)")
    for segment in target:
        add(segment.marker, len(segment.rows), per_segment[segment.index])

    with open(out_path, "w", encoding="utf-8") as out:
        out.write("\t".join(COLUMNS) + "\n")
        for event in events:
            out.write("\t".join(clean(event[name]) for name in COLUMNS) + "\n")
        out.write("\n")
        for line in summary:
            out.write(line + "\n")
    for line in summary:
        print(line)
    return 0


sys.exit(main(sys.argv))
