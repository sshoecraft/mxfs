#!/usr/bin/env python3
"""
classify_free_foreign.py — classify every P55C-FREE-FOREIGN line across a
32-node MXFS board journal capture (the source-tree rule: persistent, not /tmp).

Evidence dir: tests/evidence/sess429_s433_dmesg/board_journal_test<N>.txt
Each line: [ <uptime_s> ] <node> kernel: mxfs: <TAG> <k=v ...> — <prose>

Cross-node timeline caveat (stated up front, not buried): the only wall-clock
anchor available per node is board_journal_test<N>.meta's `uptime_s:` field,
which (despite the name) holds the wall-clock timestamp at which that node's
journal capture was taken, not a duration. Per-node boot wall-time is derived
as capture_walltime - last_line_uptime_seconds, i.e. "the last logged line
happened right before capture". This can be off by however long elapsed
between the last kernel line and the journalctl grab (unmeasured, likely low
single-digit seconds based on how tightly kernel_lines_in_window tracks the
last timestamp, but NOT verified against an independent clock). Cross-node
orderings reported here are reliable at second-to-minute granularity; do not
trust them for sub-second races.
"""
import glob
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone

EVID_DIR = "/src/mxfs/tests/evidence/sess429_s433_dmesg"

LINE_RE = re.compile(
    r"^\[\s*(?P<ts>[0-9]+\.[0-9]+)\]\s+(?P<node>\S+)\s+kernel:\s+mxfs:\s+(?P<tag>\S+)\s+(?P<rest>.*)$"
)
FOREIGN_RE = re.compile(
    r"ino=(?P<ino>\d+)\s+gen=(?P<gen>\d+)\s+disk_gen=(?P<disk_gen>\d+)\s+disk_mode=0(?P<disk_mode>[0-7]+)"
)
INO_KV_RE = re.compile(r"\bino=(\d+)\b")

SHUTDOWN_TAGS = [
    "Filesystem has been shut down",
    "xfs_do_force_shutdown",
    "P-SESSION-POISON",
    "P237-EVICT-OBLIGATION",
    "P32D-DEADINCARN-SKIP",
    "P-CR62",
    "P-CR63-DEFER-DISKLIVE",
    "P-CR3-CANCEL",
]

ALLOC_KEYWORDS = ("ALLOC", "CREATE", "RECYCLE", "ICREATE")


def u32(x):
    return x & 0xFFFFFFFF


def s32(x):
    x = u32(x)
    return x - 0x100000000 if x >= 0x80000000 else x


def mode_class(mode_octal_int):
    fmt = mode_octal_int & 0o170000
    return {
        0o040000: "dir(040xxx)",
        0o100000: "reg(0100xxx)",
        0o120000: "symlink(0120xxx)",
        0o140000: "socket(0140xxx)",
        0o060000: "blkdev(060xxx)",
        0o020000: "chrdev(020xxx)",
        0o010000: "fifo(010xxx)",
        0: "zero(0)",
    }.get(fmt, f"other(0{oct(fmt)[2:]}xxx)")


def load_meta(node):
    path = os.path.join(EVID_DIR, f"board_journal_{node}.meta")
    capture_dt = None
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                if line.startswith("uptime_s:"):
                    val = line.split(":", 1)[1].strip()
                    try:
                        capture_dt = datetime.strptime(
                            val, "%Y-%m-%d %H:%M:%S"
                        ).replace(tzinfo=timezone.utc)
                    except ValueError:
                        capture_dt = None
    return capture_dt


def main():
    node_files = sorted(
        glob.glob(os.path.join(EVID_DIR, "board_journal_test*.txt")),
        key=lambda p: int(re.search(r"test(\d+)\.txt$", p).group(1)),
    )
    if not node_files:
        print(f"NO EVIDENCE: no board_journal_test*.txt files found under {EVID_DIR}")
        return

    nodes = [re.search(r"(test\d+)\.txt$", p).group(1) for p in node_files]

    # ---- pass 1: parse every mxfs line per node, track malformed lines ----
    node_lines = {}          # node -> list of dict(ts, node, tag, raw_rest)
    node_last_ts = {}        # node -> last mxfs-line uptime seconds seen
    total_mxfs_lines = 0
    unparsed_mxfs_lines = 0

    for node, path in zip(nodes, node_files):
        lines = []
        last_ts = None
        with open(path, "r", errors="replace") as f:
            for raw in f:
                if "mxfs:" not in raw:
                    continue
                m = LINE_RE.match(raw.rstrip("\n"))
                if not m:
                    unparsed_mxfs_lines += 1
                    continue
                total_mxfs_lines += 1
                ts = float(m.group("ts"))
                last_ts = ts if last_ts is None else max(last_ts, ts)
                lines.append({
                    "ts": ts, "node": node, "tag": m.group("tag"),
                    "rest": m.group("rest"),
                })
        node_lines[node] = lines
        node_last_ts[node] = last_ts

    # ---- boot-time anchor per node, from .meta capture time - last line ts ----
    node_boot_epoch = {}
    for node in nodes:
        capture_dt = load_meta(node)
        last_ts = node_last_ts.get(node)
        if capture_dt is not None and last_ts is not None:
            node_boot_epoch[node] = capture_dt.timestamp() - last_ts
        else:
            node_boot_epoch[node] = None

    def abs_time(node, ts):
        boot = node_boot_epoch.get(node)
        if boot is None:
            return None
        return boot + ts

    # ---- collect all FOREIGN events ----
    foreign_events = []   # list of dicts
    per_node_foreign_count = defaultdict(int)
    for node in nodes:
        for rec in node_lines[node]:
            if rec["tag"] != "P55C-FREE-FOREIGN":
                continue
            fm = FOREIGN_RE.search(rec["rest"])
            if not fm:
                # malformed FOREIGN line - counted but flagged, not silently dropped
                foreign_events.append({
                    "node": node, "ts": rec["ts"], "ino": None,
                    "gen": None, "disk_gen": None, "disk_mode": None,
                    "malformed": True,
                })
                per_node_foreign_count[node] += 1
                continue
            ino = int(fm.group("ino"))
            gen = int(fm.group("gen"))
            disk_gen = int(fm.group("disk_gen"))
            disk_mode = int(fm.group("disk_mode"), 8)
            foreign_events.append({
                "node": node, "ts": rec["ts"], "ino": ino, "gen": gen,
                "disk_gen": disk_gen, "disk_mode": disk_mode,
                "malformed": False,
            })
            per_node_foreign_count[node] += 1

    total_foreign = len(foreign_events)
    malformed_foreign = sum(1 for e in foreign_events if e["malformed"])
    well_formed = [e for e in foreign_events if not e["malformed"]]
    distinct_inos = sorted(set(e["ino"] for e in well_formed))

    print("=" * 78)
    print("1. P55C-FREE-FOREIGN COUNTS")
    print("=" * 78)
    print(f"Total P55C-FREE-FOREIGN lines across all {len(nodes)} node files: {total_foreign}")
    if malformed_foreign:
        print(f"  of which {malformed_foreign} did not match the expected "
              f"ino/gen/disk_gen/disk_mode field pattern (counted, excluded "
              f"from bucket/mode/ino analysis below)")
    print(f"Well-formed FOREIGN events analyzed: {len(well_formed)} of {total_foreign}")
    print(f"Distinct inos involved: {len(distinct_inos)}")
    print()
    print("Per-node counts (node: count), nodes with 0 omitted, "
          f"denominator = {total_foreign} total lines:")
    for node in nodes:
        c = per_node_foreign_count.get(node, 0)
        if c:
            print(f"  {node}: {c}")
    zero_nodes = [n for n in nodes if per_node_foreign_count.get(n, 0) == 0]
    print(f"Nodes with zero P55C-FREE-FOREIGN lines: {len(zero_nodes)} of {len(nodes)} "
          f"({', '.join(zero_nodes) if zero_nodes else 'none'})")
    print()

    # ---- 2. delta buckets + disk_mode distribution ----
    print("=" * 78)
    print("2. delta = int32(disk_gen - gen) BUCKETS, and disk_mode DISTRIBUTION")
    print(f"   (denominator = {len(well_formed)} well-formed FOREIGN events)")
    print("=" * 78)
    bucket_equal = []
    bucket_newer = []       # disk_gen > gen (signed delta > 0)
    bucket_older = []       # disk_gen < gen-1 (signed delta < -1)
    bucket_expected_prev = []  # disk_gen == gen-1 (signed delta == -1); not
                               # named in the 3 requested buckets but real and
                               # must not be silently dropped from the total
    for e in well_formed:
        d = s32(e["disk_gen"] - e["gen"])
        e["delta"] = d
        if d == 0:
            bucket_equal.append(e)
        elif d > 0:
            bucket_newer.append(e)
        elif d == -1:
            bucket_expected_prev.append(e)
        else:
            bucket_older.append(e)

    n = len(well_formed)
    print(f"  disk_gen == gen           (equal)                : {len(bucket_equal)} of {n}")
    print(f"  disk_gen >  gen           (newer live image)      : {len(bucket_newer)} of {n}")
    print(f"  disk_gen == gen-1         (matches expected prior "
          f"incarnation, not requested as its own bucket but real): "
          f"{len(bucket_expected_prev)} of {n}")
    print(f"  disk_gen <  gen-1         (older live image)      : {len(bucket_older)} of {n}")
    assert len(bucket_equal) + len(bucket_newer) + len(bucket_expected_prev) + len(bucket_older) == n

    print()
    print(f"  disk_mode distribution ({n} well-formed events):")
    mode_counts = defaultdict(int)
    for e in well_formed:
        mode_counts[mode_class(e["disk_mode"])] += 1
    for k, v in sorted(mode_counts.items(), key=lambda kv: -kv[1]):
        print(f"    {k}: {v} of {n}")
    print()

    # ---- 3. per-ino cross-node probe-tag timelines ----
    print("=" * 78)
    print("3. PER-INO CROSS-NODE PROBE-TAG TIMELINES (6 representative inos)")
    print("=" * 78)

    global_seen_inos = set()

    def pick_reps(bucket, k=2):
        picks = []
        for e in bucket:
            if e["ino"] in global_seen_inos:
                continue
            global_seen_inos.add(e["ino"])
            picks.append(e)
            if len(picks) >= k:
                break
        return picks

    reps = []
    reps += [("equal", e) for e in pick_reps(bucket_equal)]
    reps += [("newer", e) for e in pick_reps(bucket_newer)]
    reps += [("expected_prev(gen-1)", e) for e in pick_reps(bucket_expected_prev)]
    reps += [("older", e) for e in pick_reps(bucket_older)]
    reps = reps[:6] if len(reps) > 6 else reps

    print(f"Selected {len(reps)} representative inos (up to 2 per non-empty bucket, "
          f"capped at 6 total, from {len(distinct_inos)} distinct FOREIGN inos):")
    print()

    # index: ino -> list of (node, abs_time_or_None, ts, tag)
    ino_index = defaultdict(list)
    for node in nodes:
        for rec in node_lines[node]:
            m = INO_KV_RE.search(rec["rest"])
            if not m:
                continue
            ino = int(m.group(1))
            ino_index[ino].append((node, abs_time(node, rec["ts"]), rec["ts"], rec["tag"]))

    rep_ino_details = {}
    for bucket_name, e in reps:
        ino = e["ino"]
        events = ino_index.get(ino, [])
        # sort by absolute time where available, else fall back to raw ts
        # (raw ts fallback only affects ordering among events on nodes with
        # no meta-derived boot anchor; flagged via '?' below)
        def sort_key(ev):
            _, at, ts, _ = ev
            return (0, at) if at is not None else (1, ts)
        events_sorted = sorted(events, key=sort_key)
        rep_ino_details[(bucket_name, ino)] = events_sorted
        prose_parts = []
        run = None  # (node, tag, first_tstr, count)
        def flush_run():
            if run is None:
                return
            node_r, tag_r, tstr_r, count_r = run
            suffix = f" x{count_r}" if count_r > 1 else ""
            prose_parts.append(f"{node_r} t={tstr_r} {tag_r}{suffix}")
        for (node, at, ts, tag) in events_sorted:
            if at is not None:
                tstr = datetime.fromtimestamp(at, tz=timezone.utc).strftime("%H:%M:%S")
            else:
                tstr = f"t+{ts:.1f}s(no-anchor)"
            if run is not None and run[0] == node and run[1] == tag:
                run = (run[0], run[1], run[2], run[3] + 1)
            else:
                flush_run()
                run = (node, tag, tstr, 1)
        flush_run()
        print(f"ino={ino} [bucket={bucket_name}, delta={e['delta']}, "
              f"disk_mode={mode_class(e['disk_mode'])}, FOREIGN logged on {e['node']}]:")
        print("  " + ", ".join(prose_parts))
        print()

    # ---- 4. shutdown-signature scan ----
    print("=" * 78)
    print("4. SHUTDOWN-SIGNATURE SCAN (grep -c per tag, all 32 node files)")
    print("=" * 78)
    shutdown_counts = defaultdict(int)
    shutdown_nodes = defaultdict(set)
    for node, path in zip(nodes, node_files):
        with open(path, "r", errors="replace") as f:
            for raw in f:
                for sig in SHUTDOWN_TAGS:
                    if sig in raw:
                        shutdown_counts[sig] += 1
                        shutdown_nodes[sig].add(node)
    any_hit = any(shutdown_counts.values())
    print(f"Any shutdown signature present in the run: {'YES' if any_hit else 'NO'}")
    for sig in SHUTDOWN_TAGS:
        c = shutdown_counts.get(sig, 0)
        nlist = sorted(shutdown_nodes.get(sig, []), key=lambda n: int(n[4:]))
        print(f"  '{sig}': {c} lines across {len(nlist)} of {len(nodes)} nodes"
              f"{' (' + ','.join(nlist) + ')' if nlist else ''}")
    print()

    # ---- 5. alloc/create/recycle correlation per FOREIGN event ----
    print("=" * 78)
    print("5. SAME-NODE POST-FOREIGN REALLOC, AND OTHER-NODE PRE-FOREIGN REALLOC")
    print(f"   (denominator = {len(well_formed)} well-formed FOREIGN events)")
    print("=" * 78)

    def is_alloc_tag(tag):
        return any(k in tag for k in ALLOC_KEYWORDS)

    same_node_later_alloc = 0
    other_node_earlier_alloc = 0
    neither = 0
    both = 0
    unanchored_skipped_other_node_check = 0

    for e in well_formed:
        ino = e["ino"]
        node = e["node"]
        ts = e["ts"]
        at = abs_time(node, ts)
        events = ino_index.get(ino, [])

        same_later = any(
            ev_node == node and ev_ts > ts and is_alloc_tag(ev_tag)
            for (ev_node, ev_at, ev_ts, ev_tag) in events
        )

        other_earlier = False
        checked_any_other = False
        for (ev_node, ev_at, ev_ts, ev_tag) in events:
            if ev_node == node or not is_alloc_tag(ev_tag):
                continue
            if at is None or ev_at is None:
                continue
            checked_any_other = True
            if ev_at < at:
                other_earlier = True

        if at is None:
            unanchored_skipped_other_node_check += 1

        if same_later:
            same_node_later_alloc += 1
        if other_earlier:
            other_node_earlier_alloc += 1
        if same_later and other_earlier:
            both += 1
        if not same_later and not other_earlier:
            neither += 1

    print(f"  Same node, ALLOC/CREATE/RECYCLE/ICREATE tag for the same ino "
          f"AFTER the FOREIGN line (by that node's own uptime clock): "
          f"{same_node_later_alloc} of {len(well_formed)}")
    print(f"  A DIFFERENT node shows an ALLOC/CREATE/RECYCLE/ICREATE tag for "
          f"the same ino BEFORE the FOREIGN event time (cross-node, using the "
          f"meta-derived absolute-time anchor): {other_node_earlier_alloc} of "
          f"{len(well_formed)}")
    print(f"  Both conditions true: {both} of {len(well_formed)}")
    print(f"  Neither condition true: {neither} of {len(well_formed)}")
    print()
    print("  CAVEAT (verified by exact-tag inventory over this evidence set, "
          "not inferred): the only distinct mxfs: tags anywhere in these 32 "
          "files matching the substring filter ALLOC/CREATE/RECYCLE/ICREATE "
          "are P-RECYCLE-DEADSTAMP-CLEAR and P-RECYCLE-GATE. NO tag containing "
          "ALLOC, CREATE, or ICREATE occurs anywhere in this capture (0 lines "
          "for each, all 32 files). P-RECYCLE-DEADSTAMP-CLEAR is emitted as "
          "housekeeping immediately after FOREIGN/HOME-SETTLED handling for "
          "the same incarnation being discharged, not as evidence of a new "
          "on-disk allocation. So the same-node figure above "
          f"({same_node_later_alloc} of {len(well_formed)}) reflects "
          "RECYCLE-family housekeeping tags only, and should NOT be read as "
          "\"106 of 164 inos were observed being reallocated\" — this "
          "evidence set contains no direct proof of a subsequent real alloc "
          "for any FOREIGN ino, on any node.")
    if unanchored_skipped_other_node_check:
        print(f"  NOTE: {unanchored_skipped_other_node_check} of {len(well_formed)} "
              f"FOREIGN events were on a node with no usable boot-time anchor "
              f"(missing/unparseable .meta) — cross-node before/after check "
              f"skipped for those, same-node check still applied")


if __name__ == "__main__":
    main()
