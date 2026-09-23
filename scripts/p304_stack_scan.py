#!/usr/bin/env python3
"""Scan gzipped kernel logs for P304-IOCNT-UNTOKENED probe lines.

Two jobs:
  extract <file>  -- emit a compact, line-numbered stream of P304 lines and
                     stack-trace-shaped lines for that file (cheap per-file pass).
  report          -- read all extract streams from stdin-named files and produce
                     (1) distinct stack traces, (2) ops/comm tally.
"""
import sys, gzip, re, os, collections

MARKERS = ("Call Trace", "<TASK>", "dump_stack")
P304 = "P304-IOCNT-UNTOKENED"

def extract(path):
    out = []
    try:
        fh = gzip.open(path, "rt", errors="replace") if path.endswith(".gz") \
             else open(path, "rt", errors="replace")
    except OSError as e:
        sys.stderr.write("OPENFAIL %s %s\n" % (path, e))
        return
    with fh:
        for n, line in enumerate(fh, 1):
            if (P304 in line or "+0x" in line or "Workqueue:" in line
                    or "CPU: " in line or any(m in line for m in MARKERS)):
                out.append("%d\t%s" % (n, line.rstrip("\n")))
    sys.stdout.write("\n".join(out) + ("\n" if out else ""))

FUNC = re.compile(r"([A-Za-z_][A-Za-z0-9_.]*)\+0x")
OPSCOMM = re.compile(r"(ops=\S+)\s+(comm=\S+)")

def norm_comm(c):
    v = c[len("comm="):]
    if v.startswith("kworker"):
        return "kworker"
    return v

def report(listfile):
    files = [l.strip() for l in open(listfile) if l.strip()]
    tally = collections.Counter()
    total_p304 = 0
    traces = []           # (sig, path, p304line, tracelines)
    ntrace_raw = 0
    sigs_all = set()
    for path in files:
        ext = os.path.join(os.environ["P304_OUTDIR"], path.replace("/", "%") + ".p304")
        if not os.path.exists(ext):
            continue
        rows = []
        with open(ext, "rt", errors="replace") as fh:
            for l in fh:
                num, _, txt = l.rstrip("\n").partition("\t")
                try:
                    rows.append((int(num), txt))
                except ValueError:
                    pass
        for i, (num, txt) in enumerate(rows):
            if P304 not in txt:
                continue
            total_p304 += 1
            m = OPSCOMM.search(txt)
            if m:
                tally["%s %s" % (m.group(1), norm_comm(m.group(2)))] += 1
            else:
                tally["<no ops/comm> " + txt[:60]] += 1
            # look ahead for a stack marker within 60 SOURCE lines
            j = i + 1
            hit = None
            while j < len(rows) and rows[j][0] - num <= 60:
                if any(mk in rows[j][1] for mk in MARKERS):
                    hit = j
                    break
                j += 1
            if hit is None:
                continue
            ntrace_raw += 1
            # collect trace body: from the P304 line forward while lines stay
            # contiguous-ish (within 120 source lines of the marker)
            body = []
            k = hit
            base = rows[hit][0]
            while k < len(rows) and rows[k][0] - base <= 120:
                t = rows[k][1]
                if P304 in t or "mxfs: P" in t:
                    break
                if ("+0x" in t or "Workqueue:" in t or "CPU: " in t
                        or any(mk in t for mk in MARKERS)):
                    body.append(t)
                k += 1
            # also pull a CPU:/Workqueue: line just before the marker if present
            pre = []
            k2 = hit - 1
            while k2 > i:
                t = rows[k2][1]
                if "Workqueue:" in t or "CPU: " in t:
                    pre.insert(0, t)
                k2 -= 1
            real = [b for b in body if " ? " not in b]
            sig = tuple(FUNC.findall(" ".join(real)))
            sigall = tuple(FUNC.findall(" ".join(body)))
            sigs_all.add(sigall)
            traces.append((sig, path, txt, pre + body))

    print("=== TOTAL P304 LINES: %d ===" % total_p304)
    print("=== TRACES FOUND (pre-dedup): %d ===" % ntrace_raw)
    seen = {}
    for sig, path, p304, body in traces:
        if sig and sig not in seen:
            seen[sig] = (path, p304, body)
    print("=== DISTINCT TRACES (strict, incl. '?' speculative frames): %d ===" % len(sigs_all))
    print("=== DISTINCT TRACES (real frames only, '?' lines ignored): %d ===" % len(seen))
    for idx, (sig, (path, p304, body)) in enumerate(list(seen.items())[:4], 1):
        print("\n--- TRACE %d  FILE: %s" % (idx, path))
        print("P304: " + p304[:200])
        for b in body:
            print("  " + b[:200])
    print("\n=== OPS/COMM TALLY (total %d) ===" % total_p304)
    for k, v in tally.most_common():
        print("%8d  %s" % (v, k))

if __name__ == "__main__":
    if sys.argv[1] == "extract":
        extract(sys.argv[2])
    else:
        report(sys.argv[2])
