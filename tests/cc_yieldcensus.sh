#!/bin/bash
# cc_yieldcensus.sh — census the fair-handoff YIELD TICKET, cluster-wide.
#
# WHY (ccloop c7ee71c6 sess130, GPT RULE-5 closure requirement for
# D-32NODE-SHARED-DIR-CREATE-PACE): the sess126 root was not merely "grant
# waits are long" — it was that the cluster ran ON ITS SAFETY VALVE.  A PR
# requester that is COMPATIBLE with every current holder defers anyway on a
# foreign EX yield ticket (strict writer preference), dozing 250 ms at a time,
# while the EX waiter the ticket guards cannot be granted either.  Nothing
# breaks the cycle until the 5000 ms MXFS_CAW_YIELD_TIMEOUT_MS stale-ticket
# valve expires the ticket — and then it repeats.
#
# So "the mean grant wait fell" is NOT sufficient evidence that the pathology
# is gone.  The discriminator is the TICKET AGE DISTRIBUTION AT DEFER: if
# tickets are being retired by holders releasing, ages stay small; if they are
# being retired by the valve, ages pile up against 5000 ms.
#
# sess126 baseline (0.11.452, ino 128, n=1141 defers):
#     age_ms p50=2873  p90=4588  max=4994     <- pinned against the 5 s valve
#     P139-TAILCENSUS n=172, foreign_yt p50=15 and doze250 p50=15 in ALL 172
#     (15 x MXFS_CAW_DEFER_POLL_MS 250 = 3750 ms of pure dozing)
#
# PROBES (all UNCONDITIONAL — do NOT set mxfs.instr, and do NOT raise the
# console loglevel; see tests/quiet_console.sh for why that alone can fail a
# pace criterion):
#   P204-YT-DEFER    dlm_caw.c, first 200/module-load.  One line per deferral
#                    taken on a FOREIGN yield ticket, carrying age_ms and the
#                    slot's own waiter/holder masks.
#   P139-TAILCENSUS  dlm_caw.c, first 2000/module-load, emitted for any grant
#                    wait > 800 ms.  foreign_yt / doze250 / bit_lost split the
#                    tail between ticket deferral, poll dozing and queue-
#                    position loss.
#
# Both are capped PER MODULE LOAD, and run.sh's prep_cluster rmmods, so a prep
# resets them: mark, run ONE workload, report.
#
# usage:
#   cc_yieldcensus.sh mark   [N]     # kmsg boundary, console left quiet
#   cc_yieldcensus.sh report [N]     # harvest since the mark
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/..
cd "$REPO"
MODE="${1:-}"; N="${2:-32}"
# Any other harness's boundary works as the window start — set MXFS_YC_MARK to
# e.g. mxfs-GWMARK to reuse a mark already placed for cc_grantwait.
MARK="${MXFS_YC_MARK:-mxfs-YCMARK}"
# shellcheck source=quiet_console.sh
. "$REPO/tests/quiet_console.sh"

case "$MODE" in
mark)
    for i in $(seq 1 "$N"); do
        ( tools/mxfs_sshpass.sh "test$i" \
            "$QUIET_CONSOLE echo '$MARK begin' > /dev/kmsg" >/dev/null 2>&1 ) &
    done
    wait; echo "marked $N nodes (console left at kernel.printk='1 4 1 1')"
    ;;
report)
    OUT=$(mktemp -d)
    for i in $(seq 1 "$N"); do
        ( tools/mxfs_sshpass.sh "test$i" \
            "dmesg | awk '/$MARK begin/{f=1;next} f' | \
             grep -a 'P204-YT-DEFER\|P139-TAILCENSUS'" \
            2>/dev/null > "$OUT/test$i" ) &
    done
    wait
    OUT="$OUT" python3 - <<'PYEOF'
import os, re, collections, statistics
OUT = os.environ["OUT"]
FIELD = re.compile(r"(\w+)=(-?[0-9a-fx]+)")

def num(v):
    try:
        return int(v, 0) if v.startswith("0x") else int(v)
    except ValueError:
        try:
            return int(v, 16)
        except ValueError:
            return None

defers, tails = [], []
for name in sorted(os.listdir(OUT)):
    node = name
    for line in open(os.path.join(OUT, name), errors="replace"):
        if "P204-YT-DEFER" in line:
            d = {k: v for k, v in FIELD.findall(line)}
            d["node"] = node
            defers.append(d)
        elif "P139-TAILCENSUS" in line:
            d = {k: num(v) for k, v in FIELD.findall(line)}
            d["node"] = node
            tails.append(d)

def q(vals, p):
    if not vals:
        return 0
    s = sorted(vals)
    return s[min(len(s) - 1, int(round((len(s) - 1) * p)))]

def stat(label, vals, unit=""):
    if not vals:
        print("   %-14s (none)" % label); return
    print("   %-14s n=%-6d p50=%-8s p90=%-8s max=%-8s mean=%.1f%s"
          % (label, len(vals), q(vals, .50), q(vals, .90), max(vals),
             statistics.mean(vals), unit))

VALVE = 5000   # MXFS_CAW_YIELD_TIMEOUT_MS
print("## P204-YT-DEFER — deferrals taken on a FOREIGN yield ticket")
if not defers:
    print("   NONE cluster-wide.  No PR/compat requester deferred on a foreign")
    print("   EX ticket at all — the strict-writer-preference convoy did not form.")
else:
    ages = [int(d["age_ms"]) for d in defers if "age_ms" in d]
    nodes = len({d["node"] for d in defers})
    print("   defers=%d  nodes=%d  distinct inos=%d"
          % (len(defers), nodes, len({d.get("ino") for d in defers})))
    stat("age_ms", ages)
    near = [a for a in ages if a >= VALVE - 500]
    print("   AGES WITHIN 500ms OF THE %dms VALVE: %d of %d (%.1f%%)"
          % (VALVE, len(near), len(ages), 100.0 * len(near) / len(ages)))
    print("   -> a high share here means tickets are retired BY THE VALVE, i.e.")
    print("      the system is still running on its safety valve.")
    per = collections.Counter(d.get("ino") for d in defers)
    print("   top inos: " + "  ".join("ino=%s n=%d" % (i, n)
                                      for i, n in per.most_common(5)))

print()
print("## P139-TAILCENSUS — grant waits > 800 ms")
if not tails:
    print("   NONE cluster-wide.  No grant wait exceeded 800 ms.")
else:
    print("   tail_waits=%d  nodes=%d" % (len(tails), len({t["node"] for t in tails})))
    stat("elapsed_ms", [t["elapsed_ms"] for t in tails if t.get("elapsed_ms") is not None])
    stat("foreign_yt", [t["foreign_yt"] for t in tails if t.get("foreign_yt") is not None])
    stat("doze250", [t["doze250"] for t in tails if t.get("doze250") is not None])
    stat("bit_lost", [t["bit_lost"] for t in tails if t.get("bit_lost") is not None])
    per = collections.Counter(t.get("ino") for t in tails)
    print("   top inos: " + "  ".join("ino=%s n=%d" % (i, n)
                                      for i, n in per.most_common(5)))
PYEOF
    ;;
*)
    sed -n '2,40p' "$0"
    exit 1
    ;;
esac
