#!/bin/bash
# cc_bastcensus.sh — the HOLDER side of an inode handoff, from always-on probes.
#
# WHY (ccloop c7ee71c6 sess127).  sess126 proved by wall-clock stack sampling
# that ~100% of the 32-node crash_consistency blocking wall is the CAW grant
# wait on the MOUNT ROOT (ino 128), and captured P204-YT-DEFER showing the
# holders_pr mask BIT-IDENTICAL for 3 s under a pending EX ticket with hex=0.
# That is the requester side.  It does not say WHY the seven PR holders never
# release.  Three mutually-exclusive causes, three different fixes:
#
#   STALLED   the BAST fires, the release pipeline starts, and it blocks
#             (drain / ilock / AIL) for seconds
#             -> fix is in the release path (read-side barrier, drain bound)
#   UNDELIVERED  the BAST never reaches the holder at all (not in the poll
#             batch, callback declined, work never queued)
#             -> fix is in BAST delivery, not in any lock policy
#   CHURN     the holder DOES release promptly and immediately re-acquires PR,
#             so the aggregate mask only LOOKS frozen
#             -> fix is admission: the re-acquire must respect the ticket
#
# Discriminators, all from probes that are unconditional (NOT instr-gated):
#   P70-BP ino=.. ENTRY   release pipeline entered (mode/state/held_ms/realns)
#   P70-BP ino=.. EXIT=full   pipeline finished (realns)  -> ENTRY..EXIT = wall
#   SESS50-STARVE ino=..  poll thread SEES an incompatible waiter while we hold
#   P132-ILOCK-STUCK      the release drain could not get i_lock for >5 s
#
#   many ENTRY, short ENTRY->EXIT, small held_ms   => CHURN
#   few  ENTRY, long  ENTRY->EXIT                  => STALLED
#   SESS50-STARVE present but no ENTRY             => UNDELIVERED
#
# usage:
#   cc_bastcensus.sh mark   [N]         # kmsg boundary on every node
#   cc_bastcensus.sh report [N] [INO]   # harvest since the mark (default 128)
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/..
cd "$REPO"
MODE="${1:-}"; N="${2:-32}"; INO="${3:-128}"
MARK="mxfs-BCMARK"
# `mark` must NOT raise the console loglevel — see tests/quiet_console.sh.
# shellcheck source=quiet_console.sh
. "$REPO/tests/quiet_console.sh"

case "$MODE" in
mark)
    for i in $(seq 1 "$N"); do
        ( tools/mxfs_sshpass.sh "test$i" \
            "$QUIET_CONSOLE echo '$MARK begin' > /dev/kmsg" \
            >/dev/null 2>&1 ) &
    done
    wait; echo "marked $N nodes"
    ;;
report)
    OUT=$(mktemp -d)
    for i in $(seq 1 "$N"); do
        ( tools/mxfs_sshpass.sh "test$i" \
            "dmesg | awk '/$MARK begin/{f=1;next} f' | \
             grep -a 'P70-BP\|SESS50-STARVE\|P132-ILOCK\|P36-STRIKEOUT'" \
            2>/dev/null > "$OUT/test$i" ) &
    done
    wait
    OUT="$OUT" INO="$INO" python3 - <<'PYEOF'
import os, re, collections, statistics
OUT = os.environ["OUT"]; INO = int(os.environ["INO"])
FIELD = re.compile(r"(\w+)=(-?\d+)")

entries = collections.defaultdict(list)   # node -> [dict]
exits   = collections.defaultdict(list)
starve  = collections.Counter()
ilock   = collections.Counter()
strike  = collections.Counter()
allino_entry = collections.Counter()

def fields(line, tag):
    return dict((k, int(v)) for k, v in FIELD.findall(line.split(tag, 1)[1]))

for name in sorted(os.listdir(OUT), key=lambda s: int(s[4:])):
    for line in open(os.path.join(OUT, name)):
        if "P70-BP" in line and "ENTRY" in line:
            d = fields(line, "P70-BP")
            allino_entry[d.get("ino", -1)] += 1
            if d.get("ino") == INO:
                entries[name].append(d)
        elif "P70-BP" in line and "EXIT=full" in line:
            d = fields(line, "P70-BP")
            if d.get("ino") == INO:
                exits[name].append(d)
        elif "SESS50-STARVE" in line:
            d = fields(line, "SESS50-STARVE")
            if d.get("ino") == INO:
                starve[name] += 1
        elif "P132-ILOCK" in line:
            ilock[name] += 1
        elif "P36-STRIKEOUT" in line:
            strike[name] += 1

print("## ALL-INODE P70-BP ENTRY counts (top 10) — where release work happens")
for ino, c in allino_entry.most_common(10):
    print("   ino=%-12d entries=%d" % (ino, c))

ne = sum(len(v) for v in entries.values())
nx = sum(len(v) for v in exits.values())
print("\n## ino=%d  P70-BP ENTRY=%d  EXIT=full=%d  nodes_with_entry=%d"
      % (INO, ne, nx, len(entries)))
if not ne:
    print("   NO release pipeline ever entered for this inode.")
    print("   SESS50-STARVE(ino=%d) per node: %s" % (INO, dict(starve)))
    print("   => UNDELIVERED if starve>0, else this inode is simply not BAST'd.")
    raise SystemExit(0)

modes = collections.Counter()
held  = []
for node, rows in entries.items():
    for d in rows:
        modes[d.get("mode", -1)] += 1
        held.append(d.get("held_ms", 0))

def pct(v, p):
    if not v: return 0
    s = sorted(v); return s[min(len(s) - 1, int(len(s) * p / 100.0))]

print("   ENTRY mode histogram (3=PR 5=EX): %s" % dict(modes))
print("   held_ms at BAST entry: p50=%d p90=%d max=%d mean=%.1f"
      % (pct(held,50), pct(held,90), max(held), statistics.mean(held)))

# pair ENTRY -> next EXIT on the same node (bast work per inode is serialized)
durs = []
unpaired = 0
for node in entries:
    ee = sorted(entries[node], key=lambda d: d.get("realns", 0))
    xx = sorted(exits.get(node, []), key=lambda d: d.get("realns", 0))
    j = 0
    for e in ee:
        t0 = e.get("realns", 0)
        while j < len(xx) and xx[j].get("realns", 0) < t0:
            j += 1
        if j < len(xx):
            durs.append((xx[j]["realns"] - t0) / 1e6)
            j += 1
        else:
            unpaired += 1
if durs:
    print("\n   ENTRY->EXIT=full release wall ms  n=%d unpaired=%d" % (len(durs), unpaired))
    print("     p50=%.1f p90=%.1f p99=%.1f max=%.1f  sum=%.0f"
          % (pct(durs,50), pct(durs,90), pct(durs,99), max(durs), sum(durs)))
    slow = sum(1 for d in durs if d >= 250)
    print("     releases >=250ms: %d (%.1f%%)   >=1000ms: %d"
          % (slow, 100.0*slow/len(durs), sum(1 for d in durs if d >= 1000)))
else:
    print("\n   no ENTRY/EXIT pairs — %d entries never reached EXIT=full" % unpaired)

print("\n## per-node  entries / exits / SESS50-STARVE / P132-ILOCK / P36-STRIKEOUT")
for name in sorted(set(list(entries) + list(exits) + list(starve) + list(ilock)),
                   key=lambda s: int(s[4:])):
    print("   %-8s e=%-5d x=%-5d starve=%-5d ilock=%-3d strike=%d"
          % (name.replace("test","t"), len(entries.get(name,[])),
             len(exits.get(name,[])), starve[name], ilock[name], strike[name]))

print("\n## VERDICT INPUTS")
print("   entries/node mean = %.1f" % (ne / max(len(entries),1)))
print("   exits/entries     = %.2f" % (nx / max(ne,1)))
if durs:
    print("   median release    = %.1f ms" % pct(durs,50))
PYEOF
    ;;
*)
    sed -n '2,40p' "$0"; exit 2 ;;
esac
