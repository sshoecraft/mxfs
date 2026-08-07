#!/bin/bash
# cc_stackprof.sh — deploy/run/harvest the wall-clock kernel stack profiler
# (tests/mxfs_stackprof.py) across rig nodes.
#
# WHY (ccloop c7ee71c6 sess126): D-CRASH-CONSISTENCY-32-NOTERMINAL-354 and
# D-32NODE-SHARED-DIR-CREATE-PACE both come down to "~22 ms of cluster-wide
# wall per dirent-insert into a shared directory, and we do not know which
# wait that is".  sess125 refuted the dir-EX ping-pong mechanism from probe
# COUNTS.  Counts cannot answer it; this can — a task found blocked in
# stack S on f% of ticks spent f% of its wall in S.
#
# usage:
#   cc_stackprof.sh start   <dur_s> [N|csv]   # deploy + launch (returns at once)
#   cc_stackprof.sh harvest [N|csv]           # pull + print per-node histograms
#   cc_stackprof.sh agg     [N|csv]           # pull + print CLUSTER-WIDE rollup
#   cc_stackprof.sh stop    [N|csv]           # kill any running samplers
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/..
cd "$REPO"

MODE="${1:-}"; shift || true
REMOTE=/root/mxfs_stackprof.py
OUTF=/run/mxfs_stackprof.out
PIDF=/run/mxfs_stackprof.pid
# NOTE: never `pkill -f mxfs_stackprof.py` — the ssh `bash -c` line that
# launches the sampler CONTAINS that string, so pkill kills its own shell
# before the sampler ever starts (silent no-op; cost sess126 a cycle).
# Always kill via the pidfile.

hosts() {
    local spec="${1:-32}"
    case "$spec" in
        *,*) echo "$spec" | tr ',' '\n' ;;
        *[!0-9]*) echo "$spec" ;;
        *) seq 1 "$spec" | sed 's/^/test/' ;;
    esac
}

case "$MODE" in
start)
    DUR="${1:-90}"; SPEC="${2:-32}"
    for h in $(hosts "$SPEC"); do
        (
            tools/mxfs_sshpass.sh "$h" SCP tests/mxfs_stackprof.py "$REMOTE" >/dev/null 2>&1
            tools/mxfs_sshpass.sh "$h" \
                "[ -s $PIDF ] && kill \$(cat $PIDF) 2>/dev/null; \
                 nohup python3 $REMOTE $DUR $OUTF 20 >/dev/null 2>&1 < /dev/null & \
                 echo \$! > $PIDF; \
                 sleep 0.3; kill -0 \$(cat $PIDF) 2>/dev/null && echo '$h ARMED' || echo '$h FAILED'" \
                2>/dev/null
        ) &
    done
    wait
    ;;
stop)
    SPEC="${1:-32}"
    for h in $(hosts "$SPEC"); do
        ( tools/mxfs_sshpass.sh "$h" "[ -s $PIDF ] && kill \$(cat $PIDF); true" >/dev/null 2>&1 ) &
    done
    wait
    echo "stopped"
    ;;
harvest|agg)
    SPEC="${1:-32}"
    OUT=$(mktemp -d)
    for h in $(hosts "$SPEC"); do
        ( tools/mxfs_sshpass.sh "$h" "cat $OUTF 2>/dev/null" 2>/dev/null > "$OUT/$h" ) &
    done
    wait
    if [ "$MODE" = harvest ]; then
        for f in "$OUT"/*; do
            echo "======== $(basename "$f") ========"
            cat "$f"
        done
    else
        OUT="$OUT" python3 - <<'PYEOF'
import os, collections
OUT = os.environ["OUT"]
sections = {"TOP-WAIT": collections.Counter(),
            "SIGNATURE": collections.Counter(),
            "PER-COMM": collections.Counter(),
            "FOCUS": collections.Counter()}
nodes = 0; ticks = 0; samples = 0
focus_ticks = 0
for name in sorted(os.listdir(OUT)):
    body = open(os.path.join(OUT, name)).read()
    if not body.strip():
        continue
    nodes += 1
    cur = None
    for line in body.splitlines():
        if line.startswith("# mxfs_stackprof"):
            for tok in line.split():
                if tok.startswith("ticks="):   ticks   += int(tok.split("=")[1])
                if tok.startswith("samples="): samples += int(tok.split("=")[1])
            continue
        if line.startswith("## "):
            # sess127: "## FOCUS <syms> ticks=N of M (p%)" carries its own
            # tick occupancy in the header — the release-side wall share.
            if line.startswith("## FOCUS"):
                cur = "FOCUS"
                for tok in line.split():
                    if tok.startswith("ticks="):
                        focus_ticks += int(tok.split("=")[1])
                continue
            cur = line[3:].strip(); continue
        if cur and line.strip():
            n, k = line.strip().split(None, 1)
            sections[cur][k] += int(n)
print("CLUSTER ROLLUP: nodes=%d ticks=%d samples=%d" % (nodes, ticks, samples))
print("FOCUS (DLM release/holder side) blocked on %d of %d ticks = %.2f%%"
      % (focus_ticks, ticks, 100.0 * focus_ticks / max(ticks, 1)))
for sec in ("TOP-WAIT", "SIGNATURE", "PER-COMM", "FOCUS"):
    c = sections[sec]
    tot = sum(c.values()) or 1
    print("\n## %s   (total %d)" % (sec, tot))
    for k, v in c.most_common(25):
        print("  %6.2f%%  %8d  %s" % (100.0 * v / tot, v, k))
PYEOF
    fi
    ;;
*)
    sed -n '2,20p' "$0"
    exit 2
    ;;
esac
