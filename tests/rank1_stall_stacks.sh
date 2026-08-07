#!/bin/bash
# rank1_stall_stacks.sh — where does rank 1 spend the extra ~120 s when
# dirent_durability truncates at its 240 s budget?
#
# WHY A STACK SAMPLER AND NOT PROBE COUNTS
#   The rank1 240s truncation is a PACE failure, and every probe-count route to
#   it is confounded:
#     * loser-vs-peers is invalid because rank1's coordinator role alone puts it
#       above every peer by x20-x158 on a PASSING run
#       (tests/rank1_straggler_probe.sh);
#     * rank1-failing-vs-rank1-passing is invalid across differing module ages
#       because probe pr_warn counters are static atomic_t (per module load) and
#       CAPPED -- measured artifact: P170-CLWR 800 -> 0, its documented cap being
#       exactly 800.
#   Blocked-task stacks have neither problem: they are sampled state, not
#   cumulative counters, so they need no baseline and cannot saturate.
#
#   Reproduction shape (observed 3x): fresh prep, 1-2 passes at 116-124 s, then a
#   240s/240s truncation on test1 with 31 nodes reporting FAIL. So sample during
#   runs 2 and 3 after a prep.
#
# Usage: tests/rank1_stall_stacks.sh [n_nodes] [iters]
#   Samples test1 for the whole of each dirent_durability run and prints the
#   most frequent blocked stacks for the run that truncated.

set -u
cd "$(dirname "$0")/.." || exit 1
N="${1:-32}"
ITERS="${2:-3}"
SSH=tools/mxfs_sshpass.sh
OUT=$(mktemp -d)
echo "=== rank1_stall_stacks: ${ITERS} iters @ ${N}/caw — artifacts $OUT ==="

cleanup() {
    timeout 30 "$SSH" test1 "test -f /root/stallsample.pid && kill \$(cat /root/stallsample.pid) 2>/dev/null; true" >/dev/null 2>&1
    # NEVER `pgrep -f` (see tools/mxfs_pgrep.sh header — clyde 2026-08-04 wedge).
    tools/mxfs_pgrep.sh '^/bin/bash \./run\.sh' | while read -r pp; do kill "$pp" 2>/dev/null; done
    sleep 2
    for pp in $(fuser /tmp/mxfs_run.lock 2>/dev/null); do kill -9 "$pp" 2>/dev/null; done
}
trap cleanup EXIT TERM INT

start_sampler() {
    # The sampler script lives in tests/ and the node has /src NFS-mounted, so
    # it is launched by PATH -- not shipped through a heredoc inside an ssh
    # payload, which an earlier cut did and which silently never started.
    timeout 30 "$SSH" test1 "
        test -f /root/stallsample.pid && kill \$(cat /root/stallsample.pid) 2>/dev/null
        rm -f /root/stall.log
        test -x /src/mxfs/tests/mxfs_stallsample.sh || { echo NO_SCRIPT; exit 0; }
        setsid nohup /src/mxfs/tests/mxfs_stallsample.sh 3 > /root/stall.log 2>&1 < /dev/null &
        sleep 4
        test -s /root/stall.log && echo SAMPLER_UP || echo SAMPLER_EMPTY
    " 2>/dev/null | grep -c SAMPLER_UP
}

for it in $(seq 1 "$ITERS"); do
    echo "--- iter $it/$ITERS ---"
    up=$(start_sampler)
    [ "$up" -ge 1 ] || { echo "    sampler did not start"; continue; }
    timeout 400 ./run.sh "$N" caw dirent_durability > "$OUT/run$it.txt" 2>&1
    v=$(grep -E '^[[:space:]]+(PASS|FAIL|BLOCK)[[:space:]]+dirent_durability' "$OUT/run$it.txt" | tail -1)
    [ -z "$v" ] && { echo "    NO VERDICT — run did not execute"; sed -n '1,4p' "$OUT/run$it.txt" | sed 's/^/      /'; break; }
    echo "    $v"
    timeout 60 "$SSH" test1 "test -f /root/stallsample.pid && kill \$(cat /root/stallsample.pid) 2>/dev/null; cat /root/stall.log" 2>/dev/null \
        | grep -vE '^(Warning|If you)' > "$OUT/stall$it.log"
    echo "    sampled $(grep -c '^=== ' "$OUT/stall$it.log") snapshots, $(grep -c '^--- pid=' "$OUT/stall$it.log") D-state observations"

    case "$v" in
      *FAIL*|*BLOCK*)
        echo "    *** TRUNCATED RUN — top blocked stacks on rank1 ***"
        python3 - "$OUT/stall$it.log" <<'PY'
import sys, re, collections
txt = open(sys.argv[1], errors="replace").read()
blocks = re.split(r'^--- pid=', txt, flags=re.M)[1:]
sig = collections.Counter()
comm = collections.Counter()
for b in blocks:
    lines = b.splitlines()
    head = lines[0] if lines else ""
    c = head.split("comm=")[-1].strip() if "comm=" in head else "?"
    frames = [l.strip().split("+")[0].lstrip("[<] ?") for l in lines[1:]
              if l.strip().startswith(("[<", " ")) or "+0x" in l]
    frames = [f for f in frames if f and not f.startswith("===")]
    if not frames:
        continue
    comm[c] += 1
    sig[(c, " <- ".join(frames[:4]))] += 1
print(f"    D-state observations by task ({sum(comm.values())} total):")
for c, n in comm.most_common(8):
    print(f"      {n:>5}  {c}")
print("    top blocked stacks (task: innermost 4 frames):")
for (c, s), n in sig.most_common(8):
    print(f"      {n:>5}  {c}: {s}")
PY
        echo "    artifacts: $OUT"
        exit 10
        ;;
    esac
done
echo "=== done (no truncation captured). artifacts: $OUT ==="
