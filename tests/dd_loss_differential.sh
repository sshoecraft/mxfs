#!/bin/bash
# dd_loss_differential.sh — find the UNPROBED producer of D-SILENT-MKDIR-LOSS
# by differencing kernel-probe frequencies between the losing node and its
# healthy peers, instead of testing one marker hypothesis at a time.
#
# WHY THIS EXISTS
#   By sess26 every documented marker in the loss chain had been measured to
#   zero in a window where 8 dirents were durably lost (test19, 32/caw):
#     P32E-DIREPOCH-FENCE 0, P195 0, P188 0, P177 0, P146V 0, P51 0, P65 0,
#     P194 0, P34J-RELOAD-DEMOTE-BAIL 0.
#   All 11 were confirmed present in the built module first, so those zeros are
#   real. Race bails resolve 623/623 and never overlap the P6 mid-tenure skip.
#   So the producer has NO probe. Nominating the next marker by intuition has
#   failed across five sessions; this lets the data nominate it.
#
#   Method: loop dirent_durability until it FAILS, then for every node harvest
#   the window-scoped kernel log and count each distinct `mxfs: <TOKEN>`.
#   Report tokens whose frequency on the losing node departs from the peer
#   distribution. A token that only the losing node emits, or emits at a wildly
#   different rate, is the lead.
#
# HARVEST SOURCE: whichever of `dmesg` / `journalctl -k` actually still contains
# the window marker, chosen PER NODE and reported as win_src.
#
# Neither source is reliably longer. Retention varies ~60x ACROSS NODES because
# both are ring/size-capped and nodes log at wildly different rates. Measured on
# one build, minutes apart:
#     test19: dmesg 1824 lines / 112 s   journalctl -k 59067 lines / ~50 min
#     test5:  dmesg 95460 lines / 1407 s journalctl -k 73686 lines
# i.e. dmesg was 30x SHORTER than journalctl on one node and LONGER on another.
# A `dirent_durability` run is 116-124 s, so on a heavy-logging node the dmesg
# window is shorter than the run being measured -- but hardcoding journalctl
# instead loses data on quiet nodes. Pick per node, and say which was used.
#
# Usage: tests/dd_loss_differential.sh [iters] [n_nodes]

set -u
cd "$(dirname "$0")/.." || exit 1
ITERS="${1:-8}"
N="${2:-32}"
SSH=tools/mxfs_sshpass.sh
OUT=$(mktemp -d)
echo "=== dd_loss_differential: up to $ITERS iters @ ${N}/caw — artifacts in $OUT ==="

# An outer `timeout` killing this script must not leave its ./run.sh child
# holding /tmp/mxfs_run.lock -- that orphan blocks every later run, and a
# blocked run emits no verdict line, which once made three iterations look
# like non-failures.  Kill the whole process group's run.sh on the way out.
cleanup() {
    # NEVER `pgrep -f` (see tools/mxfs_pgrep.sh header — clyde 2026-08-04 wedge).
    tools/mxfs_pgrep.sh '^/bin/bash \./run\.sh' | while read -r pp; do kill "$pp" 2>/dev/null; done
    sleep 2
    # Killing run.sh is NOT enough: its sshpass/mxfs_sshpass children inherited
    # fd 9 and keep the flock alive, so the lock reads HELD with no run.sh in
    # the process table.  Release it by killing whoever still holds the fd.
    for pp in $(fuser /tmp/mxfs_run.lock 2>/dev/null); do
        kill -9 "$pp" 2>/dev/null
    done
}
trap cleanup EXIT TERM INT

# Scoped token census for one node: everything after the LAST
# MXFS_DIRENT_WINDOW marker, reduced to `PROBE-TOKEN count`.
#
# Also saves the FULL scoped text alongside it.  Counts alone are not enough:
# the census read P6-MIDTENURE-RELOAD-SKIP=661 on a losing node, and by the time
# a follow-up query ran, the NEXT iteration had stamped a new
# MXFS_DIRENT_WINDOW -- so re-scoping "the last window" then read a different
# run entirely (44, not 661).  Capture the evidence at failure time or lose it.
harvest() {
    local node="$1" dest="$2"
    timeout 120 "$SSH" "$node" "
        dmesg > /tmp/h_dm.txt 2>/dev/null
        journalctl -k --no-pager > /tmp/h_jk.txt 2>/dev/null
        # lines AFTER the last window marker in each source; 0 if no marker.
        for f in /tmp/h_dm.txt /tmp/h_jk.txt; do
            awk -v f=\$f '/MXFS_DIRENT_WINDOW/{n=NR} END{print f, (n?NR-n:0), (n?1:0)}' \$f
        done > /tmp/h_pick.txt
        BEST=\$(sort -k2,2nr /tmp/h_pick.txt | head -1 | awk '{print \$1}')
        HAVE=\$(sort -k2,2nr /tmp/h_pick.txt | head -1 | awk '{print \$3}')
        echo \"#win_src=\$BEST win_marker=\$HAVE \$(cat /tmp/h_pick.txt | tr '\n' ';')\"
        awk '/MXFS_DIRENT_WINDOW/{n=NR} {l[NR]=\$0} END{for(i=n+1;i<=NR;i++) print l[i]}' \$BEST
    " 2>/dev/null | grep -vE '^(Warning|If you)' > "${dest}.full"
    # Token census is derived LOCALLY from the .full capture above, so both
    # views come from the same scoped text and the same chosen source.  An
    # earlier cut re-queried the node with journalctl for the counts while the
    # .full used the best source -- two different windows in one "measurement".
    {
        grep -m1 '^#' "${dest}.full" 2>/dev/null || echo "#win_src=unknown"
        grep -oE 'mxfs: [A-Z][A-Za-z0-9]*(-[A-Za-z0-9]+)+' "${dest}.full" 2>/dev/null |
          sed 's/^mxfs: //' | sort | uniq -c | awk '{print $2, $1}'
    } > "$dest"
}

for it in $(seq 1 "$ITERS"); do
    echo "--- iter $it/$ITERS ---"
    run_out="$OUT/run$it.txt"
    timeout 400 ./run.sh "$N" caw dirent_durability > "$run_out" 2>&1
    verdict=$(grep -E '^[[:space:]]+(PASS|FAIL|BLOCK)[[:space:]]+dirent_durability' "$run_out" | tail -1)
    if [ -z "$verdict" ]; then
        # run.sh serialises on /tmp/mxfs_run.lock.  A blocked or aborted run
        # emits NO verdict line, and treating that as "no failure to inspect"
        # silently turns an un-run iteration into an apparent pass -- which is
        # how three iterations once reported nothing at all.  Abort loudly.
        echo "    NO VERDICT — run did not execute. First lines of its output:"
        sed -n '1,6p' "$run_out" | sed 's/^/      /'
        echo "    (if this says another run holds the lock, clear the stray run.sh first)"
        break
    fi
    echo "    $verdict"

    case "$verdict" in
        *FAIL*) ;;
        *) continue ;;
    esac

    # Name the losing node. run.sh reports at least one as first_fail[testN:...].
    bad=$(sed -n 's/.*first_fail\[\(test[0-9]\+\):.*/\1/p' "$run_out" | head -1)
    if [ -z "$bad" ]; then
        echo "    FAIL with no first_fail[] to attribute — keeping run log only"
        continue
    fi
    echo "    LOSING NODE: $bad — harvesting all $N nodes (scoped, best source per node)"
    if [ "$bad" = "test1" ]; then
        echo "    *** WARNING: the loser is test1 = RANK 1. A loser-vs-peers"
        echo "    *** differential is NOT VALID for rank 1: its coordinator role"
        echo "    *** alone puts it above EVERY peer by x20-x158 on P1-AGWAIT,"
        echo "    *** P128-INACT-DEFER, P-DIRFLUSH, P-BLOCK0-CONVGATE and"
        echo "    *** P-IGET-ENOENT on a PASSING run (measured, see"
        echo "    *** tests/rank1_straggler_probe.sh). Those rows are role noise,"
        echo "    *** not failure signal. Compare rank1-failing against"
        echo "    *** rank1-PASSING instead. Table below is printed for the record"
        echo "    *** only — do not read a mechanism out of it."
    fi

    for i in $(seq 1 "$N"); do harvest "test$i" "$OUT/tok.iter$it.test$i" & done
    wait

    python3 - "$OUT" "$it" "$bad" "$N" <<'PY'
import sys, os, statistics
out, it, bad, n = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])

def load(node):
    p = os.path.join(out, f"tok.iter{it}.{node}")
    d, meta = {}, ""
    if not os.path.exists(p):
        return d, "MISSING"
    for line in open(p):
        line = line.strip()
        if line.startswith("#"):
            meta = line; continue
        parts = line.split()
        if len(parts) == 2 and parts[1].isdigit():
            d[parts[0]] = int(parts[1])
    return d, meta

badd, badmeta = load(bad)
peers = {}
for i in range(1, n + 1):
    node = f"test{i}"
    if node == bad:
        continue
    d, _ = load(node)
    if d:
        peers[node] = d

print(f"\n=== DIFFERENTIAL iter {it}: {bad} (LOST) vs {len(peers)} peers ===")
print(f"    {bad} window: {badmeta}")
if not peers:
    print("    no peer data — cannot difference"); sys.exit(0)

tokens = set(badd) | {t for d in peers.values() for t in d}
rows = []
for t in sorted(tokens):
    b = badd.get(t, 0)
    vals = [d.get(t, 0) for d in peers.values()]
    med = statistics.median(vals)
    npeers_with = sum(1 for v in vals if v > 0)
    # Interesting = only the loser has it, only the loser lacks it, or a big
    # rate departure from the peer median.
    only_bad = b > 0 and npeers_with == 0
    only_peers = b == 0 and npeers_with >= max(2, len(peers) // 2)
    ratio = (b + 1) / (med + 1)
    if only_bad or only_peers or ratio >= 3 or ratio <= 1 / 3:
        rows.append((t, b, med, min(vals), max(vals), npeers_with,
                     "ONLY-LOSER" if only_bad else
                     "ONLY-PEERS" if only_peers else
                     f"x{ratio:.1f}"))
if not rows:
    print("    no token departs from the peer distribution.")
    print("    => the losing node is probe-indistinguishable from healthy peers;")
    print("       the producer emits NO probe at all on the path that loses.")
else:
    print(f"    {'TOKEN':<40} {'loser':>6} {'peer_med':>9} {'min':>5} {'max':>5} {'npeers':>6}  flag")
    for t, b, med, mn, mx, npw, flag in rows:
        print(f"    {t:<40} {b:>6} {med:>9} {mn:>5} {mx:>5} {npw:>6}  {flag}")
print(f"\n    raw token censuses: {out}/tok.iter{it}.*")
PY
    # STOP on the first captured failure.  Continuing runs dirent_durability
    # again, stamps a new MXFS_DIRENT_WINDOW, and makes every later
    # "scope to the last window" query read the wrong run.
    echo "    STOPPING after first captured failure — the losing window is now"
    echo "    the LAST one on every node, so follow-up queries scope to it."
    echo "    artifacts: $OUT"
    exit 10
done

echo "=== done. artifacts: $OUT ==="
