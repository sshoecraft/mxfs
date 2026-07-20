#!/bin/bash
# harvest_dblreclaim.sh — aggregate P-DBLRECLAIM / pag_ici_lock stuck-holder /
# soft-lockup evidence across test1..testN (ccloop 703f15c3 sess1).
#
# Chasing: XFS_ALL_IRECLAIM_FLAGS double-set assert in xfs_inode_mark_reclaimable
# (xfs_icache.c) immediately preceding a permanent multi-CPU soft lockup, first
# seen at fence_during_write@8/caw (after a dir_reuse_coherency warmup in the
# same cluster session).  assfail() is non-fatal by default (bug_on_assert=0),
# so execution continues past the assert into a second synchronous-inactivation
# pass — the leading hypothesis.
#
# Markers:
#   P-DBLRECLAIM       xfs_inode_mark_reclaimable saw XFS_ALL_IRECLAIM_FLAGS
#                       already set (ino/pid/comm/flags logged) — CRITICAL,
#                       dumped verbatim.
#   P25-INSTR           MXFS synchronous inactivation entry/exit
#                       ("sync-inactive" / "sync-inactive-DONE").  Fires on
#                       EVERY unlinked-inode reclaim (thousands/run even when
#                       healthy) so it is NOT dumped verbatim — instead
#                       paired per-ino locally: any ino whose sync-inactive
#                       has no matching -DONE by harvest time is a DANGLING
#                       call (the actual hang site); any ino with a second
#                       sync-inactive before its first -DONE is a genuine
#                       DOUBLE-ENTRY (overlapping re-entrancy, the smoking
#                       gun for the double-reclaim hypothesis).
#   P-ICI-STUCK         a waiter has been spinning >5s for pag_ici_lock, with
#                       the stamped holder's pid/comm/hold-time (new this
#                       session — 19 acquire sites now stamp, was 6/19) —
#                       CRITICAL, dumped verbatim.
#   EVICT-RING-*        cross-node forced-eviction signals (DIR_MODIFY /
#                       INODE_FREE) — routine (thousands/run), counted only.
#   soft lockup / Call Trace / Assertion failed / BUG:  raw kernel distress —
#                       CRITICAL, dumped verbatim.
#
# A node that's actually wedged (soft lockup holding a spinlock cluster-wide)
# may still answer ssh (only specific kworkers/tasks are stuck, not
# necessarily the whole box) but dmesg reads can themselves hang if they
# contend the same lock — hence the per-node timeout + backgrounded fan-out.
#
# Usage: harvest_dblreclaim.sh <N> [since-UTC "YYYY-MM-DD HH:MM:SS"]
set -u
N="${1:?usage: harvest_dblreclaim.sh <N> [since-utc]}"
SINCE="${2:-}"
REPO=/src/mxfs
SSH="$REPO/tools/mxfs_sshpass.sh"; PF=/tmp/.mxfs_pass

CRITICAL='P-DBLRECLAIM|P-ICI-STUCK|soft lockup|hard lockup|Call Trace|Assertion failed|BUG:|INFO: task .* blocked'
NOISY='EVICT-RING-DIRMOD|EVICT-RING-FLAG'

tmpd=$(mktemp -d)
for r in $(seq 1 "$N"); do
    (
        if [ -n "$SINCE" ]; then
            SRC="journalctl -k --since '$SINCE' --no-pager 2>/dev/null"
        else
            SRC="dmesg"
        fi
        timeout 20 "$SSH" "test$r" "$PF" \
            "$SRC | grep -E '(${CRITICAL})'" \
            2>/dev/null > "$tmpd/$r.log"
        rc=$?
        [ "$rc" -gt 1 ] && echo "UNREACHABLE-OR-TIMEOUT rc=$rc" > "$tmpd/$r.unreach"
        timeout 20 "$SSH" "test$r" "$PF" \
            "$SRC | grep -cE '(${NOISY})'" \
            2>/dev/null > "$tmpd/$r.noisy"
        timeout 20 "$SSH" "test$r" "$PF" \
            "$SRC | grep -E 'P25-INSTR'" \
            2>/dev/null > "$tmpd/$r.p25"
        # Live D-state / stuck-task snapshot, best-effort, short timeout.
        timeout 10 "$SSH" "test$r" "$PF" \
            "ps -eo pid,stat,wchan:32,etimes,comm | awk '\$2 ~ /D/'" \
            2>/dev/null > "$tmpd/$r.dstate"
    ) &
done
wait

total_hits=0
noisy_total=0
for r in $(seq 1 "$N"); do
    lines=$(wc -l < "$tmpd/$r.log" 2>/dev/null || echo 0)
    noisy=$(cat "$tmpd/$r.noisy" 2>/dev/null || echo 0)
    noisy_total=$((noisy_total + noisy))
    unreach=""
    [ -s "$tmpd/$r.unreach" ] && unreach=" [$(cat "$tmpd/$r.unreach")]"
    dstate_n=$(wc -l < "$tmpd/$r.dstate" 2>/dev/null || echo 0)
    if [ "$lines" -gt 0 ] || [ "$dstate_n" -gt 0 ] || [ -n "$unreach" ]; then
        echo "=== test$r: ${lines} CRITICAL line(s), ${noisy} routine evict-ring, ${dstate_n} D-state task(s)${unreach} ==="
        [ "$lines" -gt 0 ] && sed 's/^/  /' "$tmpd/$r.log"
        if [ "$dstate_n" -gt 0 ]; then
            echo "  --- D-state tasks ---"
            sed 's/^/  /' "$tmpd/$r.dstate"
        fi
        total_hits=$((total_hits + lines))
    fi
done
echo
echo "=== total CRITICAL hits across $N node(s): $total_hits (routine evict-ring traffic: $noisy_total, not shown) ==="
[ "$total_hits" -eq 0 ] && echo "(clean — no P-DBLRECLAIM/P-ICI-STUCK/lockup evidence found)"

echo
echo "=== P25-INSTR sync-inactive pairing analysis (per node, file order = chronological) ==="
python3 - "$N" "$tmpd" <<'PYEOF'
import sys, re

n = int(sys.argv[1])
tmpd = sys.argv[2]
start_re = re.compile(r'sync-inactive ino=(0x[0-9a-fA-F]+)')
done_re = re.compile(r'sync-inactive-DONE ino=(0x[0-9a-fA-F]+)')

any_issue = False
total_pairs = 0
for r in range(1, n + 1):
    path = f"{tmpd}/{r}.p25"
    try:
        lines = open(path).read().splitlines()
    except FileNotFoundError:
        continue
    open_count = {}   # ino -> count of starts not yet matched by a DONE
    dangling = {}      # ino -> count still open at EOF
    double_entry = []  # (ino, line) where a 2nd start arrived before the 1st DONE
    pairs = 0
    for line in lines:
        m = done_re.search(line)
        if m:
            ino = m.group(1)
            if open_count.get(ino, 0) > 0:
                open_count[ino] -= 1
                pairs += 1
            continue
        m = start_re.search(line)
        if m:
            ino = m.group(1)
            open_count[ino] = open_count.get(ino, 0) + 1
            if open_count[ino] >= 2:
                double_entry.append((ino, line.strip()))
    dangling = {ino: c for ino, c in open_count.items() if c > 0}
    total_pairs += pairs
    if dangling or double_entry:
        any_issue = True
        print(f"test{r}: {pairs} clean pairs, {len(dangling)} DANGLING ino(s), {len(double_entry)} DOUBLE-ENTRY event(s)")
        for ino, c in list(dangling.items())[:10]:
            print(f"    DANGLING ino={ino} unmatched_starts={c} -- sync-inactive fired but no -DONE ever seen (stuck call site)")
        for ino, line in double_entry[:10]:
            print(f"    DOUBLE-ENTRY ino={ino}: {line}")
    elif pairs > 0:
        print(f"test{r}: {pairs} clean pairs, 0 issues")

if not any_issue:
    print(f"(clean across all nodes — {total_pairs} total sync-inactive/-DONE pairs, every one matched, no overlaps)")
PYEOF

rm -rf "$tmpd"
