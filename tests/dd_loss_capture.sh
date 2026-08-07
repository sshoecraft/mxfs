#!/bin/bash
# dd_loss_capture.sh — catch a REAL silent-dirent-loss run and name its producer.
#
# WHY (ccloop c7ee71c6 sess23)
#   `dirent_durability` reproduced a genuine loss (durable_loss=3, mkdir_err=0)
#   in a window where `dirent_publish_integrity` counted
#   stale_base_mutations=0 — i.e. the loss happened WITHOUT P195, the marker
#   state.md calls "the DETERMINISTIC predicate" for this defect.  Window
#   mis-scoping is ruled out (dirent_durability stamps MXFS_DIRENT_WINDOW
#   BEFORE its workload, and the criterion scans from the last marker).
#
#   So either there is a SECOND producer, or P195 mis-models the mechanism.
#   This harness settles that by capturing, IN THE SAME SCOPED WINDOW as a
#   failing run, every marker that is known to be able to DROP a committed
#   dirent, per node:
#
#     P195  mutation on an epoch-stale base          (the assumed producer)
#     P188  grant handed off with an unlanded change (release-barrier half)
#     P189  RELOG refused: our core is behind disk   (drops the entry outright)
#     P146V incore/disk divergence at flush          (the unlanded witness)
#     P32E  dir-epoch fence skipped a flush          (silently discards it)
#     P177  publication obligation dropped at adopt
#     P34J  reload abandoned because a drain was active
#     P65   epoch conversion gate
#     P6    mid-tenure reload skipped
#
#   The loss reproduces roughly 1 run in 3 at 16 nodes, so this LOOPS until it
#   catches one (or hits the iteration cap) and prints a per-node marker table
#   for the failing run ONLY.  A passing run's counts are printed too, as the
#   control arm — the interesting result is which marker is present in the
#   FAILING window and absent (or much rarer) in the passing ones.
#
# USAGE: tests/dd_loss_capture.sh [max_iters] [nodes]
# EXIT:  0 = a failing run was captured (evidence in tests/logs/ddloss_*)
#        1 = no failure within max_iters (all runs passed — say so, do not
#            report that as "fixed")
#        2 = infrastructure failure
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd -- "$SCRIPT_DIR/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
ITERS="${1:-6}"
N="${2:-16}"

STAMP=$(date -u +%Y%m%d_%H%M%S)
OUT="$REPO/tests/logs/ddloss_$STAMP"
mkdir -p "$OUT"

MARKERS='P195-STALE-BASE-ALREADY-DIRTY|P188-REL-OBLIGATION-AT-UNLOCK|P189-RELOG-BEHIND-DISK|P146V-UNLANDED|P32E-DIREPOCH-FENCE|P177-OBLIGATION-DROPPED-AT-ADOPT|P34J|P65-EPOCH-CONVGATE|P6-MIDTENURE-RELOAD-SKIP'

# Harvest each node's marker counts, scoped to the LAST MXFS_DIRENT_WINDOW —
# the same scoping dirent_publish_integrity uses, so the numbers are directly
# comparable to that criterion's verdict.
harvest() {   # <label>
    local label="$1" i
    for i in $(seq 1 "$N"); do
        # Source choice is PER NODE.  Retention varies ~60x across nodes and
        # neither source is reliably longer -- measured minutes apart on one
        # build: test19 dmesg 1824 lines/112 s vs journalctl 59067; test5 dmesg
        # 95460 lines/1407 s vs journalctl 73686.  A dirent_durability run is
        # ~120 s, so on a heavy-logging node the dmesg window is shorter than
        # the run.  Take whichever source still has the most lines AFTER the
        # last window marker, and never concatenate them (the marker would be
        # found in one source and the tail taken from both).
        ( timeout 60 "$SSH" "test$i" "
            dmesg > /tmp/c_dm.txt 2>/dev/null
            journalctl -k --no-pager > /tmp/c_jk.txt 2>/dev/null
            for f in /tmp/c_dm.txt /tmp/c_jk.txt; do
                awk -v f=\$f '/MXFS_DIRENT_WINDOW/{n=NR} END{print f, (n?NR-n:0)}' \$f
            done | sort -k2,2nr | head -1 | awk '{print \$1}' > /tmp/c_best.txt
            B=\$(cat /tmp/c_best.txt)
            printf 'win_src=%s ' \"\$B\"
            awk '/MXFS_DIRENT_WINDOW/{seen=1; buf=\"\"; next} seen{buf=buf \$0 \"\\n\"} END{printf \"%s\", buf}' \$B \
              | grep -oE '$MARKERS' | sort | uniq -c | awk '{print \$2\"=\"\$1}' | tr '\n' ' '
            echo" > "$OUT/${label}.node$i" 2>/dev/null; true ) &
    done
    wait
}

report() {   # <label>
    local label="$1" i line
    echo "--- marker census ($label), scoped to the last MXFS_DIRENT_WINDOW ---"
    for i in $(seq 1 "$N"); do
        line=$(tr -d '\r' < "$OUT/${label}.node$i" 2>/dev/null | head -1)
        [ -n "${line// /}" ] && printf "    test%-3s %s\n" "$i" "$line"
    done
    echo "    (nodes with no markers in the window are omitted)"
}

echo "=== dd_loss_capture: up to $ITERS iterations at $N nodes — out=$OUT ==="

caught=0
for it in $(seq 1 "$ITERS"); do
    L="$OUT/run$it.log"
    timeout 400 "$REPO/run.sh" "$N" caw dirent_durability > "$L" 2>&1
    rc=$?
    verdict=$(grep -oE '(PASS|FAIL)  dirent_durability' "$L" | head -1 | awk '{print $1}')
    measured=$(grep -oE 'durable_loss=[0-9]+ late_ok=[0-9]+ mkdir_err=[0-9]+' "$L" | head -1)
    echo "iter $it: ${verdict:-NORESULT} $measured (rc=$rc)"

    if [ "$verdict" = "FAIL" ]; then
        caught=1
        harvest "fail$it"
        report  "fail$it"
        echo "--- DD-DURABLE-LOSS lines from the failing run ---"
        grep -hE 'DD-DURABLE-LOSS' "$L" | head -20 | sed 's/^/    /'
        for i in $(seq 1 "$N"); do
            ( timeout 60 "$SSH" "test$i" "echo ===DMESG===; dmesg; echo ===JOURNALCTL===; journalctl -k --no-pager" > "$OUT/dmesg_fail$it.node$i" 2>&1; true ) &
        done
        wait
        echo "    full dmesg harvested to $OUT"
        break
    fi
    # control arm: keep the LAST passing run's census for comparison
    harvest "pass$it"
done

if [ "$caught" = "1" ]; then
    echo "=== CAUGHT a failing run — compare its census above against the control arm below ==="
    for f in "$OUT"/pass*.node1; do
        [ -e "$f" ] || continue
        lbl=$(basename "$f" .node1)
        report "$lbl"
        break
    done
    echo "    evidence: $OUT"
    exit 0
fi

echo "=== NO failure in $ITERS iterations.  This is NOT evidence the defect is fixed"
echo "    (RULE 6: 'cannot reproduce' is not a disposition) — it reproduces ~1 run in 3-10."
echo "    evidence: $OUT"
exit 1
