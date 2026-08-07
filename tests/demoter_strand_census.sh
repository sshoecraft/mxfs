#!/bin/bash
# demoter_strand_census.sh — cluster-wide census of the demoter-claim strand.
# (ccloop c7ee71c6 sess29, D-MOUNT-DEGRADES-WITH-USE.)
#
# WHAT IT COUNTS, AND WHY EACH COLUMN EXISTS
#   bail   P34J-RELOAD-DEMOTE-BAIL.  A reload abandoned because some other task
#          holds a demoter claim.  1-3 per node is the HEALTHY shape (a live
#          release drain, ~150 ms, that clears itself).  Hundreds on ONE node is
#          the defect: a claim nothing will ever clear, so every reload of that
#          inode pays mxfs.reload_demote_wait_ms and bails.
#   strand P214-DEMOTER-STRANDED.  The claim was still held after
#          mxfs.demoter_strand_ms (default 5000).  Emitted ONCE per inode and
#          NOT ratelimited, so it survives the bail flood it causes.  This is
#          the line that names the leaking site — read `slot=`, `line=`, `comm=`.
#   punt   P152-TRANSDRAIN-PUNT.  The trans-free drain handed a release to the
#          dwork instead of running it inline, retaining its claim across the
#          committing task's post-commit iunlock.  sess29 stamps that retention
#          (i_dlm_demoter_punt) so mxfs_demoter_punt_reclaim_check can end it.
#   recl   P213-PUNT-RECLAIM.  A retained claim actually released by the fix.
#
#   MEASURED CONTRADICTION this census exists to prevent repeating: sess28
#   attributed the strand to the punt because the bail printed
#   demoter_line=34955, whose only unpaired exit is the punt.  This census then
#   showed test23 with 224 bails and punt=0, while three nodes that DID punt had
#   0-1 bails.  The bail was printing slot 1's stale stamps while the strand was
#   in a slot it had no forensics for.  Always read `strand`, never infer the
#   site from `bail`.
#
# WINDOW SCOPING IS MANDATORY FOR AN A/B
#   dmesg is cumulative, so an unscoped census reports the SAME totals for both
#   arms of an A/B and silently proves nothing.  (Measured: control and fix arms
#   both reported bail=25 strand=1 punt=5 because the ring still held the
#   control arm's lines.)  `mark` stamps MXFS_DEMOTER_WINDOW on every node and
#   the census then counts only what follows the LAST such marker.
#
# USAGE
#   tests/demoter_strand_census.sh [nodes] mark          # stamp the window
#   tests/demoter_strand_census.sh [nodes]               # census (scoped if marked)
#   tests/demoter_strand_census.sh [nodes] full          # + the P214 lines
#
# Per-node timeout is 30 s: this is a dmesg grep, and a node that cannot answer
# one in 30 s is itself the finding.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO"

N="${1:-32}"
MODE="${2:-brief}"
D=$(mktemp -d)

if [ "$MODE" = mark ]; then
    for ((i = 1; i <= N; i++)); do
        timeout 20 tools/mxfs_sshpass.sh "test$i" \
            "echo 'MXFS_DEMOTER_WINDOW mark' > /dev/kmsg" >/dev/null 2>&1 &
    done
    wait
    echo "--- MXFS_DEMOTER_WINDOW stamped on $N node(s) ---"
    exit 0
fi

for ((i = 1; i <= N; i++)); do
    (
        # Scope to everything after the LAST window marker; with no marker the
        # whole ring is used, which is correct for a one-shot look but must
        # never be used to compare two arms.
        timeout 30 tools/mxfs_sshpass.sh "test$i" '
            w=$(mktemp)
            dmesg | awk "/MXFS_DEMOTER_WINDOW/{m=NR} {l[NR]=\$0}
                         END{ if (m) for(i=m+1;i<=NR;i++) print l[i]; else for(i=1;i<=NR;i++) print l[i] }" > "$w"
            b=$(grep -c "P34J-RELOAD-DEMOTE-BAIL" "$w")
            s=$(grep -c "P214-DEMOTER-STRANDED" "$w")
            p=$(grep -c "P152-TRANSDRAIN-PUNT" "$w")
            r=$(grep -c "P213-PUNT-RECLAIM" "$w")
            inos=$(grep "P34J-RELOAD-DEMOTE-BAIL" "$w" |
                   grep -oE "ino=[0-9]+" | sort -u | wc -l)
            echo "$b $s $p $r $inos"
            rm -f "$w"
        ' 2>/dev/null | grep -E "^[0-9]+ " | tail -1 > "$D/test$i"
        if [ "$MODE" = full ]; then
            timeout 30 tools/mxfs_sshpass.sh "test$i" '
                dmesg | awk "/MXFS_DEMOTER_WINDOW/{m=NR} {l[NR]=\$0}
                             END{ if (m) for(i=m+1;i<=NR;i++) print l[i]; else for(i=1;i<=NR;i++) print l[i] }" |
                grep "P214-DEMOTER-STRANDED"' 2>/dev/null \
                | grep P214 > "$D/test$i.strand"
        fi
    ) >/dev/null 2>&1 &
done
wait

printf '%-8s %6s %6s %6s %6s %6s\n' node bail strand punt recl inos
tb=0; ts=0; tp=0; tr=0
for ((i = 1; i <= N; i++)); do
    out=$(cat "$D/test$i" 2>/dev/null)
    [ -n "$out" ] || out="- - - - -"
    # shellcheck disable=SC2086
    set -- $out
    [ "$1" = "-" ] || { tb=$((tb + $1)); ts=$((ts + $2)); tp=$((tp + $3)); tr=$((tr + $4)); }
    # Only print rows that carry a signal; an all-zero node is the healthy case.
    [ "$1" = "0" ] && [ "$2" = "0" ] && [ "$3" = "0" ] && [ "$4" = "0" ] && continue
    printf '%-8s %6s %6s %6s %6s %6s\n' "test$i" "$1" "$2" "$3" "$4" "$5"
done
printf '%-8s %6d %6d %6d %6d\n' TOTAL "$tb" "$ts" "$tp" "$tr"

if [ "$MODE" = full ]; then
    echo
    echo "=== P214-DEMOTER-STRANDED lines + their claim rings (the site of the leak) ==="
    cat "$D"/*.strand 2>/dev/null | sed 's/^.*mxfs: */  /' | sort -u

    # The defer balance is the discriminator between "the drain never ran for
    # this entry" and "an unbalanced nested SET".  Triggering demoter_dump makes
    # the module print it; read it back from the ring on the same node.
    echo
    echo "=== P215-DEFER balance + P216 claim recycle (balance MUST be 0, init_inherit MUST be 0) ==="
    for ((i = 1; i <= N; i++)); do
        (
            timeout 30 tools/mxfs_sshpass.sh "test$i" \
                'echo 1 > /sys/module/mxfs/parameters/demoter_dump 2>/dev/null
                 sleep 1
                 dmesg | grep -E "P215-DEFER|P216-CLAIM-RECYCLE" | tail -2' \
                2>/dev/null | grep -E "P215-DEFER|P216-CLAIM-RECYCLE" > "$D/test$i.bal"
        ) >/dev/null 2>&1 &
    done
    wait
    for ((i = 1; i <= N; i++)); do
        b=$(sed 's/^.*mxfs: //' "$D/test$i.bal" 2>/dev/null | tr '\n' ' ')
        case "$b" in
            "") ;;                                               # no answer
            *"init_inherit=0 free_dirty=0"*balance=0*) ;;        # fully healthy
            *balance=0*init_inherit=0\ free_dirty=0*) ;;         # same, other order
            *) printf '  %-8s %s\n' "test$i" "$b" ;;
        esac
    done
    echo "  (only nodes with balance != 0 or a nonzero recycle counter are listed)"
fi

echo
echo "READ IT LIKE THIS:"
echo "  bail 1-3 per node  = healthy (a live drain, self-clearing)."
echo "  bail in the 100s on one node with strand>0 = the defect; read the P214 line."
echo "  strand=0 with bail high = the claim cleared within demoter_strand_ms after all."
echo "  punt>0 recl=0 is fine: a retained claim is only reclaimed once needed."
