#!/bin/bash
# drc_parse.sh — summarize a dir_reuse_coherency run's per-round result across
# all rounds and both nodes.  Run.sh copies each failing run's per-node logs to
# /tmp/run_dir_reuse_coherency_<RUN_ID>/test{1,2}; this parses the drc lines
# (readdir=N/EXP, lookup_fail=K) into a compact per-round table + a PASS/FAIL
# verdict, so a 24-round run is assessed at a glance instead of eyeballing tails.
#
# Usage: scripts/drc_parse.sh [RUN_LOG_DIR]   (default: newest run_dir_reuse_* )
set -u
DIR="${1:-$(ls -dt /tmp/run_dir_reuse_coherency_* 2>/dev/null | head -1)}"
[ -n "$DIR" ] && [ -d "$DIR" ] || { echo "no run log dir (arg or /tmp/run_dir_reuse_coherency_*)"; exit 1; }
echo "=== $DIR ==="
worst_rd=200; worst_lf=0; nbad=0
for f in "$DIR"/test*; do
    [ -f "$f" ] || continue
    node=$(basename "$f")
    echo "--- $node ---"
    # Each round logs (on shortfall) a 'drc round=R rank=.. readdir=N/EXP lookup_fail=K' line.
    # Rounds with no line PASSED both checks.
    grep -oE "drc round=[0-9]+ rank=[0-9]+ readdir=[0-9]+/[0-9]+ lookup_fail=[0-9]+" "$f" 2>/dev/null \
      | while read -r l; do echo "  $l"; done
    # Also surface any kernel-level shutdown / corruption the node hit.
    grep -oE "block_verify|EFSCORRUPTED|Internal error|rc=-110|shutdown" "$f" 2>/dev/null | sort | uniq -c | sed 's/^/  KERN: /'
    rline=$(grep -E '^RESULT:' "$f" 2>/dev/null | tail -1)
    echo "  ${rline:-RESULT: (none)}"
done
echo "=== verdict ==="
if grep -hqE "drc round=[0-9]+ rank=[0-9]+ readdir=[0-9]+/[0-9]+ lookup_fail=[0-9]+" "$DIR"/test* 2>/dev/null; then
    echo "FAIL — at least one round had a readdir shortfall or leaf-hash hole (lines above)"
else
    echo "no per-round failure lines found (either clean PASS or run aborted — check RESULT lines)"
fi
