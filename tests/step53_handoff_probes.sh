#!/bin/bash
#
# tests/step53_handoff_probes.sh — collect the step-5.3 direct-handoff /
# adopt / AG-authority probes from every node and print a cluster tally.
#
# These are the probes that decide whether the sess107 ruling's producer half
# actually works on the rig (D-FOREIGN-REPLAY-UNGATED-IMAGES):
#
#   P6H-HANDOFF        releaser directly promoted a nominated waiter.  Since
#                      0.11.438 it MINTS the grantee's ex_grant_epoch, so
#                      gep= must be nonzero and must advance per resource.
#   P6H-ADOPT          grantee observed itself already granted (the adopt
#                      arm).  Since 0.11.439 it validates provenance and
#                      fills the grant result; st=1 is WRITE_EPOCH.
#   P6H-ADOPT-REFUSE   adopt refused for lack of provenance.  why=unminted on
#                      a uniform fleet means a mint site is still missing.
#   P242-GRANT-UNSET   structural invariant: rc==0 with an UNSET result.
#                      Must be silent.
#   P243-AGAUTH-UNBOUND a fresh AG EX acquire published no authority epoch
#                      (0.11.440).  Must be silent on CAW.
#   P241-AUTHTRY       the inode-authority install attempt census; its
#                      by_try histogram names the refusal class.
#
# Usage: tests/step53_handoff_probes.sh <nnodes> [outdir]
#
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
SSH="$REPO/tools/mxfs_sshpass.sh"
N="${1:?usage: step53_handoff_probes.sh <nnodes> [outdir]}"
OUT="${2:-$(mktemp -d)}"
mkdir -p "$OUT"

PAT='P6H-HANDOFF|P6H-ADOPT|P242-GRANT-UNSET|P243-AGAUTH-UNBOUND|P241-AUTHTRY'

echo "--- collecting from $N node(s) into $OUT ---"
for i in $(seq 1 "$N"); do
    (
        "$SSH" "test$i" "dmesg | grep -aE '$PAT'" 2>/dev/null > "$OUT/test$i.log"
    ) &
done
wait

echo
echo "=== per-node counts ==="
printf '%-8s %8s %8s %8s %8s %8s %8s\n' node HANDOFF ADOPT REFUSE UNSET AGUNBND AUTHTRY
for i in $(seq 1 "$N"); do
    f="$OUT/test$i.log"
    [ -s "$f" ] || { printf '%-8s %8s\n' "test$i" "(none)"; continue; }
    printf '%-8s %8d %8d %8d %8d %8d %8d\n' "test$i" \
        "$(grep -c 'P6H-HANDOFF' "$f")" \
        "$(grep -c 'P6H-ADOPT ' "$f")" \
        "$(grep -c 'P6H-ADOPT-REFUSE' "$f")" \
        "$(grep -c 'P242-GRANT-UNSET' "$f")" \
        "$(grep -c 'P243-AGAUTH-UNBOUND' "$f")" \
        "$(grep -c 'P241-AUTHTRY' "$f")"
done

echo
echo "=== cluster totals ==="
cat "$OUT"/test*.log > "$OUT/all.log" 2>/dev/null
for p in P6H-HANDOFF 'P6H-ADOPT ' P6H-ADOPT-REFUSE P242-GRANT-UNSET P243-AGAUTH-UNBOUND; do
    printf '%-24s %d\n' "$p" "$(grep -c "$p" "$OUT/all.log")"
done

# NOTE: do NOT extract with `grep -o 'PROBE[^\n]*'`.  Inside a bracket
# expression \n is literally backslash-or-n, so [^\n]* stops at the first
# letter 'n' — "P6H-HANDOFF ino=..." truncates to "P6H-HANDOFF i" and every
# downstream field lookup silently returns zero.  grep is line-oriented
# already; select the line, then pull the field with awk/sed.
field_hist() {  # <line-pattern> <field>
    grep -a -- "$1" "$OUT/all.log" |
        sed -n "s/.*\\b$2=\\([^ ]*\\).*/\\1/p" | sort | uniq -c | sort -rn
}

echo
echo "=== P6H-HANDOFF gep= distribution (0 = mint missing) ==="
field_hist 'P6H-HANDOFF' gep | head -12
echo "  handoff gep=0  : $(grep -a 'P6H-HANDOFF' "$OUT/all.log" | grep -c ' gep=0 ')"
echo "  handoff gep!=0 : $(grep -a 'P6H-HANDOFF' "$OUT/all.log" | grep -vc ' gep=0 ')"

echo
echo "=== P6H-ADOPT st= distribution (1 = WRITE_EPOCH proving) ==="
field_hist 'P6H-ADOPT ' st

echo
echo "=== P6H-ADOPT epoch advance (gep must be > reg_gep) ==="
grep -a 'P6H-ADOPT ' "$OUT/all.log" |
    sed -n 's/.* gep=\([0-9]*\) reg_gep=\([0-9]*\).*/\1 \2/p' |
    awk '{ if ($1 > $2) adv++; else if ($1 == $2) eq++; else lt++ }
         END { printf "  advanced=%d  equal=%d  regressed=%d\n",
               adv+0, eq+0, lt+0 }'

echo
echo "=== P6H-ADOPT-REFUSE why= distribution ==="
field_hist 'P6H-ADOPT-REFUSE' why

echo
echo "=== P241-AUTHTRY by_try histogram (last line per node) ==="
for i in $(seq 1 "$N"); do
    l="$(grep -a 'by_try' "$OUT/test$i.log" 2>/dev/null | tail -1)"
    [ -n "$l" ] && echo "test$i: ${l#*P241-AUTHTRY }"
done

echo
echo "raw logs: $OUT"
