#!/bin/sh
# d529_whole_txn_verify.sh — D-FOREIGN-REPLAY-ATOMIC-SKIP-PER-BATCH-NOT-PER-TXN-529
#
# Verifies the sess412/413 whole-transaction verdict fix: untrusted-replay
# classification (ATOMIC-SKIP / ENFORCE-ADMIT / SBCLEAN / SNLOCAL) must be
# derived EXACTLY ONCE over a transaction's COMPLETE item queue, never per
# 100-item pass-2 batch.  Pre-fix signature (measured fln7/fln9 on 0.27.x):
# one 131-item churn txn logged P227-FR-ENFORCE-ADMIT twice — items=100 then
# items=31 — and a mixed-verdict txn would have PARTIALLY APPLIED (the tear).
#
# Two arms, both a churn false-death fence (fence_live_node.sh hbpause):
#   A regression — knob off.  fence_live_node must PASS end-to-end (fln9
#     equivalence), AND the classification sweep must show (1) at least one
#     txn classified with items>100 (the arm exercised the >1-batch case)
#     and (2) no split/mixed classification for any lsn.
#   B fault-injection — dbg_fr_taint_items_over=100 on every node (ledger
#     step 2): every untrusted txn over 100 items is forced to the refusal
#     arm as if a LATER-batch image were unauthorized.  fence_live_node's
#     own verdict is advisory here (a refused replay by design does not
#     release the slot); the arm's assertions are:
#       - P-DBG-FR-TAINT-INJECT fired with items>100
#       - NO lsn carries both an ADMIT and an INJECT/ATOMIC-SKIP verdict
#         (pre-fix: batch 1 ADMIT+applied, batch 2 SKIP = partial apply)
#       - no split signature, no BUG/Oops on any node
#     The knob is cleared afterwards.
#
# Usage: tests/d529_whole_txn_verify.sh [A|B|AB] [victim] [peer] [nodes]
# Env:   D529_OUT (evidence dir root, default tests/evidence/<ts>_d529)
set -u
ARMS=${1:-AB}; VICTIM=${2:-test20}; PEER=${3:-test1}; NODES=${4:-32}
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
TS=$(date -u +%Y%m%dT%H%M%SZ); T0=$(date +%s)
ROOT=${D529_OUT:-tests/evidence/${TS}_d529}
mkdir -p "$ROOT"
CLASS_RE='P227-FR-ENFORCE-ADMIT\|P227-FR-ATOMIC-SKIP\|P227-FR-SBCOUNTER-CLEANSKIP\|P227-SNLOCAL-ACCEPT\|P-DBG-FR-TAINT-INJECT'

# sweep classification lines from every survivor (per-node evidence files)
sweep_class() { # $1 = out dir
    d=$1
    for i in $(seq 1 "$NODES"); do
        [ "test$i" = "$VICTIM" ] && continue
        ( timeout 25 $SSH "test$i" "dmesg | grep -a '$CLASS_RE\|BUG:\|Oops'" \
            2>/dev/null | grep -av '^Unauthorized\|^Warning:\|^If you' \
            > "$d/class_test$i.txt"; echo $? > "$d/class_test$i.rc" ) &
    done
    wait
}

# analyze one arm's classification sweep; prints findings, returns nonzero on
# a D-529 violation.  Duplicate (lsn, verdict, items) triples are ALLOWED —
# the stabilization machinery may retry a whole replay attempt and reclassify
# every txn identically.  Flagged: same lsn with two different verdicts, or
# same lsn+verdict with two different item counts (the 100/31 batch split).
analyze() { # $1 = dir  $2 = arm
    python3 - "$1" "$2" <<'EOF'
import glob, re, sys
d, arm = sys.argv[1], sys.argv[2]
# the probe name sits in TRAILING parens on the ADMIT/SKIP/SBCLEAN/SNLOCAL
# lines and LEADS on the INJECT line — extract each field independently.
name_rx = re.compile(r'(P227-FR-ENFORCE-ADMIT|P227-FR-ATOMIC-SKIP|P227-FR-SBCOUNTER-CLEANSKIP|P227-SNLOCAL-ACCEPT|P-DBG-FR-TAINT-INJECT)')
lsn_rx = re.compile(r'lsn=(0x[0-9a-f]+)', re.I)
items_rx = re.compile(r'items=(\d+)')
seen = {}   # lsn -> set of (verdict, items)
inject_over = 0; admit_over = 0; bugs = 0; total = 0
for f in sorted(glob.glob(d + '/class_test*.txt')):
    for line in open(f, errors='replace'):
        if 'BUG:' in line or 'Oops' in line:
            bugs += 1; print('BUG LINE %s: %s' % (f, line.strip()[:200])); continue
        nm = name_rx.search(line); lm = lsn_rx.search(line); im = items_rx.search(line)
        if not (nm and lm and im): continue
        total += 1
        v, lsn, items = nm.group(1), lm.group(1), int(im.group(1))
        seen.setdefault(lsn, set()).add((v, items))
        if v == 'P-DBG-FR-TAINT-INJECT' and items > 100: inject_over += 1
        if v == 'P227-FR-ENFORCE-ADMIT' and items > 100: admit_over += 1
fail = 0
for lsn, s in seen.items():
    verdicts = {v for v, _ in s}
    if len(verdicts) > 1:
        # INJECT + ATOMIC-SKIP for one lsn is the injection's own pair
        # (the probe fires, then the refusal arm logs) — not a violation.
        if verdicts != {'P-DBG-FR-TAINT-INJECT', 'P227-FR-ATOMIC-SKIP'}:
            print('MIXED VERDICT lsn=%s: %s' % (lsn, sorted(s))); fail = 1
    for v in verdicts:
        items = {i for vv, i in s if vv == v}
        if len(items) > 1:
            print('SPLIT CLASSIFICATION lsn=%s verdict=%s items=%s (per-batch signature)' % (lsn, v, sorted(items))); fail = 1
print('arm %s: %d classification lines, %d distinct txns, admit>100=%d inject>100=%d bugs=%d' % (arm, total, len(seen), admit_over, admit_over if arm != 'B' else inject_over, bugs))
if bugs: fail = 1
if arm == 'A' and admit_over == 0:
    print('FAIL arm A: no txn classified with items>100 — the arm never exercised the multi-batch case D-529 is about'); fail = 1
if arm == 'B' and inject_over == 0:
    print('FAIL arm B: P-DBG-FR-TAINT-INJECT never fired with items>100 — the injection did not take'); fail = 1
sys.exit(fail)
EOF
}

set_knob() { # $1 = value
    tests/fleet_set_params.sh "dbg_fr_taint_items_over=$1" "$NODES" "$ROOT/knob_$1.txt" > /dev/null 2>&1
    rc=$?
    echo "knob dbg_fr_taint_items_over=$1 on $NODES nodes rc=$rc (SETFAIL=$(grep -c SETFAIL "$ROOT/knob_$1.txt" 2>/dev/null))"
    [ $rc = 0 ] && ! grep -q SETFAIL "$ROOT/knob_$1.txt"
}

overall=0
echo "=== d529_whole_txn_verify arms=$ARMS victim=$VICTIM peer=$PEER nodes=$NODES out=$ROOT $(date -u +%FT%TZ) ==="

case $ARMS in *A*)
    echo "--- ARM A (regression, knob off) ---"
    A=$ROOT/armA; mkdir -p "$A"
    FLN_OUT=$A/fln FLN_INJECT=hbpause tests/fence_live_node.sh d529a churn "$VICTIM" "$PEER" "$NODES" > "$A/fln.log" 2>&1
    arc=$?
    echo "fence_live_node rc=$arc  $(grep -a 'VERDICT' "$A/fln.log" | tail -1 | cut -c1-200)"
    [ $arc = 0 ] || { echo "FAIL arm A: fence_live_node regression arm failed (see $A/fln.log)"; overall=1; }
    sweep_class "$A"
    analyze "$A" A || overall=1
;; esac

case $ARMS in *B*)
    echo "--- ARM B (fault injection, dbg_fr_taint_items_over=100) ---"
    B=$ROOT/armB; mkdir -p "$B"
    # the knob must be set AFTER prep (prep power-cycles nodes / reloads the
    # module) — fence_live_node applies FLN_PARAMS after its prep step.
    FLN_OUT=$B/fln FLN_INJECT=hbpause \
      FLN_PARAMS="target_cache_protected=1 foreign_replay_token_enforce=1 dbg_fr_taint_items_over=100" \
      tests/fence_live_node.sh d529b churn "$VICTIM" "$PEER" "$NODES" > "$B/fln.log" 2>&1
    brc=$?
    echo "fence_live_node rc=$brc (advisory: a refused replay by design does not release the slot)  $(grep -a 'VERDICT' "$B/fln.log" | tail -1 | cut -c1-200)"
    sweep_class "$B"
    analyze "$B" B || overall=1
    # the victim must still have been contained (withdraw + stopped writing)
    grep -aq 'WITHDRAW seen' "$B/fln.log" || { echo "FAIL arm B: victim never withdrew (containment regression, independent of D-529)"; overall=1; }
    set_knob 0 || { echo "FAIL arm B: could not clear the injection knob"; overall=1; }
;; esac

if [ $overall = 0 ]; then echo "VERDICT PASS: whole-txn classification held (no split, no mixed verdict)"; else echo "VERDICT FAIL"; fi
echo "=== done total=$(( $(date +%s) - T0 ))s out=$ROOT ==="
exit $overall
