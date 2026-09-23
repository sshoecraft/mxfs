#!/bin/bash
# guard_census — no single-node fast path may be added without being classified.
#
# WHY THIS IS A BOARD CRITERION AND NOT A CODE-REVIEW HABIT.
#
# `mxfs_v5_dlm_is_single_node()` answers "am I alone right now". Dozens of
# guards ask it when the question they need answered is whether anybody else
# can still hold — or have left behind — a view of the metadata in hand. Every
# guard of the first kind switches itself off at the instant a departed peer's
# residue is on the platter and nobody is left to publish or invalidate it.
#
# The class has been declared closed TWICE, each time by fixing one call site:
#
#   D-0904  a survivor's pending peer-invalidations dropped on a single-node
#           fast path. Fixed at one site, closed FIXED AND VERIFIED. The rest
#           were never swept.
#   D-0949  the guard that keeps a fully-free inode chunk instead of returning
#           its blocks to the AG free pool. Measured: 187 chunks deleted by a
#           sole survivor in ONE lap — and it had never printed a line in the
#           project's history, because its only probe sat inside a branch
#           requiring not-multi-node while itself requiring multi-node.
#
# Both closures were honest about the site they fixed and neither stopped the
# class regrowing, because nothing counted the others. This row counts them.
#
# WHAT PASSING MEANS, EXACTLY. Every guard in the tree appears in the reviewed
# inventory at tests/criteria/sole_survivor_sites.json. That is a much weaker
# claim than "every guard is safe" and must never be read as the stronger one:
# a guard in the inventory is not thereby correct, it is thereby KNOWN. What
# this row prevents is a NEW one appearing without anyone deciding whether the
# work it skips has consequences that outlive the membership change.
#
# WHAT FAILING MEANS. Someone added a single-node fast path, or an existing
# function grew one. Classify it — does the skipped work leave durable state, a
# cached obligation, or anything a future or rejoining peer can observe? — and
# only then re-run `tools/sole_survivor_audit.py --baseline`. Regenerating the
# baseline to clear the red is the same act as widening a timeout to make a
# test pass.
#
# The check FAILS CLOSED: a missing inventory, a missing tool or a missing
# python3 is a failure, not a pass. A gate that goes quiet when it cannot
# answer is the exact failure mode this whole defect class is made of.
#
# derived time budget: a static walk of ~465k lines of C, measured under one second
# on this host. The manifest budget is 20 s; anything near that is a finding.
SUITE_TEST_NAME=guard_census
NODES="${MXFS_NODES:-1}"
REPO="${MXFS_REPO:-/src/mxfs}"
AUDIT="$REPO/tools/sole_survivor_audit.py"
INV="$REPO/tests/criteria/sole_survivor_sites.json"

emit(){ echo "RESULT: $1 | test=$SUITE_TEST_NAME | nodes=$NODES | measured=$2 | reason=${3:-}"; }

command -v python3 >/dev/null 2>&1 || {
    emit FAIL "python3=missing" "the census cannot run, so it refuses"; exit 1; }
[ -f "$AUDIT" ] || {
    emit FAIL "audit=missing" "no $AUDIT — the census cannot run, so it refuses"; exit 1; }
[ -f "$INV" ] || {
    emit FAIL "inventory=missing" "no $INV — an absent inventory is not an empty one"; exit 1; }

out=$(python3 "$AUDIT" --root "$REPO" --check --inventory "$INV" 2>&1); rc=$?
total=$(printf '%s' "$out" | sed -n 's/^OK \([0-9]*\) guards.*/\1/p' | head -1)
newn=$(printf '%s\n' "$out" | grep -c '^NEW ')
grewn=$(printf '%s\n' "$out" | grep -c '^GREW ')

if [ "$rc" -eq 0 ]; then
    emit PASS "guards=${total:-?} new=0 grown=0"
else
    printf '%s\n' "$out" | grep -E '^(NEW|GREW) ' | head -10
    emit FAIL "new=$newn grown=$grewn" "a single-node fast path was added without being classified; classify it, then re-baseline"
fi
exit 0
