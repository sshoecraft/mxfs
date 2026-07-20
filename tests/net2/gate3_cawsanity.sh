#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Gate 3 — NET2 §11 step 3 shared-code lift, CAW-neutrality sanity
# (DLM_IMPL_PLAN.md).  Step 3 moved resource_hash_raw/resource_equal
# (dlm.c) + lock_compat/is_compatible/recompute_granted_mode + the
# EX/PW popcount check (dlm_caw.c) into dlm/dlm_shared.c with
# identical bodies.  CAW behavior must be provably unchanged: proof =
# the two canary tests on a freshly-prepped 2-node CAW cluster running
# the lifted build (criteria-met protection, DLM_IMPL_PLAN "CAW-green
# protection").
#
# ── RULE-0 budget (written BEFORE first run) ──
#   infra    = run.sh 2/caw prep with up to 30 running extra nodes to
#              tear down (parallel, ~100 s worst) + participant clean +
#              NFS ensure + re-mkfs 0.6 s + mounts 2.7/4.8 s +
#              readiness  => provisional 240 s
#   workload = posix_multi + dlm_fairness, manifest budgets 30 s each
#              (measured 3 s / 2 s at 2-node on 0.10.x)
#   GATE3_BUDGET_S: provisional was 300; first healthy PASS measured
#   32 s (prep 18 s + tests 5 s) => pinned 120 s (RULE-0
#   tighten-toward-actual, retaining power-cycle-escalation variance).
#   run.sh enforces the per-test budgets itself.
#   Per DLM_IMPL_PLAN (ladder_rung.sh rationale) run.sh is NEVER
#   killed mid-flight: an overrun is recorded as FAIL and diagnosed.
#
# Usage: gate3_cawsanity.sh

set -u
cd "$(dirname "$0")"
REPO="$(cd ../.. && pwd)"
GATE3_BUDGET_S="${GATE3_BUDGET_S:-120}"
CRIT="$REPO/criteria.json"
# The test cluster's shared LUN is dm-multipath since the 0.10.120
# multipath ladder (multipathd holds /dev/sda open on every node) —
# same device convention as scripts/ladder_rung.sh.
export MXFS_DEV="${MXFS_DEV:-/dev/mapper/mpatha}"

MODINFO=$(command -v modinfo || echo /usr/sbin/modinfo)
sv=$("$MODINFO" "$REPO/mxfs.ko" 2>/dev/null | awk '/^srcversion/{print $2}')

tstat() { # test-name field
    jq -r --arg t "$1" --arg f "$2" \
       '[.categories[].tests[] | select(.name==$t) | .runs["2/caw"][$f]][0] // "MISSING"' \
       "$CRIT" 2>/dev/null
}

iso_p0=$(tstat posix_multi iso)
iso_f0=$(tstat dlm_fairness iso)

start=$SECONDS
# Explicit forced prep: the marker records (nodes, dlm, srcversion) and a
# filtered invocation hard-errors on build mismatch — the lifted build is
# by definition a new srcversion, so re-form first.
( cd "$REPO" && ./run.sh 2 caw prep_cluster )
prep_rc=$?
rc=1
if [ "$prep_rc" -eq 0 ]; then
    ( cd "$REPO" && ./run.sh 2 caw posix_multi dlm_fairness )
    rc=$?
fi
wall=$((SECONDS - start))

p_stat=$(tstat posix_multi status);  p_iso=$(tstat posix_multi iso)
f_stat=$(tstat dlm_fairness status); f_iso=$(tstat dlm_fairness iso)

verdict=PASS; reason=""
[ "$p_stat" = PASS ] || { verdict=FAIL; reason="posix_multi=$p_stat"; }
[ "$f_stat" = PASS ] || { verdict=FAIL; reason="${reason:+$reason,}dlm_fairness=$f_stat"; }
# The records must be from THIS invocation, not a stale earlier pass.
[ "$p_iso" != "$iso_p0" ] || { verdict=FAIL; reason="${reason:+$reason,}posix_multi-not-rerecorded"; }
[ "$f_iso" != "$iso_f0" ] || { verdict=FAIL; reason="${reason:+$reason,}dlm_fairness-not-rerecorded"; }
[ "$prep_rc" -eq 0 ] || { verdict=FAIL; reason="${reason:+$reason,}prep_rc=$prep_rc"; }
[ "$rc" -eq 0 ] || { verdict=FAIL; reason="${reason:+$reason,}runsh_rc=$rc"; }
if [ "$wall" -gt "$GATE3_BUDGET_S" ]; then
    verdict=FAIL; reason="${reason:+$reason,}rule0-budget($wall>${GATE3_BUDGET_S}s)"
fi
[ -n "$reason" ] || reason=-
echo "RESULT: $verdict | test=net2_gate3_cawsanity | nodes=2 | measured=wall_s=$wall,budget_s=$GATE3_BUDGET_S,sv=$sv,posix_multi=$p_stat,dlm_fairness=$f_stat | reason=$reason"
[ "$verdict" = PASS ]
