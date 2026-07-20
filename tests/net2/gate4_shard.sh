#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Gate 4 — NET2 lock plane / shard machine (DLM_IMPL_PLAN.md §11 step 4).
#
# The §13.2 matrix in the user harness: leader kill/partition at every
# commit point (sh_killpoints: 9 poison points × op phases), partition
# patterns incl. leader-alone / follower-alone / heal-truncate
# (sh_partitions), reconfiguration with state transfer + held-lock
# survival (sh_reconfig), closed-set recovery barrier on total replica
# loss (sh_recovery), 2-permanent-loss (sh_two_loss), duplicate-grant
# suppression across failover (sh_idempotent_failover), transferring-
# replicas-never-vote (sh_xfer_no_vote), replicated waiter order
# (sh_waiter_order), epoch change mid-op (sh_epoch_mid_op).  Evidence
# asserts live in the scenarios: single grant-capable leader per
# (E,term) [assert_single_leader], commit_seq/gen high-waters never
# regress [probe_monotone], no holder overlap [assert_no_overlap],
# total loss ⇒ barrier never empty-table [sh_recovery checks].
# Full shard group × 3 seeds + default seed + ASan sweep of the whole
# suite (wire+mc+shard — the lock plane rides midcomms; a shard-only
# ASan run would miss cross-layer frees).
#
# ── RULE-0 budget (written BEFORE first run; tighten after healthy PASS) ──
#   infra    = harness clean build ×2 (normal + ASan): measured ~10 s
#   workload = shard group: 11 scenarios with multi-second settle
#              sleeps ≈ 45 s/run × 4 seeds + ASan build + full-suite
#              ASan run ≈ 60 s
#              native == the harness itself  =>  ×~1.5 headroom
#   SCEN_BUDGET_S (everything after first build) = 300
#   (calibrated 2026-07-17: actual 199 s on clyde; provisional 620
#   tightened toward it per RULE 0.)
#   RULE0_CALIBRATE=1 => measure + report, do not enforce (budget-
#   pinning run).  A timeout or overrun is a FAIL (RULE 0.3), never a
#   retry-with-bigger-timeout.
#
# Usage: gate4_shard.sh

set -u
cd "$(dirname "$0")"
SCEN_BUDGET_S="${SCEN_BUDGET_S:-300}"
CAL="${RULE0_CALIBRATE:-0}"
SEEDS="0xF422 0xBEEF 0x1234"

fail=0

t0=$(date +%s)
echo "== gate4: harness clean build =="
make clean >/dev/null 2>&1
if ! make 2>&1 | tail -5; then
    echo "RESULT: FAIL | test=net2_gate4 | nodes=1 | measured=- | reason=harness-build-failed"
    exit 1
fi
t_build=$(( $(date +%s) - t0 ))
echo "build_wall_s=$t_build"

run_matrix() {
    local label="$1"; shift
    local out
    out="$("$@" 2>/dev/null | grep '^RESULT:')"
    echo "$out"
    local pass ntot
    pass=$(echo "$out" | grep -c 'RESULT: PASS')
    ntot=$(echo "$out" | grep -c 'RESULT:')
    if [ "$ntot" -eq 0 ] || [ "$pass" -ne "$ntot" ]; then
        echo "gate4: $label: $pass/$ntot passed — FAIL"
        fail=1
    else
        echo "gate4: $label: $pass/$ntot passed"
    fi
}

t1=$(date +%s)
echo "== gate4: shard group, default seed =="
run_matrix "shard default" ./net2_harness run shard
for seed in $SEEDS; do
    echo "== gate4: shard group, seed $seed =="
    run_matrix "shard seed=$seed" ./net2_harness run shard --seed "$seed"
done

echo "== gate4: AddressSanitizer sweep (full suite) =="
make clean >/dev/null 2>&1
if ! make CFLAGS="-O1 -g -std=gnu11 -Wall -Wextra -Werror -fsanitize=address" >/dev/null 2>&1; then
    echo "RESULT: FAIL | test=net2_gate4 | nodes=1 | measured=- | reason=asan-build-failed"
    exit 1
fi
asan_log=$(mktemp)
run_matrix "asan full suite" ./net2_harness run all
./net2_harness run all >/dev/null 2>"$asan_log" || true
if grep -qE 'ERROR: (Address|Leak)Sanitizer' "$asan_log"; then
    echo "gate4: sanitizer errors:"
    grep -E 'ERROR: (Address|Leak)Sanitizer' "$asan_log" | head -5
    fail=1
fi
rm -f "$asan_log"

# leave a normal (non-sanitizer) binary behind
make clean >/dev/null 2>&1
make >/dev/null 2>&1

t_scen=$(( $(date +%s) - t1 ))
echo "scenario_wall_s=$t_scen budget_s=$SCEN_BUDGET_S"
if [ "$CAL" = "1" ]; then
    echo "gate4: CALIBRATION run — wall $t_scen s (pin the budget near this)"
elif [ "$t_scen" -gt "$SCEN_BUDGET_S" ]; then
    echo "gate4: RULE-0 overrun: $t_scen s > $SCEN_BUDGET_S s — FAIL"
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    echo "RESULT: FAIL | test=net2_gate4 | nodes=1 | measured=wall=${t_scen}s | reason=see-above"
    exit 1
fi
echo "RESULT: PASS | test=net2_gate4 | nodes=1 | measured=wall=${t_scen}s,budget=${SCEN_BUDGET_S}s | reason=-"
