#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Gate 1 — NET2 protocol foundation (DLM_IMPL_PLAN.md §11 step 1).
#
# Verifies: user-mode harness builds; golden encode/decode vectors;
# malformed-frame fuzz (1e5 seeded frames); TLV round-trip; fault-engine
# determinism; kernel build still compiles (net2_wire.h static asserts
# compile in the kernel via v5_mount.c's include — no Kbuild change yet).
#
# ── RULE-0 budget (written BEFORE first run; tighten after healthy PASS) ──
#   infra    = harness clean build: pure gcc of 2 TUs, est < 10 s
#            + kernel `make modules` compile check: measured separately,
#              reported as infra (first run = calibration; record actual
#              in tests/criteria/TIMEOUT_BUDGETS.md)
#   workload = 4 scenarios, pure CPU; native est < 10 s  =>  x2 = 20 s
#   HARNESS_BUDGET_S (build + scenarios, excl. kernel) = 30
#   RULE0_CALIBRATE=1 => measure + report, do not enforce (budget-pinning
#   run).  A timeout or overrun is a FAIL (RULE 0.3), not a retry.
#
# Usage: gate1_wire.sh [--skip-kernel]
#   SKIP_KERNEL=1 (or --skip-kernel) skips the `make modules` check —
#   for inner-loop use only; the gate verdict requires the kernel check.

set -u
cd "$(dirname "$0")"
REPO="$(cd ../.. && pwd)"
HARNESS_BUDGET_S="${HARNESS_BUDGET_S:-30}"
CAL="${RULE0_CALIBRATE:-0}"
SKIP_KERNEL="${SKIP_KERNEL:-0}"
[ "${1:-}" = "--skip-kernel" ] && SKIP_KERNEL=1

fail=0
t0=$(date +%s)

echo "== gate1: harness clean build =="
make clean >/dev/null 2>&1
if ! make 2>&1 | tail -20; then
    echo "RESULT: FAIL | test=net2_gate1 | nodes=1 | measured=- | reason=harness-build-failed"
    exit 1
fi
t_build=$(( $(date +%s) - t0 ))
echo "build_wall_s=$t_build"

if [ ! -s vectors/v1_frame_fc0.bin ]; then
    if [ "$CAL" = "1" ]; then
        echo "== gate1: vectors missing — generating (CALIBRATE mode) =="
        ./net2_harness write-vectors vectors || {
            echo "RESULT: FAIL | test=net2_gate1 | nodes=1 | measured=- | reason=vector-generation-failed"
            exit 1
        }
        echo "NOTE: vectors generated; review + commit them — goldens only"
        echo "      protect against regression once checked in."
    else
        echo "RESULT: FAIL | test=net2_gate1 | nodes=1 | measured=- | reason=vectors-missing (run with RULE0_CALIBRATE=1 once)"
        exit 1
    fi
fi

echo "== gate1: harness scenarios =="
t1=$(date +%s)
# Gate-1 scope only (wire foundation); the step-2 midcomms matrix is
# gate 2's (gate2_midcomms.sh).
GATE1_SCENARIOS="wire_golden wire_fuzz tlv_roundtrip fault_engine"
for scen in $GATE1_SCENARIOS; do
    if [ "$CAL" = "1" ]; then
        ./net2_harness run "$scen" || fail=1
    else
        timeout "$HARNESS_BUDGET_S" ./net2_harness run "$scen" || fail=1
    fi
done
t_scen=$(( $(date +%s) - t1 ))
harness_total=$(( t_build + t_scen ))
echo "scenario_wall_s=$t_scen harness_total_s=$harness_total budget_s=$HARNESS_BUDGET_S"
if [ "$CAL" != "1" ] && [ "$harness_total" -gt "$HARNESS_BUDGET_S" ]; then
    echo "RULE-0 overrun: ${harness_total}s > ${HARNESS_BUDGET_S}s — FAIL"
    fail=1
fi

t_kern=-
if [ "$SKIP_KERNEL" != "1" ]; then
    echo "== gate1: kernel compile check (make modules) =="
    tk=$(date +%s)
    if ! make -C "$REPO" modules > /tmp/gate1_kbuild.log 2>&1; then
        tail -30 /tmp/gate1_kbuild.log
        echo "RESULT: FAIL | test=net2_gate1 | nodes=1 | measured=harness_s=$harness_total | reason=kernel-build-failed"
        exit 1
    fi
    t_kern=$(( $(date +%s) - tk ))
    echo "kernel_build_wall_s=$t_kern (infra; recorded, not budgeted here)"
fi

status=PASS
[ "$fail" -ne 0 ] && status=FAIL
echo "RESULT: $status | test=net2_gate1 | nodes=1 | measured=harness_s=$harness_total,kernel_s=$t_kern,budget_s=$HARNESS_BUDGET_S | reason=$([ $fail -eq 0 ] && echo - || echo scenario-failures)"
[ "$fail" -eq 0 ]
