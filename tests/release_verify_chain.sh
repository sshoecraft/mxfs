#!/bin/bash
#
# release_verify_chain.sh — every rig step a release must pass, in order, on
# one module, detached: the flake-window laps a board's genuine failures still
# need, the full verification at the claimed node count, then the two-node
# boards (with their own window laps first) on the same module, so the
# two-node claim is re-earned at the version being released.
#
# Usage: tests/release_verify_chain.sh VERSION
#
# Steps, each read from the environment, in this order:
#   W4_LAPS   (default 0)  laps of tests/board_4node_chain.sh w4<i>_V tcp:W4_ROWS
#             (W4_ROWS default alloc_witness,chk_clean: the four-node quiesce
#             row and the witness its release verdict needs under one run id)
#   FULL      (default 1)  NODES=4 tests/full_verify.sh VERSION — the clean
#             build, both 4-node boards alone on the host, the packages unless
#             dist/VERSION holds them, every platform's packaged round and
#             hung-node test on both transports, sVirt on RHEL
#   W2TCP     (default 0)  laps of NODES=2 tests/board_4node_chain.sh w2t<i>_V tcp:W2TCP_ROWS
#   W2CAWD    (default 0)  laps of NODES=2 tests/board_4node_chain.sh w2c<i>_V cawd:W2CAWD_ROWS
#   BOARDS2   (default 1)  the two-node boards last, tcp then cawd, so their
#             read-back sees every window lap: NODES=2 tests/board_4node_chain.sh b2_V tcp cawd
#
# The lap counts are derived from the board, never guessed: a row whose newest
# genuine failure sits at window index k (0 = the live run, 11-run window,
# tools/criteria.py) reads PASS again only after 11-k more runs of that row,
# and the board run that ends each half is one of them.  So a row at k needs
# 10-k laps here before its board.  Derived 2026-09-29 for 0.90.17: 4/tcp
# chk_clean k=6 with two chain laps still to land -> W4_LAPS=2; 2/tcp fio_perf
# k=3 -> W2TCP=7; 2/cawd crash_audit k=2 -> W2CAWD=8.
#
# Every run.sh enforces its own per-row budget and full_verify.sh its own
# per-step bounds, so nothing here wraps a step in a timeout.  A failing step
# does not stop the chain: each step's own prep restores the fleet, and one
# run should show every failure.  What does stop it is a step that could not
# start (missing script): that is a chain defect, not a measurement.
#
# Log: tests/evidence/release_verify_<VERSION>.log — each step ends with
# "=== rc=N: <step> ===", and the last line is RELEASE_CHAIN_DONE.  The
# sub-steps keep their own logs (board_<N><dlm>_<label>.log,
# full_verify_<VERSION>*.log).
#
# Launch it detached with its output in a file (nohup setsid ... &): a chain
# started as a tool's background task is killed with the session that started
# it, and a board killed mid-row finalizes that row ABORTED.
#
set -u
V="${1:?usage: tests/release_verify_chain.sh VERSION}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE" || exit 1
EV="$HERE/tests/evidence"
mkdir -p "$EV"
L="$EV/release_verify_$V.log"
W4_LAPS="${W4_LAPS:-0}"
W4_ROWS="${W4_ROWS:-alloc_witness,chk_clean}"
FULL="${FULL:-1}"
W2TCP="${W2TCP:-0}"
W2TCP_ROWS="${W2TCP_ROWS:-fio_perf,guard_census}"
W2CAWD="${W2CAWD:-0}"
W2CAWD_ROWS="${W2CAWD_ROWS:-alloc_witness,chk_clean,crash_audit}"
BOARDS2="${BOARDS2:-1}"
for s in tests/board_4node_chain.sh tests/full_verify.sh run.sh; do
    [ -x "$s" ] || { echo "$(date -u +%FT%TZ) chain defect: $s is not executable; nothing run" | tee -a "$L"; exit 2; }
done

step() {  # step <name> <command...>: run it, log its output and rc
    local name=$1
    shift
    echo "=== $(date -u +%FT%TZ) $name: $* ===" | tee -a "$L"
    "$@" >> "$L" 2>&1
    local rc=$?
    echo "=== rc=$rc: $name ($(date -u +%FT%TZ)) ===" | tee -a "$L"
    return $rc
}

echo "=== release_verify_chain $V $(date -u +%FT%TZ) W4_LAPS=$W4_LAPS FULL=$FULL W2TCP=$W2TCP W2CAWD=$W2CAWD BOARDS2=$BOARDS2 ===" | tee -a "$L"
for ((i = 1; i <= W4_LAPS; i++)); do
    NODES=4 step "w4 lap $i/$W4_LAPS" tests/board_4node_chain.sh "w4${i}_$V" "tcp:$W4_ROWS"
    python3 tools/criteria.py 4 tcp | grep -E "^Total|${W4_ROWS//,/|}" | cut -c1-160 >> "$L"
done
if [ "$FULL" = 1 ]; then
    NODES=4 step "full_verify nodes=4" tests/full_verify.sh "$V"
fi
for ((i = 1; i <= W2TCP; i++)); do
    NODES=2 step "w2 tcp lap $i/$W2TCP" tests/board_4node_chain.sh "w2t${i}_$V" "tcp:$W2TCP_ROWS"
    python3 tools/criteria.py 2 tcp | grep -E "^Total|${W2TCP_ROWS//,/|}" | cut -c1-160 >> "$L"
done
for ((i = 1; i <= W2CAWD; i++)); do
    NODES=2 step "w2 cawd lap $i/$W2CAWD" tests/board_4node_chain.sh "w2c${i}_$V" "cawd:$W2CAWD_ROWS"
    python3 tools/criteria.py 2 cawd | grep -E "^Total|${W2CAWD_ROWS//,/|}" | cut -c1-160 >> "$L"
done
if [ "$BOARDS2" = 1 ]; then
    NODES=2 step "boards nodes=2" tests/board_4node_chain.sh "b2_$V" tcp cawd
    for dlm in tcp cawd; do
        echo "=== board 2/$dlm ===" >> "$L"
        python3 tools/criteria.py 2 "$dlm" | grep -vE '\| PASS ' | cut -c1-160 >> "$L"
    done
fi
grep -E '^=== rc=|^Total:|^VERDICT:' "$L" | tail -n 40
echo "RELEASE_CHAIN_DONE $(date -u +%FT%TZ)" | tee -a "$L"
