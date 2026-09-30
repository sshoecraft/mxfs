#!/bin/bash
#
# release_verify_chain.sh — every rig step a release must pass, in order, on
# one module, detached: the flake-window laps a board's genuine failures still
# need, the full verification at the claimed node count, then the boards of
# every smaller released node count (with their own window laps first) on the
# same module, so each smaller claim is re-earned at the version being
# released.
#
# Usage: [CLAIM=N] tests/release_verify_chain.sh VERSION
#
# Read from the environment:
#   CLAIM   (default 4)  the node count the release claims
#   LAPS    (default none)  window laps, each "<nodes>:<dlm>:<row>[,<row>...]:<count>":
#           <count> laps of NODES=<nodes> tests/board_4node_chain.sh
#           w<nodes><dlm><i>_V <dlm>:<rows>.  Laps at the claimed node count
#           run first; laps at a smaller count run before that count's boards.
#   FULL    (default 1)  NODES=CLAIM tests/full_verify.sh VERSION — the clean
#           build, both boards at the claimed node count, the packages unless
#           dist/VERSION holds them, every platform's packaged round and
#           hung-node test on both transports, sVirt on RHEL
#   LOWER   (default: the released node counts below CLAIM, largest first —
#           "4 2" under CLAIM=8, "2" under CLAIM=4)  for each, that count's
#           laps and then NODES=<count> tests/board_4node_chain.sh b<count>_V
#           tcp cawd, the boards last so their read-back sees every lap
#   POWER, PLATFORM_GROUPS  passed on to tests/full_verify.sh, which documents
#           them.  With POWER=1 the chain also starts with every platform set
#           off and the rig's CLAIM nodes up, so the laps and the boards run
#           on a host holding nothing else.
#
# The lap counts are derived from the board, never guessed: a row whose newest
# genuine failure sits at window index k (0 = the live run, 11-run window,
# tools/criteria.py) reads PASS again only after 11-k more runs of that row,
# and the board run that ends each half is one of them.  So a row at k needs
# 10-k laps here before its board.  Derived 2026-09-29 for 0.90.17: 4/tcp
# chk_clean k=6 with two chain laps still to land -> 4:tcp:alloc_witness,chk_clean:2
# (the four-node quiesce row and the witness its release verdict needs under
# one run id); 2/tcp fio_perf k=3 -> 2:tcp:fio_perf,guard_census:7; 2/cawd
# crash_audit k=2 -> 2:cawd:alloc_witness,chk_clean,crash_audit:8.
#
# Every run.sh enforces its own per-row budget and full_verify.sh its own
# per-step bounds, so nothing here wraps a step in a timeout.  A failing step
# does not stop the chain: each step's own prep restores the fleet, and one
# run should show every failure.  What does stop it is a step that could not
# start (missing script, malformed LAPS): that is a chain defect, not a
# measurement.
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
V="${1:?usage: [CLAIM=N] tests/release_verify_chain.sh VERSION}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE" || exit 1
EV="$HERE/tests/evidence"
mkdir -p "$EV"
L="$EV/release_verify_$V.log"
CLAIM="${CLAIM:-4}"
LAPS="${LAPS:-}"
FULL="${FULL:-1}"
POWER="${POWER:-0}"
export POWER
[[ "$CLAIM" =~ ^[0-9]+$ ]] && [ "$CLAIM" -ge 2 ] || { echo "CLAIM must be an integer >= 2 (got '$CLAIM')" | tee -a "$L"; exit 2; }
if [ -z "${LOWER+set}" ]; then
    LOWER=""
    for n in 4 2; do [ "$n" -lt "$CLAIM" ] && LOWER="$LOWER $n"; done
fi
for s in tests/board_4node_chain.sh tests/full_verify.sh scripts/lab_power.sh run.sh; do
    [ -x "$s" ] || { echo "$(date -u +%FT%TZ) chain defect: $s is not executable; nothing run" | tee -a "$L"; exit 2; }
done
for spec in $LAPS; do
    [[ "$spec" =~ ^[0-9]+:(tcp|cawd|caw|cawp):[a-z0-9_,]+:[0-9]+$ ]] \
        || { echo "$(date -u +%FT%TZ) chain defect: LAPS entry '$spec' is not <nodes>:<dlm>:<rows>:<count>; nothing run" | tee -a "$L"; exit 2; }
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

laps_at() {  # laps_at <nodes>: every LAPS entry for that node count, in order
    local want=$1 spec n dlm rows count i
    for spec in $LAPS; do
        IFS=: read -r n dlm rows count <<<"$spec"
        [ "$n" = "$want" ] || continue
        for ((i = 1; i <= count; i++)); do
            NODES=$n step "w$n $dlm lap $i/$count" tests/board_4node_chain.sh "w${n}${dlm}${i}_$V" "$dlm:$rows"
            python3 tools/criteria.py "$n" "$dlm" | grep -E "^Total|${rows//,/|}" | cut -c1-160 >> "$L"
        done
    done
}

echo "=== release_verify_chain $V $(date -u +%FT%TZ) CLAIM=$CLAIM LAPS=[$LAPS] FULL=$FULL LOWER=[$LOWER ] POWER=$POWER ===" | tee -a "$L"
if [ "$POWER" = 1 ]; then
    step "platform sets off" scripts/lab_power.sh down ubuntu2404 pve9 rhel9 debian13
    step "rig up" scripts/lab_power.sh up "rig:$CLAIM"
fi
laps_at "$CLAIM"
if [ "$FULL" = 1 ]; then
    NODES=$CLAIM step "full_verify nodes=$CLAIM" tests/full_verify.sh "$V"
fi
for n in $LOWER; do
    laps_at "$n"
    NODES=$n step "boards nodes=$n" tests/board_4node_chain.sh "b${n}_$V" tcp cawd
    for dlm in tcp cawd; do
        echo "=== board $n/$dlm ===" >> "$L"
        python3 tools/criteria.py "$n" "$dlm" | grep -vE '\| PASS ' | cut -c1-160 >> "$L"
    done
done
grep -E '^=== rc=|^Total:|^VERDICT:' "$L" | tail -n 40
echo "RELEASE_CHAIN_DONE $(date -u +%FT%TZ)" | tee -a "$L"
