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
#   LAPS    (default none)  window laps, each "<configuration>:<row>[,<row>...]:<count>",
#           e.g. "4/net/mesh/direct:chk_clean:2": <count> laps of
#           tests/board_4node_chain.sh w<slug><i>_V <configuration>:<rows>.
#           Laps at the claimed node count run first; laps at a smaller count
#           run before that count's boards.
#   FULL    (default 1)  NODES=CLAIM tests/full_verify.sh VERSION — the clean
#           build, the release matrix's boards at the claimed node count, the
#           packages unless dist/VERSION holds them, every platform's packaged
#           round and hung-node test on each configuration, sVirt on RHEL
#   LOWER   (default: the released node counts below CLAIM, largest first —
#           "4 2" under CLAIM=8, "2" under CLAIM=4)  every count's laps, and
#           then ONE tests/board_4node_chain.sh bL_V call running every
#           configuration of the release matrix at every one of those counts
#           side by side (tools/configuration.py release-matrix --nodes
#           <count>): the i-th configuration at <count> on rig group g<count>,
#           the next on g<count>b, each on a pool LUN of its own.  The boards
#           come last so their read-back sees every lap
#   POWER, PLATFORM_GROUPS  passed on to tests/full_verify.sh, which documents
#           them.  With POWER=1 the chain also starts with every platform set
#           off and the rig's CLAIM nodes up, so the laps and the boards run
#           on a host holding nothing else.
#
# The lap counts are derived from the board, never guessed: a row whose newest
# genuine failure sits at window index k (0 = the live run, 11-run window,
# tools/criteria.py) reads PASS again only after 11-k more runs of that row,
# and the board run that ends each half is one of them.  So a row at k needs
# 10-k laps here before its board.  Derived 2026-09-29 for 0.90.17: 4/net/mesh/direct
# chk_clean k=6 with two chain laps still to land ->
# 4/net/mesh/direct:alloc_witness,chk_clean:2 (the four-node quiesce row and
# the witness its release verdict needs under one run id); 2/net/mesh/direct
# fio_perf k=3 -> 2/net/mesh/direct:fio_perf,guard_census:7; 2/disk/caw/direct
# crash_audit k=2 -> 2/disk/caw/direct:alloc_witness,chk_clean,crash_audit:8.
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
# sub-steps keep their own logs (board_<N-class-method-attach>_<label>.log,
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
    [[ "$spec" =~ ^[0-9]+(/[a-z]+){3}:[a-z0-9_,]+:[0-9]+$ ]] \
        && python3 tools/configuration.py parse "${spec%%:*}" >/dev/null \
        || { echo "$(date -u +%FT%TZ) chain defect: LAPS entry '$spec' is not <configuration>:<rows>:<count>; nothing run" | tee -a "$L"; exit 2; }
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
    local want=$1 spec cfg n rows count i
    for spec in $LAPS; do
        IFS=: read -r cfg rows count <<<"$spec"
        n=${cfg%%/*}
        [ "$n" = "$want" ] || continue
        for ((i = 1; i <= count; i++)); do
            step "w $cfg lap $i/$count" tests/board_4node_chain.sh "w${cfg//\//-}${i}_$V" "$cfg:$rows"
            python3 tools/criteria.py "$cfg" | grep -E "^Total|${rows//,/|}" | cut -c1-160 >> "$L"
        done
    done
}

echo "=== release_verify_chain $V $(date -u +%FT%TZ) CLAIM=$CLAIM LAPS=[$LAPS] FULL=$FULL LOWER=[$LOWER ] POWER=$POWER ===" | tee -a "$L"
# What the host actually spends, every 5 s for the whole chain, next to the
# step lines in $L that say which stage was running: how far the stages can
# overlap is decided from this, not from the vCPUs the guests were given.
# Anything else running on clyde shows up here too.
vmstat -w -t 5 > "$EV/release_verify_hostcpu_$V.log" 2>&1 &
HOSTCPU=$!
trap 'kill $HOSTCPU 2>/dev/null' EXIT
# group_of <count> <i>: the rig group the i-th configuration at <count> runs on
group_of() { local g=g$1; [ "$2" -gt 0 ] && g=g$1$(printf "\\$(printf %o $((97 + $2)))"); echo "$g"; }
# With POWER=1 every stage starts from a host holding only what it uses: a
# guest left up from the stage before (a platform set is 8 of them) is memory
# and CPU the boards do not get.  RIG_MAX is the highest rig node any group
# names.
RIG_MAX=$(tools/mxfs_lab.sh groups | while read -r g; do tools/mxfs_lab.sh group "$g"; done | tr ' ' '\n' | sed -n 's/^test//p' | sort -n | tail -1)
if [ "$POWER" = 1 ]; then
    step "platform sets off" scripts/lab_power.sh down ubuntu2404 pve9 rhel9 debian13
    step "rig off" scripts/lab_power.sh down "rig:${RIG_MAX:-$CLAIM}"
    [ -n "$LAPS" ] && step "rig up" scripts/lab_power.sh up "rig:$CLAIM"
fi
laps_at "$CLAIM"
# SIDE_BY_SIDE=1 (default): the claimed count's boards join the smaller
# counts' boards in ONE side-by-side step, and full_verify runs only its build
# before it and its packages and platforms after it.  At 2 vCPUs and 2.5 GiB
# per rig guest, 8+8+4+4+2+2 = 28 guests are 56 vCPUs on this 56-core host
# and ~70 GiB of its 94.  SIDE_BY_SIDE=0 keeps the stages apart: the claimed
# count's suites inside full_verify, then the smaller counts' boards.
SIDE_BY_SIDE="${SIDE_BY_SIDE:-1}"
together=0
[ "$FULL" = 1 ] && [ "$SIDE_BY_SIDE" = 1 ] && together=1
if [ "$together" = 1 ]; then
    NODES=$CLAIM STEPS=build step "full_verify nodes=$CLAIM build" tests/full_verify.sh "$V"
elif [ "$FULL" = 1 ]; then
    NODES=$CLAIM step "full_verify nodes=$CLAIM" tests/full_verify.sh "$V"
fi
counts="$LOWER"
[ "$together" = 1 ] && counts="$CLAIM $LOWER"
boards=(); sets=(); cfgs=()
for n in $counts; do
    [ "$n" = "$CLAIM" ] || laps_at "$n"
    i=0
    for cfg in $(python3 tools/configuration.py release-matrix --nodes "$n"); do
        g=$(group_of "$n" "$i")
        [ "$(scripts/../tools/mxfs_lab.sh group "$g" 2>/dev/null | wc -w)" = "$n" ] \
            || { echo "$(date -u +%FT%TZ) chain defect: $cfg needs rig group $g of $n nodes in the lab file" | tee -a "$L"; exit 2; }
        boards+=("$cfg@$g"); sets+=("group:$g"); cfgs+=("$cfg")
        i=$((i + 1))
    done
done
if [ "${#boards[@]}" -gt 0 ]; then
    if [ "$POWER" = 1 ]; then
        step "rig off" scripts/lab_power.sh down "rig:${RIG_MAX:-$CLAIM}"
        step "board groups up" scripts/lab_power.sh up "${sets[@]}"
    fi
    step "boards nodes=[$counts ] side by side" tests/board_4node_chain.sh "bL_$V" "${boards[@]}"
    for cfg in "${cfgs[@]}"; do
        echo "=== board $cfg ===" >> "$L"
        python3 tools/criteria.py "$cfg" | grep -vE '\| PASS ' | cut -c1-160 >> "$L"
    done
fi
if [ "$together" = 1 ]; then
    # full_verify powers down only the claimed count's groups before a
    # platform group; the smaller counts' groups are up from the boards too
    [ "$POWER" = 1 ] && step "rig off" scripts/lab_power.sh down "rig:${RIG_MAX:-$CLAIM}"
    NODES=$CLAIM STEPS=packages,platforms step "full_verify nodes=$CLAIM packages,platforms" tests/full_verify.sh "$V"
fi
grep -E '^=== rc=|^Total:|^VERDICT:' "$L" | tail -n 40
echo "RELEASE_CHAIN_DONE $(date -u +%FT%TZ)" | tee -a "$L"
