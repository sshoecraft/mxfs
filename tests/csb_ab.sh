#!/bin/bash
# csb_ab.sh — paired A/B of one or more module parameters against
# creator_stale_base.sh, with the PRECURSOR probes counted per pass.
#
# WHY THIS EXISTS
#   Two things made every previous A/B on this defect family worthless:
#
#   1. PREP AGE.  The storm's failure rate falls monotonically with time since
#      the last prep (21 -> 7 -> 7 -> 4 failing rounds on one build, same
#      params, back to back).  A single run after a fresh prep is not
#      comparable with a single run later.  Fixed the same way sf_storm_ab.sh
#      fixes it: one warm-up pass that is DISCARDED, then alternating A/B
#      passes on the same cluster state.
#   2. NO SIGNAL.  The behavioural symptom (a lost dirent) reproduces roughly
#      1 run in 10, and the deterministic precursor P195 fired 0-1 times per
#      storm run — so both arms read 0 and the comparison said nothing.
#      creator_stale_base.sh CONSTRUCTS the precondition instead of waiting for
#      it (measured: 3003 P65-EPOCH-CONVGATE events in one 20-round run), which
#      is what finally gives an arm something to differ in.
#
#   So this reports BOTH layers per pass: the symptom (node-round checks that
#   failed, and whether the creator's own child was among the missing names)
#   AND the invariant violation (P195 — a tenure that mutated an epoch-stale
#   base).  A fix must move the precursor; the symptom alone is too sparse.
#
# USAGE
#   tests/csb_ab.sh <param=val[,param=val...]> <param=val[,...]> [pairs] [rounds] [nodes]
#     arm A spec, arm B spec, then how many A/B pairs to run.
#     e.g. tests/csb_ab.sh p6_epoch_override=1,create_baseline_trackers=1 \
#                          p6_epoch_override=0,create_baseline_trackers=0 3 20
#
#   Assumes the cluster is ALREADY PREPPED with the build under test.  Does not
#   prep — prepping mid-experiment reintroduces confound (1).
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd -- "$SCRIPT_DIR/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"

ASPEC="${1:?usage: csb_ab.sh <A spec> <B spec> [pairs] [rounds] [nodes]}"
BSPEC="${2:?}"
PAIRS="${3:-3}"
ROUNDS="${4:-20}"
N="${5:-32}"
SLOT="${CSB_SLOT:-4}"
KIDS="${CSB_KIDS:-2}"
QUIET="${CSB_QUIET:-1500}"

set_spec() {
    local spec="$1" kv k v i got
    for kv in ${spec//,/ }; do
        k="${kv%%=*}"; v="${kv##*=}"
        for i in $(seq 1 "$N"); do
            ( timeout 20 "$SSH" "test$i" \
                "echo $v > /sys/module/mxfs/parameters/$k" >/dev/null 2>&1 ) &
        done
        wait
        got=$(timeout 20 "$SSH" test1 "cat /sys/module/mxfs/parameters/$k" \
              2>/dev/null | tr -dc '0-9-')
        [ "$got" = "$v" ] || { echo "PARAM SET FAILED: $k wanted=$v got=$got" >&2; exit 2; }
    done
}

# One pass: run the reproducer, then harvest the precursor counts from every
# node's ring.  creator_stale_base.sh clears the rings at its start, so the
# counts below belong to THIS pass only.
run_once() {
    local out rc fails creator_lost p195 p194 p188 p65 p189conv i
    out=$("$SCRIPT_DIR/creator_stale_base.sh" "$ROUNDS" "$N" "$SLOT" "$KIDS" "$QUIET" 2>&1)
    rc=$?
    if [ "$rc" = 2 ]; then
        echo "INFRA" ; return
    fi
    fails=$(printf '%s\n' "$out" | sed -n 's/.*node-checks OK=[0-9]* FAIL=\([0-9]*\).*/\1/p')
    creator_lost=$(printf '%s\n' "$out" | sed -n 's/.*includes the CREATOR.s own child: \([0-9]*\).*/\1/p')
    local tmp; tmp=$(mktemp -d)
    for i in $(seq 1 "$N"); do
        ( timeout 30 "$SSH" "test$i" \
            "dmesg | grep -E 'P195-STALE-BASE|P194-EPOCH-STALE|P188-REL-OBLIG|P65-EPOCH-CONVGATE|P189-RELOG'" \
            > "$tmp/t$i" 2>/dev/null ) &
    done
    wait
    p195=$(cat "$tmp"/t* 2>/dev/null | grep -c 'P195-STALE-BASE')
    p194=$(cat "$tmp"/t* 2>/dev/null | grep -c 'P194-EPOCH-STALE')
    p188=$(cat "$tmp"/t* 2>/dev/null | grep -c 'P188-REL-OBLIG')
    p65=$(cat "$tmp"/t*  2>/dev/null | grep -c 'P65-EPOCH-CONVGATE')
    p189conv=$(cat "$tmp"/t* 2>/dev/null | grep 'P189-RELOG' \
        | grep -c 'fmt=1\] disk\[nlink=[0-9]* chg=[0-9]* size=[-0-9]* fmt=2\]')
    rm -rf "$tmp"
    echo "${fails:-0} ${creator_lost:-0} $p195 $p194 $p188 $p65 $p189conv"
}

echo "=== csb_ab: A[$ASPEC] vs B[$BSPEC]  pairs=$PAIRS rounds=$ROUNDS nodes=$N ==="
echo "--- warm-up pass (DISCARDED — prep-age confound) ---"
set_spec "$ASPEC"
run_once >/dev/null

printf '%-6s %-6s %-8s %-14s %-6s %-6s %-6s %-8s %-10s\n' \
    pass arm fail_chk creator_lost P195 P194 P188 P65 P189conv
atot=0; btot=0; a195=0; b195=0; acl=0; bcl=0
for p in $(seq 1 "$PAIRS"); do
    for arm in A B; do
        [ "$arm" = A ] && set_spec "$ASPEC" || set_spec "$BSPEC"
        read -r f cl x195 x194 x188 x65 x189 <<<"$(run_once)"
        if [ "$f" = INFRA ]; then
            printf '%-6s %-6s %s\n' "$p" "$arm" "INFRA-FAIL (not a data point)"
            continue
        fi
        printf '%-6s %-6s %-8s %-14s %-6s %-6s %-6s %-8s %-10s\n' \
            "$p" "$arm" "$f" "$cl" "$x195" "$x194" "$x188" "$x65" "$x189"
        if [ "$arm" = A ]; then
            atot=$(( atot + f )); a195=$(( a195 + x195 )); acl=$(( acl + cl ))
        else
            btot=$(( btot + f )); b195=$(( b195 + x195 )); bcl=$(( bcl + cl ))
        fi
    done
done
echo "--- totals over $PAIRS pairs ---"
echo "  A[$ASPEC]  failing_checks=$atot  creator_child_lost=$acl  P195=$a195"
echo "  B[$BSPEC]  failing_checks=$btot  creator_child_lost=$bcl  P195=$b195"
echo "  (a difference smaller than the pass-to-pass spread within one arm is noise)"
