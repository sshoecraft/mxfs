#!/bin/bash
# creator_baseline_ab.sh — same-build A/B for mxfs.creator_baseline_stamp
# (ccloop c7ee71c6 sess28, D-SILENT-MKDIR-LOSS creator-baseline fix).
#
# WHAT IS UNDER TEST
#   A directory this node creates keeps i_dlm_dir_valid_epoch at the never-set
#   sentinel 0 for the life of the in-core inode.  Its CAW slot, meanwhile,
#   inherits the dir_epoch lineage of whatever incarnation last used that inode
#   NUMBER (caw_tombstone_slot / caw_claim_inherit_epoch keep it deliberately),
#   and our own publish claim BUMPS it again (caw_grant_epoch_update advances on
#   any EX claim whose slot names a different node as previous EX holder).  So
#   `master_epoch > valid_epoch` is PERMANENTLY TRUE for a self-created dir, and
#   P32E-DIREPOCH-FENCE then skips EVERY flush of it — mkdir(2) returns 0 and no
#   node ever writes the dirent.
#
#   mxfs.creator_baseline_stamp establishes the baseline at the instant the
#   inode takes its FIRST REAL EX GRANT (the publish), while i_mxfs_self_created
#   still holds — i.e. while no peer has so much as requested the lock, so there
#   is no peer update to launder.
#     bit0 (1) = stamp i_dlm_dir_valid_epoch
#     bit1 (2) = stamp i_dlm_cached_grant_gen
#     0        = pre-fix sentinels (the negative control)
#
# THE REPRODUCER IS AGE-DEPENDENT.  Measured this session at 2/caw on one build:
#   fresh prep -> dirent_durability -> dirent_publish_integrity  => PASS (0 hits)
#   fresh prep -> AGING BATCH -> same two                        => FAIL (3 hits)
# Never judge this fix from a fresh-prep run; that shape passes in both arms.
#
# RULE 0.  Every timeout below is budget + measured harness overhead, never a
# round number and never the tool cap.  Budgets come from tests/suite/manifest
# (dir_reuse_coherency uses run.sh's own 140*N caw formula); OVERHEAD=30 is the
# measured run.sh wrapper cost at 2 nodes (79s wall for a 63s test, 25s for a
# 2s test).  run.sh itself enforces the budget and flips PASS->FAIL on overrun,
# so the outer timeout MUST exceed it or a mid-flight kill silently drops the
# result line.  A timeout here is a FAILURE, not a retry signal.
#
# Usage:
#   tests/creator_baseline_ab.sh arm  <N> <mask>   # full arm: prep+age+measure
#   tests/creator_baseline_ab.sh prep <N> <mask>
#   tests/creator_baseline_ab.sh age  <N>          # 2 calls internally
#   tests/creator_baseline_ab.sh measure <N>
#   tests/creator_baseline_ab.sh census  <N>       # P210/P195 per node, scoped
#
# `arm` runs the stages back to back and will exceed a 10-minute foreground cap
# at N>2; call the stages separately there (the honest per-stage sum is printed
# by `budget`).
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO"

OVERHEAD=30

STAGE="${1:?usage: creator_baseline_ab.sh <arm|prep|mark|age|measure|census|budget> <N> [mask]}"
N="${2:?node count}"
MASK="${3:-0}"

# Per-criterion budgets, all from tests/suite/manifest.
# Prep is infra (boot/mkfs/mount/converge) and its cost grows with the node
# set.  MEASURED: 25-28s at N=2; 36-37s at N=8; 51s, 76s and >120s at N=32
# (sess27 recorded 58-219s at 32).  A flat 90 killed a healthy 32-node prep
# mid-converge, so scale it from those measurements rather than rounding up.
B_PREP=$((90 + 5 * N))
B_CRASH=90
B_DRC=120                       # manifest flat 120 (run.sh's 140*N caw formula is NOT applied here — measured 101-106s at N=2 and 108s at N=32 against a 120s budget)
B_FDW=60
B_FNP=60
B_SOAK=60
B_DD=240
B_DPI=60

t() { echo "$(( $1 + OVERHEAD ))"; }

nodes() { local i; for ((i=1; i<=N; i++)); do echo "test$i"; done; }

# Set the knob on every node and READ IT BACK.  A module reload resets it to the
# built-in default (0), so this must run AFTER prep, every time.  Verifying the
# read-back is not paranoia: an arm that silently ran at the default would be
# indistinguishable from a fix that did nothing.
# MASK is a comma-separated k=v spec of module params, e.g.
#   dir_epoch_incarn_gate=1,creator_baseline_stamp=1
# A bare integer is shorthand for creator_baseline_stamp=<int> (the original
# arm axis).  Empty / "0" means "leave every knob at its built-in default".
set_mask() {
    local spec="$1" h kv k v got bad=0
    case "$spec" in
        ''|*[!0-9]*) ;;                                  # already a k=v spec
        *) spec="creator_baseline_stamp=$spec" ;;        # bare int shorthand
    esac
    for h in $(nodes); do
        for kv in ${spec//,/ }; do
            k="${kv%%=*}"; v="${kv#*=}"
            tools/mxfs_sshpass.sh "$h" \
                "echo $v > /sys/module/mxfs/parameters/$k" >/dev/null 2>&1
            got=$(tools/mxfs_sshpass.sh "$h" \
                  "cat /sys/module/mxfs/parameters/$k" \
                  2>/dev/null | tr -d '\r' | tail -1)
            if [ "$got" != "$v" ]; then
                echo "  !! $h: $k=$got (wanted $v)"
                bad=1
            fi
        done
    done
    [ "$bad" = 0 ] || { echo "ABORT: knob not applied on every node"; exit 3; }
    echo "--- $spec confirmed on all $N node(s) ---"
}

# Stamp the scoping marker on every node so `census` can bound ANY workload,
# not just the criteria that stamp it themselves (dirent_durability does;
# sf_mkdir_storm.sh does not).  Same marker string the suite's
# dirent_window_scope() looks for, so both readers agree.
stage_mark() {
    local h
    for h in $(nodes); do
        tools/mxfs_sshpass.sh "$h" \
            "echo 'MXFS_DIRENT_WINDOW ab-mark' > /dev/kmsg" >/dev/null 2>&1
    done
    echo "--- window marker stamped on all $N node(s) ---"
}

stage_prep() {
    echo "=== PREP $N/caw (mask=$MASK) budget=${B_PREP}s ==="
    MXFS_FORCE_PREP=1 timeout "$(t $B_PREP)" ./run.sh "$N" caw prep_cluster \
        || { echo "PREP FAILED/TIMED OUT"; exit 4; }
    set_mask "$MASK"
}

stage_age() {
    echo "=== AGE part 1: crash_consistency dir_reuse_coherency ==="
    timeout "$(t $((B_CRASH + B_DRC + OVERHEAD)))" \
        ./run.sh "$N" caw crash_consistency dir_reuse_coherency || return 1
    echo "=== AGE part 2: fence_during_write fault_netpartition soak ==="
    timeout "$(t $((B_FDW + B_FNP + B_SOAK + 2 * OVERHEAD)))" \
        ./run.sh "$N" caw fence_during_write fault_netpartition soak || return 1
}

stage_measure() {
    echo "=== MEASURE: dirent_durability ==="
    timeout "$(t $B_DD)" ./run.sh "$N" caw dirent_durability
    echo "=== MEASURE: dirent_publish_integrity ==="
    timeout "$(t $B_DPI)" ./run.sh "$N" caw dirent_publish_integrity
}

# Scoped census.  Per node take whichever kernel-log source still holds the most
# lines AFTER the last MXFS_DIRENT_WINDOW marker (sess26: retention varies ~60x
# per node, so hardcoding either source loses data), then count the fix's own
# markers inside that window only.
stage_census() {
    local h out d
    d=$(mktemp -d)
    echo "=== CENSUS (scoped to the last MXFS_DIRENT_WINDOW) ==="
    # PARALLEL: a serial 32-node scan of a multi-MB ring took >600s and was
    # killed.  Each node is independent, so fan out and join; per-node timeout
    # keeps one slow node from stalling the join.
    for h in $(nodes); do
        (
        tools/mxfs_sshpass.sh "$h" '
            best=""; bestn=0
            for src in "dmesg" "journalctl -k --no-pager -o cat"; do
                f=$(mktemp)
                $src 2>/dev/null | awk "/MXFS_DIRENT_WINDOW/{m=NR} {l[NR]=\$0}
                    END{ if (m) for(i=m+1;i<=NR;i++) print l[i] }" > "$f"
                n=$(wc -l < "$f")
                if [ "$n" -gt "$bestn" ]; then bestn=$n; best=$f; else rm -f "$f"; fi
            done
            if [ -z "$best" ]; then echo "0 0 0 0 0 0 0 0"; exit 0; fi
            p210=$(grep -c "P210-CREATOR-BASELINE" "$best")
            seen=$(grep "P210-CREATOR-BASELINE" "$best" | grep -c "state=1")
            valid=$(grep "P210-CREATOR-BASELINE" "$best" | grep -c "state=2")
            p195=$(grep -c "P195-STALE-BASE-ALREADY-DIRTY" "$best")
            p194=$(grep -c "P194-EPOCH-STALE-OP" "$best")
            p32e=$(grep -c "P32E-DIREPOCH-FENCE" "$best")
            p211=$(grep -c "P211-EPOCH-" "$best")
            echo "$bestn $p210 $seen $valid $p195 $p194 $p32e $p211"
            rm -f "$best"
        ' 2>/dev/null | grep -E "^[0-9]+ " | tail -1 > "$d/$h"
        ) &
    done
    wait
    printf '%-8s %8s %6s %6s %6s %6s %6s %6s %6s\n' \
        node lines P210 seen valid P195 P194 P32E P211
    { for h in $(nodes); do
        out=$(cat "$d/$h" 2>/dev/null)
        [ -n "$out" ] || out="- - - - - - - -"
        # shellcheck disable=SC2086
        set -- $out
        printf '%-8s %8s %6s %6s %6s %6s %6s %6s %6s\n' \
            "$h" "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8"
      done
      awk '{for(i=1;i<=8;i++) t[i]+=$i} END{printf "%-8s %8d %6d %6d %6d %6d %6d %6d %6d\n","TOTAL",t[1],t[2],t[3],t[4],t[5],t[6],t[7],t[8]}' \
        "$d"/* 2>/dev/null; }
    echo
    echo "READ IT LIKE THIS:"
    echo "  P210 > 0 in BOTH arms  = the reproducer armed (knob-independent)."
    echo "  seen  = control arm reached the publish point (stamp knob off)."
    echo "  valid = the publish stamp applied (creator_baseline_stamp != 0)."
    echo "  P211  = the incarnation gate engaged (fix arm only)."
    echo "  P195/P32E = the defect signals.  Acceptance is BOTH -> 0 with exposure > 0."
    echo "  exposure = 0 means the arm PROVED NOTHING -- rerun with the aging batch."
}

case "$STAGE" in
    prep)    stage_prep ;;
    mark)    stage_mark ;;
    age)     stage_age ;;
    measure) stage_measure ;;
    census)  stage_census ;;
    arm)     stage_prep && stage_age && stage_measure && stage_census ;;
    budget)
        echo "N=$N  overhead=${OVERHEAD}s"
        echo "  prep    $(t $B_PREP)s"
        echo "  age1    $(t $((B_CRASH + B_DRC + OVERHEAD)))s"
        echo "  age2    $(t $((B_FDW + B_FNP + B_SOAK + 2 * OVERHEAD)))s"
        echo "  measure $(t $B_DD)s + $(t $B_DPI)s"
        echo "  ARM SUM $(( $(t $B_PREP) + $(t $((B_CRASH + B_DRC + OVERHEAD))) \
                          + $(t $((B_FDW + B_FNP + B_SOAK + 2 * OVERHEAD))) \
                          + $(t $B_DD) + $(t $B_DPI) ))s"
        ;;
    *) echo "unknown stage '$STAGE'"; exit 2 ;;
esac
