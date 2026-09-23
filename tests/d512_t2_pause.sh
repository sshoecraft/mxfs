#!/bin/bash
# (bash: tests/lib/rig.sh uses indirect expansion and printf -v; under sh
#  the lap died with "Bad substitution" before its first verdict, s59h)
# d512_t2_pause.sh — D-512 cycle-2 verification T2 (drain pausepoint ladder)
# + the T6 no-stale-into-reuse rider (sess415 ruling).
#
# For each release-drain stage 1-5 (dbg_rel_pause_* knobs, 0.28.4):
#   H (holder) buffered-writes F (dirty pages, cached EX grant).
#   Arm H's pause for F's ino at the stage, 3000ms.
#   W (waiter) reads F — the read BASTs H, whose release drain pauses at
#   the stage; W's grant CANNOT arrive until the drain completes and the
#   unlock publishes.
# Asserts per stage:
#   - W's read wall >= 2.0s (the pause held the publication back — the
#     barrier does not leak at this stage) and <= 25s (bounded);
#   - W's md5 == H's content (the drain landed the dirty data before
#     publication — no lost update);
#   - P-D512-RELPAUSE + P-D512-RELPAUSE-END fired for the stage on H;
#   - T6 rider, AFTER the whole ladder: W unlinks each F and creates G (may
#     reuse F's blocks); G reads back exactly as written on W (no stale
#     write from H landed).  The rider ran inside each stage until s62a:
#     stage N's create then reused the inode number stage N-1's rider had
#     just freed, a PENDING bast for that number re-fired a release at the
#     create — under the freshly armed pause — and H held nothing when W
#     read (stage 5: 450 ms "leak" with both pause markers present, the
#     re-fired release's).  With no free between stages every create gets a
#     fresh number and the only release under the pause is the one W's read
#     causes.
#   - zero splats on H.
#
# the budget rule (derived): per stage ~10s (setup 2 + pause 3 + reads 2 + rider 3)
# x5 = ~50s + dmesg 5s => ~55s.  Caller bound 150s.
#
# Usage: tests/d512_t2_pause.sh <label> [holder] [waiter] (default test2 test1)
set -u
LABEL=${1:?label}; H=${2:-test2}; W=${3:-test1}
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
OUT=${D512_OUT:-tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d512t2}
mkdir -p "$OUT"
# rs/rsx/measure/capture_require/value_now_into/window_into (tests/lib/rig.sh):
# every capture a verdict is taken from crosses the boundary in the parent
# shell first; a failed acquisition is an ABORT, never a count of zero or an
# empty value.
. "$(dirname "$0")/lib/rig.sh"
P=/sys/module/mxfs/parameters
fails=0
# ck: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS

D="$MNT/.d512t2_$LABEL"
echo "=== d512_t2_pause label=$LABEL H=$H W=$W out=$OUT $(date -u +%FT%TZ) ==="
MARK="D512T2-$LABEL-$$"
timeout 20 $SSH "$H" "echo '$MARK' > /dev/kmsg; mkdir -p '$D'" >/dev/null 2>&1

for stage in 1 2 3 4 5; do
    F="$D/s${stage}.dat"
    # H: create + ARM IN THE SAME SSH + re-dirty AFTER arming.  (v1 armed
    # in a second ssh: a recycled ino's create-churn re-fired a PENDING
    # bast and released the grant ~10ms after create — before the arm —
    # so W's read found a free slot and no pause engaged.  The post-arm
    # re-write re-acquires EX and re-dirties, so the grant is HELD and
    # the pause armed when W's read BASTs.)
    timeout 25 $SSH "$H" "
        dd if=/dev/urandom of='$F' bs=4096 count=8 2>/dev/null || exit 1
        ino=\$(stat -c %i '$F')
        echo \$ino > $P/dbg_rel_pause_ino
        echo $stage > $P/dbg_rel_pause_stage
        echo 3000 > $P/dbg_rel_pause_ms
        dd if=/dev/urandom of='$F' bs=4096 count=8 2>/dev/null || exit 1
        md5sum '$F' | cut -d' ' -f1
        echo \$ino
      " 2>/dev/null | filt > "$OUT/h_s$stage.txt"
    hmd5=$(sed -n 1p "$OUT/h_s$stage.txt" | tr -dc 'a-f0-9')
    ino=$(sed -n 2p "$OUT/h_s$stage.txt" | tr -dc '0-9')
    if [ -z "$ino" ] || [ -z "$hmd5" ]; then echo "  FAIL stage$stage setup"; fails=$((fails+1)); continue; fi
    # W: timed read (BASTs H -> paused drain -> grant)
    t0=$(date +%s%N)
    value_now_into wmd5 "$W" 30 "$OUT/rv_wmd5_1.txt" '^[0-9a-f]{32}$' "wmd5 on $W" "md5sum '$F' | cut -d' ' -f1"
    t1=$(date +%s%N)
    wall_ms=$(( (t1 - t0) / 1000000 ))
    timeout 20 $SSH "$H" "echo 0 > $P/dbg_rel_pause_ms; echo 0 > $P/dbg_rel_pause_ino" >/dev/null 2>&1
    ck "stage$stage: publication held (wall>=2000ms)" \
       "$([ "$wall_ms" -ge 2000 ] && echo held || echo leaked:${wall_ms}ms)" "held"
    ck "stage$stage: bounded (<25s)" "$([ "$wall_ms" -lt 25000 ] && echo yes || echo no:${wall_ms}ms)" "yes"
    ck "stage$stage: W md5 == H md5" "$([ "$wmd5" = "$hmd5" ] && echo same || echo differ)" "same"
    echo "  INFO stage$stage ino=$ino wall_ms=$wall_ms"
done
# T6 rider, after the ladder (no free happens between two stages' creates):
# W unlinks each F and creates G over the freed blocks, then verifies G.
gx=$(dd if=/dev/zero bs=4096 count=8 2>/dev/null | tr '\0' 'X' | md5sum | cut -d' ' -f1)
for stage in 1 2 3 4 5; do
    F="$D/s${stage}.dat"
    value_now_into g6 "$W" 30 "$OUT/rv_g6_$stage.txt" '^[0-9a-f]{32}$' "the rider G digest on $W (stage $stage)" \
      "rm -f '$F' && dd if=/dev/zero bs=4096 count=8 2>/dev/null | tr '\\0' 'X' > '$D/g${stage}.dat' && sync -f '$D/g${stage}.dat' && md5sum '$D/g${stage}.dat' | cut -d' ' -f1"
    ck "stage$stage: T6 rider G clean" "$([ "$g6" = "$gx" ] && echo clean || echo dirty)" "clean"
done

timeout 25 $SSH "$H" "dmesg | sed -n \"/$MARK/,\\\$p\"" 2>/dev/null | filt > "$OUT/h_dmesg.txt"
for stage in 1 2 3 4 5; do
    got=$(grep -ac "P-D512-RELPAUSE ino=[0-9]* stage=$stage " "$OUT/h_dmesg.txt")
    end=$(grep -ac "P-D512-RELPAUSE-END ino=[0-9]* stage=$stage" "$OUT/h_dmesg.txt")
    ck "stage$stage: pause+end markers" "$([ "$got" -ge 1 ] && [ "$end" -ge 1 ] && echo both || echo missing:$got/$end)" "both"
done
splat=$(grep -aEc 'BUG:|Oops|WARNING:.*lockdep' "$OUT/h_dmesg.txt")
ck "zero splats on H" "$splat" "0"

timeout 25 $SSH "$H" "rm -rf '$D'; echo 0 > $P/dbg_rel_pause_stage" >/dev/null 2>&1
if [ "$fails" -eq 0 ]; then echo "VERDICT PASS: T2 ladder 5/5 stages + T6 riders"; exit 0; fi
echo "VERDICT FAIL: $fails assertion(s)"; exit 1
