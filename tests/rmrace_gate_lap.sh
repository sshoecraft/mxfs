#!/bin/bash
# rmrace_gate_lap.sh — one arm of the demoter grant-gate A/B on a rig group:
# fresh boots of every node, one stress_rmdir_mkdir_race.sh mkdir lap with the
# test-only demoter-claim injector on rank 1, then each node's count of the
# lines that score the arm.
#
# WHY.  D-8TCP-RM-OF-A-CHILD: a task holding a demoter claim that outlived its
# release was admitted to a directory with no lock grant.  The control arm
# (gate 0) must show the no-grant admission with damage; the fix arm (gate 1)
# must show the same requests refused, every rank returned and a clean audit.
# Both arms need the stale-claim state on demand, which the injector supplies;
# the base directory is skipped so no claim is planted where its owner may exit
# first (such a claim stalls releases and withdraws nodes in BOTH arms).
#
# REAP (default 1) sets demoter_dead_claim_reap: 0 leaves a claim whose owner
# exited in place, for the control arm of its own A/B.  BASE=1 lets the injector
# plant on the base directory too, where the remover's last operation leaves a
# claim whose owner exits: the state that wedged a node on a dead claim and the
# precondition of D-SHARED-PARENT-NLINK-EXCEEDS-ITS-ENTRIES-AFTER-CONCURRENT-RM-AND-MKDIR.
#
# Usage: [REAP=0|1] [BASE=0|1] tests/rmrace_gate_lap.sh <gate 0|1> [configuration] [group] [seconds]
# Exit: the stress harness's code (0 CLEAN, 1 CORRUPT, 2 no verdict), 3 if the
# group did not come back from the reset, 124 if the lap overran its budget.
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
GATE=${1:?gate 0|1}
CONFIG=${2:-8/net/mesh/direct}
GROUP=${3:-g8}
SECS=${4:-300}
REAP=${REAP:-1}
BASE=${BASE:-0}
SSH="$REPO/tools/mxfs_sshpass.sh"
NODES=$("$REPO/tools/mxfs_lab.sh" group "$GROUP") || exit 3

# Fresh boots: a withdrawn or wedged node from an earlier lap must not carry
# its state into this one.  Boot to ssh measured ~50 s; 90 s is the bound.
for n in $NODES; do
    timeout 30 virsh -c qemu:///system destroy "$n" >/dev/null 2>&1
    timeout 30 virsh -c qemu:///system start "$n" >/dev/null 2>&1
done
deadline=$(( $(date +%s) + 90 ))
for n in $NODES; do
    until timeout 10 "$SSH" "$n" true </dev/null >/dev/null 2>&1; do
        [ "$(date +%s)" -ge "$deadline" ] && { echo "LAP gate=$GATE: $n not back within 90 s of reset"; exit 3; }
        sleep 2
    done
done
echo "=== LAP gate=$GATE reap=$REAP base=$BASE start $(date -u +%T)Z nodes [$NODES]"
skip="dbg_demoter_keep_skip_ino=BASEINO "
[ "$BASE" = 1 ] && skip=""

# Budget: prep 48-54 s + load SECS + 11 s + collection <=5 s + audit <=83 s,
# measured on the 8/net/mesh/direct g8 laps of 2026-10-01 (max 466 s to the
# verdict at SECS=300), + 6 s for the CORRUPT image copy (measured, 20 GB
# sparse).  A lap past it has a hung rank and fails the fix arm.
budget=$(( SECS + 180 ))
MXFS_EXTRA_MODARGS="demoter_bypass_grant_gate=$GATE demoter_dead_claim_reap=$REAP" \
RANK1_SYSFS="${skip}dbg_demoter_keep_inject=200" \
    timeout "$budget" "$REPO/tests/stress_rmdir_mkdir_race.sh" "$CONFIG" "$GROUP" "$SECS" 200 mkdir
rc=$?
echo "=== LAP gate=$GATE rc=$rc end $(date -u +%T)Z"
E=$(ls -dt "$REPO"/tests/evidence/stress_rmrace_*-"$GROUP"-mkdir | head -n 1)
echo "evidence $E"

# Per-node scoring counts, from the lines the harness followed live into
# <node>.watch: the kernel ring wraps long before the lap ends under this load,
# so a dmesg read afterwards counts 0 whatever happened.
for n in $NODES; do
    w="$E/$n.watch"
    printf '  %s gate=%s reap=%s mounted=%s reaped=%s inject=%s nogrant0=%s nogrant1=%s p177dir=%s wedge=%s withdraw=%s\n' "$n" \
        "$(timeout 15 "$SSH" "$n" 'cat /sys/module/mxfs/parameters/demoter_bypass_grant_gate' </dev/null 2>/dev/null)" \
        "$(timeout 15 "$SSH" "$n" 'cat /sys/module/mxfs/parameters/demoter_dead_claim_reap' </dev/null 2>/dev/null)" \
        "$(timeout 15 "$SSH" "$n" 'mountpoint -q /mnt/shared && echo 1 || echo 0' </dev/null 2>/dev/null)" \
        "$(grep -c 'P-DEMOTER-DEAD-REAP ino' "$w" 2>/dev/null)" \
        "$(grep -c 'P-DEMOTER-KEEP-INJECT ino' "$w" 2>/dev/null)" \
        "$(grep -cE 'P-DEMOTER-NOGRANT .* gate=0 ' "$w" 2>/dev/null)" \
        "$(grep -cE 'P-DEMOTER-NOGRANT .* gate=1 ' "$w" 2>/dev/null)" \
        "$(grep -cE 'P177-OBLIGATION-DROPPED-AT-ADOPT .* mode=04' "$w" 2>/dev/null)" \
        "$(grep -c 'P-INODE-WEDGE ino' "$w" 2>/dev/null)" \
        "$(grep -c 'P-WITHDRAW ' "$w" 2>/dev/null)"
done
for n in $NODES; do
    printf '  %s base_lines=%s base_nogrant=%s\n' "$n" \
        "$(zcat "$E/base_$n.txt.gz" 2>/dev/null | wc -l)" \
        "$(zcat "$E/base_$n.txt.gz" 2>/dev/null | grep -c P-DEMOTER-NOGRANT)"
done
exit "$rc"
