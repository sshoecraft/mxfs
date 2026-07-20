#!/bin/bash
# dlm_scaling — DLM lock-operation throughput scaling across N nodes.
#
# Each node drives a fixed number of metadata ops that each take + release the
# per-inode / per-dir DLM lock (create+stat+unlink in its OWN private subdir =
# disjoint resources).  A correctly-scaling DLM must NOT cross-serialize
# independent locks, so every node should clear its quota quickly via the
# local cache-hit path.  PASS iff every node completes ALL ops within the time
# budget AND sustains an op-rate floor, and the aggregate op-rate exceeds the
# fastest single node (positive scaling).
#
# RULE 0: native XFS does create+stat+unlink in tens of microseconds; OPS ops
# must finish well within WINDOW.  A node that cannot is a DLM scaling FAIL.
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"

R="$RANK"; T="$NODES"
D="$MNT/.dlm_scaling/node${R}"
# sess13: the got=0 face = this node's own subdir becoming unresolvable.  All
# T nodes race `mkdir -p` on the SAME fresh shortform parent here, the exact
# concurrent-add pattern of the dir-block/shortform stale-base swallow.  Keep
# mkdir's rc and check immediate visibility so the artifact distinguishes
# create-FAILED from created-then-SWALLOWED.
mkdir -p "$D" 2>/dev/null; mk_rc=$?
if ! stat "$D" >/dev/null 2>&1; then
    echo "ds node${R} POSTMKDIR-INVISIBLE mk_rc=$mk_rc parent_ls=[$(ls "$MNT/.dlm_scaling" 2>/dev/null | tr '\n' ' ')]" >&2
fi

OPS="${DLM_SCALING_OPS:-2000}"
WINDOW="${DLM_SCALING_WINDOW:-60}"
# Per-node ops/sec floor — a COLLAPSE detector (wedged/starved node), not an
# exact-pace assertion.  Derivation (2026-07-18, measured):
#   N<=16: 50 keeps >=40% headroom (16/caw median ~71 ops/s).
#   N=32:  two independent rigs put the healthy per-node band AT the old 50
#          floor — direct-iSCSI 48-58 (all 32 nodes, tight unimodal band,
#          median 54) and dm-multipath ~50-58 — because the structural CAW
#          per-op durable-publish pace (~19-21 ms/op, adjudicated
#          load-bearing for dir coherency in the 0.10.x ladder work) is
#          ~50/s.  A floor equal to the structural pace has zero headroom
#          and fails the tail of a healthy band, so for N>16 the default is
#          30 (~55% of the 32-node median): a node under it is genuinely
#          degraded, not unlucky.  DLM_SCALING_FLOOR_OPS still overrides.
if [ -n "${DLM_SCALING_FLOOR_OPS:-}" ]; then
    FLOOR_OPS="$DLM_SCALING_FLOOR_OPS"
elif [ "$T" -gt 16 ]; then
    FLOOR_OPS=30
else
    FLOOR_OPS=50
fi

ck "ds barrier ready" coord_barrier "ds_ready"

t0=$(date +%s.%N)
done_ops=0
: > "/tmp/dsc_checkpoints_${R}.log"
for i in $(seq 1 "$OPS"); do
    f="$D/f${i}"
    if [ $((i % 200)) -eq 0 ]; then
        tN=$(date +%s.%N)
        awk "BEGIN{printf \"i=%d t=%.3f\n\", $i, $tN-$t0}" >> "/tmp/dsc_checkpoints_${R}.log"
    fi
    { : > "$f" && stat "$f" >/dev/null 2>&1 && rm -f "$f"; } || {
        # sess13 one-shot forensics at the FIRST failed op: is the own-subdir
        # dirent still in the parent?  Dump the parent's dir blocks + DLM
        # state (P10-DIRDUMP magic lookup) and snapshot dmesg to /root — the
        # drc_blkdump_* glob in run.sh pulls it into the host artifact.
        echo "ds node${R} FIRSTFAIL i=$i own_stat=$(stat -c %i "$D" 2>&1 | head -1) parent_ls=[$(ls "$MNT/.dlm_scaling" 2>/dev/null | tr '\n' ' ')]" >&2
        pd="/root/drc_blkdump_dsc_node${R}"
        mkdir -p "$pd" 2>/dev/null
        [ -e "$MNT/.dlm_scaling/.mxfs_dirdump1" ] 2>/dev/null || true
        dmesg | tail -n 4000 > "$pd/dmesg_at_fail.txt" 2>/dev/null || true
        break
    }
    done_ops=$i
done
t1=$(date +%s.%N)
elapsed=$(awk "BEGIN{e=$t1-$t0; print (e>0)?e:0.001}")
rate=$(awk "BEGIN{printf \"%d\", $done_ops/$elapsed}")
sync

ckeq "ds node${R} completed quota" "$OPS" "$done_ops"
ck   "ds node${R} within window"  awk "BEGIN{exit !($elapsed <= $WINDOW)}"
[ "$rate" -ge "$FLOOR_OPS" ] || echo "ds node${R} rate=$rate floor=$FLOOR_OPS elapsed=${elapsed}s done=$done_ops" >&2
ck   "ds node${R} rate>=floor"    test "$rate" -ge "$FLOOR_OPS"

coord_put "dsrate_${R}" "$rate"
ck "ds barrier wrote" coord_barrier "ds_wrote"

if [ "$R" = 1 ]; then
    agg=0; maxr=0
    for n in $(seq 1 "$T"); do
        r=$(coord_get "dsrate_${n}" 30 2>/dev/null); r=${r:-0}
        agg=$((agg + r)); [ "$r" -gt "$maxr" ] && maxr="$r"
    done
    echo "DLM-SCALING: nodes=$T aggregate_ops_s=$agg max_single=$maxr" >&2
    # See scaling_curve.sh: always-false at T=1 by construction, not a signal.
    [ "$T" -gt 1 ] && ck "ds aggregate > max single" test "$agg" -gt "$maxr"
fi

ck "ds barrier done" coord_barrier "ds_done"
coord_done "$([ "$FAIL_N" -eq 0 ] && echo PASS || echo FAIL)"
finish
