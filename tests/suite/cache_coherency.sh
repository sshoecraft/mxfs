#!/bin/bash
# cache_coherency — agnostic multi-node coherency test.
#
# No false ENOENT/EEXIST and correct cache coherency under concurrent access.
# Folds the four historical coherency subtests (cross_visibility,
# cross_write_read, rename_visibility, unlink_visibility) — lifted from
# tests/cluster/test_*.sh — into one node-side agnostic test.
#
# Each node runs this body with its own RANK (1..NODES).  Phases rendezvous via
# coord_barrier (MQTT), NOT an on-FS barrier dir: coordinating the test of the
# FS *using* the FS masks the very coherency bugs we are hunting.
#
# Runs on every node; the harness (run.sh) aggregates — PASS iff all nodes pass.
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"

R="$RANK"; T="$NODES"
BASE="$MNT/.cache_coherency"
mkdir -p "$BASE" 2>/dev/null

# ---- subtest 1: cross_visibility — a file created on each node is visible everywhere
D="$BASE/cross_visibility"; mkdir -p "$D" 2>/dev/null
echo "hello from node ${R}" > "$D/node${R}.txt"; sync
echo "mxfs-CCph rank=${R} PHASE=cv-write-done" > /dev/kmsg 2>/dev/null || true
ck   "cv barrier write" coord_barrier "cv_write"
for n in $(seq 1 "$T"); do
    ck   "cv node${R} sees node${n}.txt" test -f "$D/node${n}.txt"
    ckeq "cv node${R} content of node${n}" "hello from node ${n}" "$(cat "$D/node${n}.txt" 2>/dev/null)"
done
echo "mxfs-CCph rank=${R} PHASE=cv-verify-done" > /dev/kmsg 2>/dev/null || true
ck "cv barrier verify" coord_barrier "cv_verify"

# ---- subtest 2: cross_write_read — 1MB random files, round-robin md5 verify
D="$BASE/cross_write_read"; mkdir -p "$D" 2>/dev/null
dd if=/dev/urandom of="/tmp/cwr_${R}" bs=1M count=1 2>/dev/null
cp "/tmp/cwr_${R}" "$D/data_node${R}"; sync
md5sum "/tmp/cwr_${R}" | awk '{print $1}' > "$D/data_node${R}.md5"
rm -f "/tmp/cwr_${R}"
echo "mxfs-CCph rank=${R} PHASE=cwr-write-done" > /dev/kmsg 2>/dev/null || true
ck "cwr barrier write" coord_barrier "cwr_write"
for n in $(seq 1 "$T"); do
    ckeq "cwr node${R} md5 of node${n}" "$(cat "$D/data_node${n}.md5" 2>/dev/null)" \
         "$(md5sum "$D/data_node${n}" 2>/dev/null | awk '{print $1}')"
    ckeq "cwr node${R} size of node${n}" "1048576" "$(stat -c%s "$D/data_node${n}" 2>/dev/null)"
done
echo "mxfs-CCph rank=${R} PHASE=cwr-verify-done" > /dev/kmsg 2>/dev/null || true
ck "cwr barrier verify" coord_barrier "cwr_verify"

# ---- subtest 3: rename_visibility — rename on each node visible everywhere
D="$BASE/rename_visibility"; mkdir -p "$D" 2>/dev/null
# sess1 (ccloop 0220f43f) RULE-4 + GPT consult: RPN was a T-INDEPENDENT
# constant (20/node), so the cross-node verify loop below (every node
# checks every OTHER node's every file) is O(T^2) total cluster work --
# fine at low N, but at T=32 that's 640 renames x 32 verifiers x 3 checks
# = 61440 checks (measured 12.3s rename + 15.6s verify alone), pushing the
# whole 9-phase test past its flat 60s budget under cawp's higher per-op
# DLM latency (cawd/caw had just enough margin to hide the same O(T^2)
# shape -- historical median 56-62s, already razor-thin).  RV_TOTAL is a
# CONSTANT pool size (mirrors dir_reuse_coherency's N-invariant DRC_TOTAL
# rewrite) so per-node count shrinks as T grows and total cluster verify
# work stays O(T) instead of O(T^2); the coherency signal (every node
# still verifies every object: old-gone + new-exists + content) is
# unchanged, just over a bounded pool.
RV_TOTAL="${CC_RV_TOTAL:-128}"
RPN=$(( RV_TOTAL / T > 4 ? RV_TOTAL / T : 4 ))
for i in $(seq 1 "$RPN"); do echo "content_${R}_${i}" > "$D/node${R}_before_${i}"; done
echo "mxfs-CCph rank=${R} PHASE=rv-create-done" > /dev/kmsg 2>/dev/null || true
ck "rv barrier create" coord_barrier "rv_create"
for i in $(seq 1 "$RPN"); do mv "$D/node${R}_before_${i}" "$D/node${R}_after_${i}"; done
sync
echo "mxfs-CCph rank=${R} PHASE=rv-rename-done" > /dev/kmsg 2>/dev/null || true
ck "rv barrier rename" coord_barrier "rv_rename"
for n in $(seq 1 "$T"); do
    for i in $(seq 1 "$RPN"); do
        ck   "rv old gone node${n}_before_${i}" test ! -e "$D/node${n}_before_${i}"
        ck   "rv new exists node${n}_after_${i}" test -f "$D/node${n}_after_${i}"
        ckeq "rv content node${n}_after_${i}" "content_${n}_${i}" "$(cat "$D/node${n}_after_${i}" 2>/dev/null)"
    done
done
echo "mxfs-CCph rank=${R} PHASE=rv-verify-done" > /dev/kmsg 2>/dev/null || true
ck "rv barrier verify" coord_barrier "rv_verify"

# ---- subtest 4: unlink_visibility — unlink on each node visible everywhere
D="$BASE/unlink_visibility"
# sess1 (ccloop 0220f43f) RULE-4 PROVEN: this subtest never cleared its dir
# on entry, only at its own uv-delete phase -- a run killed mid-test (e.g.
# a pace timeout in an earlier phase) leaves its uv-create'd files behind,
# and the NEXT run's "uv all files present"/"uv none remain" TOTAL-COUNT
# asserts then count the stale files too and false-fail (live-caught this
# session: exp=128 got=328, exp=0 got=200, after repeated pace-diagnosis
# runs).  Same class as this project's posix_multi "rank1 wipes dir at
# start" precedent.  rank1 clears before anyone creates; the barrier sits
# BETWEEN the rm and the mkdir (not after both) so no node's mkdir can
# race rank1's still-in-flight rm -rf.
[ "$R" = 1 ] && rm -rf "$D"
ck "uv barrier reset" coord_barrier "uv_reset"
mkdir -p "$D" 2>/dev/null
# sess1 (ccloop 0220f43f): same O(T^2)->O(T) fix as rename_visibility above
# (FPN was T-independent; UV_TOTAL keeps the pool constant so per-node
# count shrinks as T grows -- see the rename_visibility comment for the
# full rationale/measurements).
UV_TOTAL="${CC_UV_TOTAL:-128}"
FPN=$(( UV_TOTAL / T > 4 ? UV_TOTAL / T : 4 ))
for i in $(seq 1 "$FPN"); do echo "delete_me_${R}_${i}" > "$D/node${R}_file${i}"; done
echo "mxfs-CCph rank=${R} PHASE=uv-create-done" > /dev/kmsg 2>/dev/null || true
ck "uv barrier create" coord_barrier "uv_create"
if [ "$R" = 1 ]; then
    ckeq "uv all files present pre-delete" "$((T * FPN))" "$(ls "$D"/node*_file* 2>/dev/null | wc -l | tr -d ' ')"
fi
ck "uv barrier preverify" coord_barrier "uv_preverify"
for i in $(seq 1 "$FPN"); do rm -f "$D/node${R}_file${i}"; done
sync
echo "mxfs-CCph rank=${R} PHASE=uv-delete-done" > /dev/kmsg 2>/dev/null || true
ck "uv barrier delete" coord_barrier "uv_delete"
for n in $(seq 1 "$T"); do
    for i in $(seq 1 "$FPN"); do
        ck "uv gone node${n}_file${i}" test ! -e "$D/node${n}_file${i}"
    done
done
ckeq "uv none remain" "0" "$(ls "$D"/node*_file* 2>/dev/null | wc -l | tr -d ' ')"
echo "mxfs-CCph rank=${R} PHASE=uv-verify-done" > /dev/kmsg 2>/dev/null || true
ck "uv barrier verify" coord_barrier "uv_verify"

coord_done "$([ "$FAIL_N" -eq 0 ] && echo PASS || echo FAIL)"
finish
