#!/bin/bash
# intents_classless_attribute.sh — D-FOREIGN-SLICE-INTENTS-ABANDONED instrumented
# step (sess467): WHY are the images of an EFI-driven fragmented-file free
# classless?
#
# Chain 93 (0.63.0) measured the victim's rm transactions as buf_items=37
# tokened=37 ag=3 classless=34, every classless token st=4 (MISLABELLED):
# 39 one-block images in contiguous runs (bmbt blocks) and 2 x 32-sector
# images (inode clusters) across the three rolled chains.  MISLABELLED is
# the wire flattening of every non-durable inode-arm outcome, so the
# replayer cannot say which of NOOWNER / UNCACHED / STALE / NONE / UNPUB /
# RELEASING produced them.  The producer can: 0.64.1 prints one
# P239-OWNAUTH-NONDUR line per non-durable capture (bounded per outcome)
# with blkno/len/blft/outcome/ino/mode/comm.
#
# This lap reproduces the burst arm's workload on ONE live node with no
# destroy: build fragmented files, remove them, let inactivation finish, and
# harvest the producer's attribution lines.  The classification happens at
# first dirty on the producer, independent of whether the node later dies,
# so the population it names is exactly the population the burst arm's
# replayer refused.
#
# the budget rule (derived): file build 2 x 4096 pwrite ~0.4 s (8 x 0.19 s measured
# sess423 for the 8-file shape); rm + inactivation of 8192 single-block
# extents: each extent free is one deferred roll — allow 20 s; harvest 5 s.
# Caller bound 60 s.
#
# Usage: tests/intents_classless_attribute.sh <label> [node=test1] [files=2]
set -u
LABEL=${1:?label}; V=${2:-test1}; NF=${3:-2}
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd); cd "$REPO"
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_intents_attribute
mkdir -p "$OUT"
fails=0
# rs/rsx/measure/capture_require/value_now_into/window_into (tests/lib/rig.sh):
# every capture a verdict is taken from crosses the boundary in the parent
# shell first; a failed acquisition is an ABORT, never a count of zero or an
# empty value.
. "$(dirname "$0")/lib/rig.sh"
# ck: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS
cnt() { rs 20 "$1" "dmesg | sed -n \"/$MARK/,\\\$p\" | grep -ac '$2'" | tr -dc '0-9'; }

echo "=== intents_classless_attribute label=$LABEL V=$V files=$NF out=$OUT $(date -u +%FT%TZ) ==="
want=$(modinfo mxfs.ko | awk '/^srcversion:/{print $2}')
nsv=$(rs 15 "$V" "cat /sys/module/mxfs/srcversion" | tr -dc 'A-F0-9')
[ "$nsv" = "$want" ] || { echo "ABORT: $V srcversion '$nsv' != tree '$want'"; exit 2; }
[ "$(strings -a mxfs.ko | grep -c 'P239-OWNAUTH-NONDUR')" -ge 1 ] || { echo "ABORT: tree mxfs.ko lacks P239-OWNAUTH-NONDUR (build < 0.64.1)"; exit 2; }
rs 15 "$V" "grep -q ' $MNT mxfs ' /proc/mounts && echo mounted" | grep -q mounted || { echo "ABORT: $MNT not mounted on $V"; exit 2; }

MARK="ATTRIB-$LABEL-$$"
DIR=$MNT/.attrib_$LABEL
# The producer's counters are bounded per outcome (48 each) since boot; a
# node that already spent them on an earlier lap prints nothing new.  Read
# the pre-lap tally so the harvest below can tell "spent" from "none".
pre=$(rs 15 "$V" "dmesg | grep -ac 'P239-OWNAUTH-NONDUR'" | tr -dc '0-9')
echo "  INFO $V pre-lap P239-OWNAUTH-NONDUR lines since boot: ${pre:-0}"
rs 12 "$V" "echo '$MARK' > /dev/kmsg" >/dev/null

T0=$(date +%s)
rs 60 "$V" "mkdir -p $DIR && python3 - <<'EOF'
import os
d='$DIR'
for f in range($NF):
    fd=os.open(os.path.join(d,'frag%d'%f), os.O_CREAT|os.O_WRONLY|os.O_TRUNC, 0o644)
    for i in range(4096):
        os.pwrite(fd, b'\\xa5'*4096, i*8192)
    os.fsync(fd); os.close(fd)
print('ok')
EOF" | grep -q ok || { echo "ABORT: $V fragmented-file build failed"; exit 2; }
value_now_into ext "$V" 20 "$OUT/rv_ext_1.txt" '^[0-9]+$' "ext on $V" "filefrag -v $DIR/frag0 2>/dev/null | grep -ac '^ *[0-9][0-9]*:' || [ \$? = 1 ]"
echo "  INFO frag0 extents=$ext build_wall=$(( $(date +%s) - T0 ))s"
ck "files are fragmented (>=2000 extents)" "$([ "${ext:-0}" -ge 2000 ] && echo yes || echo no)" "yes"
# Baseline: how many non-durable captures did the BUILD itself produce
# (create-time bmbt images under UNPUBLISHED_EX are the known population)?
window_count_into bld "$V" 20 "$MARK" "P239-OWNAUTH-NONDUR" "bld"
echo "  INFO build-phase P239-OWNAUTH-NONDUR lines: ${bld:-0}"
rs 12 "$V" "echo '$MARK-RM' > /dev/kmsg" >/dev/null

T1=$(date +%s)
rs 40 "$V" "for f in $DIR/frag*; do rm -f \$f & done; wait; sync; echo rm_ok" | grep -q rm_ok || { echo "ABORT: rm failed on $V"; exit 2; }
# inactivation runs after unlink returns; the inodegc worker drains on its
# own cadence.  Wait for the frees to settle: the block count recovers.
i=0; while [ $i -lt 20 ]; do
    used=$(rs 10 "$V" "df -k --output=used $MNT | tail -1" | tr -dc '0-9')
    [ -n "$used" ] && [ "$used" -lt $(( NF * 4096 * 4 )) ] && break
    sleep 1; i=$((i+1))
done
echo "  INFO rm+inactivation wall=$(( $(date +%s) - T1 ))s settle_polls=$i used_kb=${used:-?}"

rs 25 "$V" "dmesg | sed -n \"/$MARK/,\\\$p\"" > "$OUT/dmesg_$V.txt" 2>/dev/null
rs 25 "$V" "dmesg | sed -n \"/$MARK-RM/,\\\$p\" | grep -a 'P239-OWNAUTH-NONDUR\|P241-AUTHTRY'" > "$OUT/rm_phase_$V.txt" 2>/dev/null
n_rm=$(grep -ac 'P239-OWNAUTH-NONDUR' "$OUT/rm_phase_$V.txt")
echo "  INFO rm-phase P239-OWNAUTH-NONDUR lines: $n_rm (P241-AUTHTRY: $(grep -ac 'P241-AUTHTRY' "$OUT/rm_phase_$V.txt"))"
if [ "$n_rm" -eq 0 ] && [ "${pre:-0}" -ge 48 ]; then
    echo "  WARN producer's per-outcome caps may be spent (pre=$pre) — reboot/remount $V for a fresh tally"
fi
echo "  --- rm-phase attribution: outcome x blft x comm (count)"
grep -a 'P239-OWNAUTH-NONDUR' "$OUT/rm_phase_$V.txt" | sed 's/.*P239-OWNAUTH-NONDUR //' | \
    awk '{o="";b="";c="";m="";l="";for(i=1;i<=NF;i++){split($i,kv,"=");if(kv[1]=="outcome")o=kv[2];if(kv[1]=="blft")b=kv[2];if(kv[1]=="comm")c=kv[2];if(kv[1]=="mode")m=kv[2];if(kv[1]=="len")l=kv[2]} print "outcome="o" blft="b" len="l" mode="m" comm="c}' | sort | uniq -c | sort -rn | head -20
echo "  --- outcome key: 0 NOOWNER 1 BADAG 2 NOPAG 3 UNCACHED 4 STALE 5 NONE 6 UNPUB 7 RELEASING 8 DURABLE 9 DURABLE_NOEP; blft 4=BTREE 8=DINODE"
ck "rm phase produced attributable non-durable captures" "$([ "$n_rm" -ge 1 ] && echo yes || echo no)" "yes"
echo "=== $( [ $fails -eq 0 ] && echo "VERDICT PASS" || echo "VERDICT FAIL fails=$fails") label=$LABEL out=$OUT $(date -u +%FT%TZ) ==="
[ $fails -eq 0 ]
