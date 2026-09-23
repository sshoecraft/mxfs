#!/bin/bash
# dialloc_disklive_inject.sh — instrumented harness for the D-0351 dialloc
# CONTAINMENT (two-phase candidate validation, 0.39.3; design-consult ruling ccmemory
# docs/rulings/d0351-dialloc-containment-two-phase.md).
#
# Plants the fault the containment must absorb: an inode number the inobt
# says is FREE whose platter dinode reads LIVE (a crossed FREE-PUBLISH
# invariant on some node).  Then makes the node allocate in that
# neighbourhood.
#   pre-containment (<= 0.39.2): dialloc hands the number out, xfs_iget finds
#     the live image -> P-CR62 DISK-LIVE -> dirty xfs_trans_cancel -> the
#     NODE SHUTS DOWN (the create returns EIO, the mount is dead).
#   with containment: P-DIALLOC-DISKLIVE ino=<X> ... quarantined, the create
#     takes another number, no shutdown, the mount stays healthy, X is never
#     handed out on that node again.
#
#   tests/dialloc_disklive_inject.sh <label> [node=test1] [peer=test2] [files=16]
#   MXFS_DIALLOC_VALIDATE=0  — A/B arm: turns the containment OFF on <node>
#     (/sys/module/mxfs/parameters/dialloc_validate) for the create step and
#     back ON afterwards; expected FAIL (the pre-containment shutdown).
#
# Steps (node): mkdir D; f0 = create+sync (ino X, live on platter); rm f0;
# sync + 2 s (the free image reaches the platter: verified by reading X's
# home with tests/dinode_inject.py — the test ABORTs if X is not free on the
# platter, so it never overwrites a live inode); setlive X (mode 0100644,
# fresh gen, crc resealed); then create <files> files in D and record their
# inos; then restore X to free (setfree) so the volume is consistent again.
# Verdict: FAIL on any shutdown signature / P-CR62 / P-CR63-DEFER-DISKLIVE
# on the node, on any create error, on any created file receiving ino X, on
# an unreadable mount on node or peer; INFO the P-DIALLOC-DISKLIVE count.
# Budget (budget): 16 creates + 4 syncs ~ 1 s native; sweeps ~ 10 s.
set -u
LABEL=${1:?label}; NODE=${2:-test1}; PEER=${3:-test2}; NFILES=${4:-16}
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd); cd "$REPO"
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "$NODE"; DEV=$MXFS_DEV_RESOLVED
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_ddl_$LABEL
mkdir -p "$OUT"
fails=0
filt() { grep -av '^Unauthorized\|^Warning:\|^If you'; }
ck0() { if [ "$2" = "0" ]; then echo "  PASS $1 (0)"; else echo "  FAIL $1 got=$2 want=0"; fails=$((fails+1)); fi; }
# rs: tests/lib/rig.sh (sourced above) provides the same helper; a local copy would shadow it
D="$MNT/.ddl_$LABEL"
MARK="DDL-$LABEL-$$"
echo "=== dialloc_disklive_inject label=$LABEL node=$NODE peer=$PEER files=$NFILES out=$OUT $(date -u +%FT%TZ) ==="
want=$(modinfo mxfs.ko | awk '/^srcversion:/{print $2}')
for n in $NODE $PEER; do
    nsv=$(rs 15 "$n" "cat /sys/module/mxfs/srcversion" | tr -dc 'A-F0-9')
    [ "$nsv" = "$want" ] || { echo "ABORT: $n srcversion '$nsv' != tree '$want'"; exit 2; }
    rs 12 "$n" "echo '$MARK' > /dev/kmsg" >/dev/null
    m=$(rs 20 "$n" "mountpoint -q $MNT && mount | grep -q ' on $MNT type mxfs ' && timeout 10 ls $MNT/. >/dev/null && echo mounted")
    [ "$m" = "mounted" ] || { echo "ABORT: $n does not have an mxfs mount at $MNT (prep the cluster first)"; exit 2; }
done
MARKTIME=$(date -u '+%Y-%m-%d %H:%M:%S')
XOFF=$(rs 60 "$NODE" "/src/mxfs/tools/chk_mxfs -v $DEV 2>/dev/null | grep -ao 'xfs_data_offset=[0-9]*' | cut -d= -f2")
[ -n "$XOFF" ] || { echo "ABORT: could not read xfs_data_offset from chk_mxfs on $NODE"; exit 2; }
echo "  INFO xfs_data_offset=$XOFF"
# 1. a freed number whose free image is on the platter
X=$(rs 40 "$NODE" "rm -rf $D; mkdir $D && cd $D && dd if=/dev/zero of=f0 bs=4k count=1 status=none && sync -f . && x=\$(stat -c %i f0) && rm -f f0 && sync -f . && sleep 2 && sync && echo \$x")
[ -n "$X" ] || { echo "ABORT: could not create/free the seed inode on $NODE"; exit 2; }
echo "  INFO seed ino X=$X dir=$D"
rs 30 "$NODE" "python3 /src/mxfs/tests/dinode_inject.py $DEV $XOFF $X show" > "$OUT/show_before.txt" 2>&1
sed 's/^/  INFO show: /' "$OUT/show_before.txt"
grep -aq 'before magic=494e mode=00 ' "$OUT/show_before.txt" || { echo "ABORT: X=$X is not FREE on the platter (free image not published yet, or not an IN slot) — refusing to inject over it"; cat "$OUT/show_before.txt"; exit 2; }
# 2. plant the live image
GEN=$(( (RANDOM << 15 | RANDOM) & 0x7fffffff ))
rs 30 "$NODE" "python3 /src/mxfs/tests/dinode_inject.py $DEV $XOFF $X setlive $GEN" > "$OUT/inject.txt" 2>&1
sed 's/^/  INFO inject: /' "$OUT/inject.txt"
grep -aq "after magic=494e mode=0100644 nlink=1 gen=$GEN crc=0x[0-9a-f]* crc_ok=1" "$OUT/inject.txt" || { echo "  FAIL injection did not verify"; fails=$((fails+1)); }
# 2b. drop the seed's cached shell (s437pre on 0.39.2: with the shell still
#     cached the create took the cache-HIT recycle path, never read the
#     platter, and silently clobbered the planted live image — the data-loss
#     arm of D-0351; the shutdown arm is the cache-MISS create, which is what
#     a peer, or this node after reclaim, does)
rs 40 "$NODE" "sync; echo 2 > /proc/sys/vm/drop_caches; sleep 1; echo 2 > /proc/sys/vm/drop_caches; echo dropped" > "$OUT/drop.txt" 2>&1
grep -q dropped "$OUT/drop.txt" || { echo "  FAIL drop_caches step did not complete"; fails=$((fails+1)); }
# 3. allocate in the neighbourhood (A/B: the containment knob on this node)
KNOB=/sys/module/mxfs/parameters/dialloc_validate
V=${MXFS_DIALLOC_VALIDATE:-1}
kv=$(rs 15 "$NODE" "[ -f $KNOB ] && echo $V > $KNOB; cat $KNOB 2>/dev/null || echo absent")
echo "  INFO $NODE dialloc_validate=$kv (requested $V)"
rs 60 "$NODE" "cd $D && bad=0; i=0; while [ \$i -lt $NFILES ]; do : > g\$i || bad=\$((bad+1)); i=\$((i+1)); done; sync -f . 2>/dev/null; echo create_bad=\$bad; stat -c %i g* 2>/dev/null | sort -n | tr '\n' ' '; echo" > "$OUT/creates.txt" 2>&1
rs 15 "$NODE" "[ -f $KNOB ] && echo 1 > $KNOB" >/dev/null 2>&1
sed 's/^/  INFO creates: /' "$OUT/creates.txt"
cbad=$(grep -ao 'create_bad=[0-9]*' "$OUT/creates.txt" | cut -d= -f2)
ck0 "$NODE create errors" "${cbad:-999}"
gotx=$(grep -av 'create_bad' "$OUT/creates.txt" | tr ' ' '\n' | grep -acx "$X")
ck0 "$NODE created files receiving the DISK-LIVE number X=$X" "$gotx"
# 4. restore X to free on the platter (the inobt never changed) — only if the
#    node is still alive; a dead node's mount cannot be trusted but the device
#    write itself is independent of the mount
rs 30 "$NODE" "python3 /src/mxfs/tests/dinode_inject.py $DEV $XOFF $X setfree" > "$OUT/restore.txt" 2>&1
sed 's/^/  INFO restore: /' "$OUT/restore.txt" | tail -1
# evidence
for n in $NODE $PEER; do
    rs 30 "$n" "journalctl -k -q --since '$MARKTIME' -o short-monotonic 2>/dev/null || dmesg | sed -n '/$MARK/,\$p'" > "$OUT/dmesg_$n.txt"
    echo "  INFO $n lines=$(wc -l < "$OUT/dmesg_$n.txt") tags: $(grep -aoE 'P-DIALLOC-[A-Z-]+|P-CR62|P-CR63-[A-Z-]+|P-CR3-CANCEL|P-SESSION-POISON|P55C-FREE-[A-Z-]+|P-FREEOB-[A-Z-]+|P-IALLOC-DBLALLOC' "$OUT/dmesg_$n.txt" | sort | uniq -c | sort -rn | tr '\n' ' ')"
    ck0 "$n zero P-CR62 DISK-LIVE" "$(grep -ac 'P-CR62 .*DISK-LIVE' "$OUT/dmesg_$n.txt")"
    ck0 "$n zero P-CR63-DEFER-DISKLIVE" "$(grep -ac 'P-CR63-DEFER-DISKLIVE' "$OUT/dmesg_$n.txt")"
    ck0 "$n zero shutdown signatures" "$(grep -ac 'Filesystem has been shut down\|xfs_do_force_shutdown\|P-SESSION-POISON\|P-CR3-CANCEL' "$OUT/dmesg_$n.txt")"
    m=$(rs 20 "$n" "mountpoint -q $MNT && timeout 10 ls $MNT/. >/dev/null && echo readable")
    if [ "$m" = "readable" ]; then echo "  PASS $n mount readable"; else echo "  FAIL $n mount not readable"; fails=$((fails+1)); fi
done
dl=$(grep -ac "P-DIALLOC-DISKLIVE ino=$X " "$OUT/dmesg_$NODE.txt")
echo "  INFO $NODE P-DIALLOC-DISKLIVE for X: $dl (containment engaged when > 0)"
[ "$dl" -gt 0 ] || echo "  WARN the containment verdict did not fire for X (pre-containment build, or X was not picked)"
rs 30 "$NODE" "rm -rf $D" >/dev/null 2>&1
echo "=== dialloc_disklive_inject RESULT $([ $fails -eq 0 ] && echo PASS || echo FAIL) fails=$fails out=$OUT ==="
[ $fails -eq 0 ]
