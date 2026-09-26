#!/bin/bash
# freepub_platter_home_inject.sh — the ONE directed measurement the design-consult
# review of 0.39.6 required (ccmemory ccloop-c7ee71c6-sess431-GPT-ruling-
# freepub-claim + the 0.39.9 review): prove that P55C classifies the home of
# a FREE obligation from the PLATTER, not from the cluster buffer that holds
# this node's own staged mode-0 image, and that the free image then lands
# before the AG unlocks.
#
# Fault: mxfs.freepub_drop_once=1 makes the partial-write mask DROP the next
# claimed free-image sector (P-FREEPUB-INJECT-DROP): the buffer keeps the
# staged mode-0 image, the platter keeps the live predecessor, the flush
# watermark is rolled back and the item re-armed (P187-PUB-REARM).  The
# expected chain on the re-push:
#   P55C-HOME-PLATTER ino=X buf_mode=00 platter_mode=0100644 (buffer != media)
#   P55C-FREE-FLUSH ino=X            (classified from the media: predecessor)
#   P-FREEPUB-CLAIM / P-FREEPUB-WRITE / P-FREEPUB-CLAIM-CLEAR why=durable
#   platter dinode X reads mode 0 (tests/dinode_inject.py show)
# and NO P55C-FREE-HOME for X before the platter write (that would be the
# buffer-image false discharge), no FOREIGN, no DISKLIVE, no shutdown.
#
#   tests/freepub_platter_home_inject.sh <label> [node=test1] [peer=test2]
# Budget (budget): <= 20 x (create+sync+rm+sync ~0.3 s native) + 15 s
# re-push wait + sweeps ~10 s => 60 s; wrapper 120 s.
set -u
LABEL=${1:?label}; NODE=${2:-test1}; PEER=${3:-test2}
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd); cd "$REPO"
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "$NODE"; DEV=$MXFS_DEV_RESOLVED
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_fph_$LABEL
mkdir -p "$OUT"
fails=0
filt() { grep -av '^Unauthorized\|^Warning:\|^If you'; }
ck0() { if [ "$2" = "0" ]; then echo "  PASS $1 (0)"; else echo "  FAIL $1 got=$2 want=0"; fails=$((fails+1)); fi; }
ckn() { if [ "${2:-0}" -gt 0 ] 2>/dev/null; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=${2:-?} want>0"; fails=$((fails+1)); fi; }
# rs: tests/lib/rig.sh (sourced above) provides the same helper; a local copy would shadow it
D="$MNT/.fph_$LABEL"
MARK="FPH-$LABEL-$$"
KNOB=/sys/module/mxfs/parameters/freepub_drop_once
echo "=== freepub_platter_home_inject label=$LABEL node=$NODE peer=$PEER out=$OUT $(date -u +%FT%TZ) ==="
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
kv=$(rs 15 "$NODE" "[ -f $KNOB ] && echo 1 > $KNOB; cat $KNOB 2>/dev/null || echo absent")
[ "$kv" = "1" ] || { echo "ABORT: $NODE $KNOB=$kv (need 1: the 0.39.9 fault-injection knob)"; exit 2; }
echo "  INFO $NODE freepub_drop_once=1 armed; xfs_data_offset=$XOFF"
# 1. free files until the injected drop fires (each rm frees one inode whose
#    free image is staged under a claim; the knob drops the first one)
rs 20 "$NODE" "rm -rf $D; mkdir -p $D && echo ok" | grep -q ok || { echo "ABORT: mkdir $D failed"; exit 2; }
X=""
for i in $(seq 1 20); do
    rs 30 "$NODE" "cd $D && dd if=/dev/zero of=f$i bs=4k count=1 status=none && sync -f . && rm -f f$i && sync -f . && sleep 0.5" >/dev/null
    X=$(rs 20 "$NODE" "journalctl -k -q --since '$MARKTIME' 2>/dev/null | grep -ao 'P-FREEPUB-INJECT-DROP .*ino=[0-9]*' | head -1 | grep -ao 'ino=[0-9]*' | cut -d= -f2")
    [ -n "$X" ] && { echo "  INFO injected drop fired at iteration $i: ino X=$X"; break; }
done
[ -n "$X" ] || { echo "  FAIL the injected drop never fired in 20 frees (knob now: $(rs 10 "$NODE" "cat $KNOB"))"; fails=$((fails+1)); }
# 2. wait for the re-push chain (xfsaild re-pushes the re-armed item)
if [ -n "$X" ]; then
    for w in $(seq 1 30); do
        done_=$(rs 20 "$NODE" "journalctl -k -q --since '$MARKTIME' 2>/dev/null | grep -ac 'P-FREEPUB-CLAIM-CLEAR ino=$X .*why=durable'")
        [ "${done_:-0}" -gt 0 ] && break
        sleep 0.5
    done
    echo "  INFO waited $w x 0.5 s for the re-push chain"
fi
rs 15 "$NODE" "echo 0 > $KNOB; cat $KNOB" > "$OUT/knob_after.txt" 2>&1
echo "  INFO $NODE freepub_drop_once after: $(cat "$OUT/knob_after.txt" | tr -d '\n')"
# 3. platter truth for X
if [ -n "$X" ]; then
    rs 30 "$NODE" "python3 /src/mxfs/tests/dinode_inject.py $DEV $XOFF $X show" > "$OUT/show_after.txt" 2>&1
    sed 's/^/  INFO show: /' "$OUT/show_after.txt"
fi
# evidence + verdicts
for n in $NODE $PEER; do
    rs 30 "$n" "journalctl -k -q --since '$MARKTIME' -o short-monotonic 2>/dev/null" > "$OUT/dmesg_$n.txt"
    echo "  INFO $n lines=$(wc -l < "$OUT/dmesg_$n.txt") tags: $(grep -aoE 'P-FREEPUB-[A-Z-]+|P55C-[A-Z-]+|P187-PUB-REARM|P-DIALLOC-[A-Z-]+|P-CR62|P-CR3-CANCEL|P-SESSION-POISON|P-FREEOB-[A-Z-]+' "$OUT/dmesg_$n.txt" | sort | uniq -c | sort -rn | tr '\n' ' ')"
    ck0 "$n zero P-DIALLOC-DISKLIVE" "$(grep -ac 'P-DIALLOC-DISKLIVE ' "$OUT/dmesg_$n.txt")"
    ck0 "$n zero P55C-FREE-FOREIGN" "$(grep -ac 'P55C-FREE-FOREIGN' "$OUT/dmesg_$n.txt")"
    ck0 "$n zero shutdown signatures" "$(grep -ac 'P-SESSION-POISON\|P-CR3-CANCEL\|P-CR62\|force-shutdown\|Internal error' "$OUT/dmesg_$n.txt")"
    ck0 "$n zero P-FREEPUB-CLAIM-STALE / freepub-stale rollback" "$(grep -ac 'P-FREEPUB-CLAIM-STALE\|cls=freepub-stale' "$OUT/dmesg_$n.txt")"
    m=$(rs 20 "$n" "timeout 10 ls $MNT/. >/dev/null && echo readable")
    [ "$m" = "readable" ] && echo "  PASS $n mount readable" || { echo "  FAIL $n mount not readable"; fails=$((fails+1)); }
done
if [ -n "$X" ]; then
    L="$OUT/dmesg_$NODE.txt"
    grep -a "ino=$X\b" "$L" | grep -a 'P-FREEPUB\|P55C\|P187\|P-FREEOB' | cut -c1-230 | sed 's/^/  CHAIN /'
    ckn "$NODE P-FREEPUB-INJECT-DROP for X" "$(grep -ac "P-FREEPUB-INJECT-DROP .*ino=$X " "$L")"
    ckn "$NODE P187-PUB-REARM for X (dropped sector re-armed, durable not advanced)" "$(grep -ac "P187-PUB-REARM ino=$X " "$L")"
    ckn "$NODE P55C-HOME-PLATTER for X with buf_mode=00 and a LIVE platter mode (buffer != media, classified from media)" "$(grep -ac "P55C-HOME-PLATTER ino=$X buf_mode=00 .*platter_mode=0100644" "$L")"
    # order: no FREE-HOME (buffer-image discharge) for X before its durable clear
    first_home=$(grep -an "P55C-FREE-HOME ino=$X " "$L" | head -1 | cut -d: -f1)
    first_dur=$(grep -an "P-FREEPUB-CLAIM-CLEAR ino=$X .*why=durable" "$L" | head -1 | cut -d: -f1)
    if [ -n "$first_home" ] && { [ -z "$first_dur" ] || [ "$first_home" -lt "$first_dur" ]; }; then echo "  FAIL $NODE P55C-FREE-HOME for X BEFORE its free image landed (buffer image taken as home) line=$first_home dur_line=${first_dur:-none}"; fails=$((fails+1)); else echo "  PASS $NODE no buffer-image FREE-HOME for X before the platter write"; fi
    ckn "$NODE re-push P55C-FREE-FLUSH for X (>= 2: the dropped one and the re-push)" "$(( $(grep -ac "P55C-FREE-FLUSH ino=$X " "$L") - 1 ))"
    ckn "$NODE P-FREEPUB-WRITE for X" "$(grep -ac "P-FREEPUB-WRITE .*ino=$X " "$L")"
    ckn "$NODE P-FREEPUB-CLAIM-CLEAR why=durable for X" "$(grep -ac "P-FREEPUB-CLAIM-CLEAR ino=$X .*why=durable" "$L")"
    ck0 "$NODE P-FREEOB-XRELEASE (AG released with the obligation open)" "$(grep -ac 'P-FREEOB-XRELEASE' "$L")"
    if grep -aq 'magic=4d4e mode=00 ' "$OUT/show_after.txt"; then echo "  PASS platter dinode X=$X reads FREE (mode 0) after the chain"; else echo "  FAIL platter dinode X=$X is not free: $(tail -1 "$OUT/show_after.txt")"; fails=$((fails+1)); fi
fi
rs 20 "$NODE" "rm -rf $D" >/dev/null 2>&1
echo "=== freepub_platter_home_inject RESULT $([ $fails -eq 0 ] && echo PASS || echo FAIL) fails=$fails out=$OUT ==="
[ $fails -eq 0 ]
