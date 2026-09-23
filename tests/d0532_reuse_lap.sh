#!/bin/bash
# tests/d0532_reuse_lap.sh <node> [laps] [label]
#
# D-RECYCLE-DEFERRED-FREE-CORPSE-ILOCK-END-UNPAIRED-EX-HOLDER-UNDERFLOW-0532
# verification arm (sess472).  Shape: on ONE node, with mxfs.ifree_drain_ms=0
# (forces the P128-INACT-DEFER arm: freed dinode undestaged, EX grant kept
# cached, struct inode IRECLAIMABLE with its grant), create a file, rm it,
# create again — the second create reallocates the same inode number and
# xfs_iget recycles the corpse (P139-RECYCLE-UNLINKED).  Before 0.64.16 the
# recycle's xfs_iunlock ran an unpaired mxfs_dlm_ilock_end on the cached grant:
# P71-UNDERFLOW ino=<n> mode=EX comm=<this task>.
# RESULT PASS   >= 1 recycle observed (P139 on the node, the arm exercised its
#               shape) and ZERO P71-UNDERFLOW lines from a non-kworker task
#               after the marker, no splat, no shutdown, knob restored.
# RESULT FAIL   any non-kworker P71-UNDERFLOW, a splat or a shutdown.
# RESULT INCONCLUSIVE  no P139 (the number was not reused; shape not reached).
#
# PEER=<node> (item (c), the in-core half): while V laps, PEER loops cat+stat
# of the same name, so a peer BAST lands on the live inode, on the corpse
# between the unlink and the recycle, or on the reclaimable corpse — the
# timing decides which.  s46a with no peer: P128-INACT-DEFER=0, P4L-ALLOC=0,
# P139=0 (a lone creator takes no grant, so nothing is deferred and nothing
# recycles): the shape needs the peer.  Read from V after the laps, exact
# counters reset before: recycle_bast_dropped (P-RECYCLE-BAST-DROP: the
# recycle cleared a SET bast_pending), recycle_grant_cached / _phantom,
# noino_bast_reclaimable; the peer's round count is reported.
# budget: laps x (create+rm+create) is milliseconds each; 100 laps < 10 s;
# whole arm bound 90 s (the peer loop stops when V removes .go, <= 2 s).
set -u
cd /src/mxfs || exit 1
V=${1:?node}; LAPS=${2:-100}; LABEL=${3:-d0532}
PEER=${PEER:-}
CNTS="p71_underflows recycle_bast_dropped recycle_grant_cached recycle_grant_phantom noino_bast_reclaimable"
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0532_$LABEL
mkdir -p "$OUT"
filt() { grep -av '^Unauthorized\|^Warning:\|^If you'; }
rs() { timeout "$1" $SSH "$2" "$3" 2>/dev/null | filt; }
MARK="D0532-$LABEL-$$"
cnt() { rs 20 "$V" "dmesg | sed -n \"/$MARK/,\\\$p\" | grep -ac '$1'" | tr -dc '0-9'; }
D=$MNT/.d0532_$LABEL
echo "=== d0532_reuse_lap node=$V laps=$LAPS out=$OUT $(date -u +%FT%TZ) ==="
want=$(modinfo mxfs.ko | awk '/^srcversion:/{print $2}')
nsv=$(rs 15 "$V" "cat /sys/module/mxfs/srcversion" | tr -dc 'A-F0-9')
[ "$nsv" = "$want" ] || { echo "RESULT FAIL d0532: $V srcversion '$nsv' != tree '$want'"; exit 2; }
rs 15 "$V" "grep -q ' $MNT mxfs ' /proc/mounts && echo mounted" | grep -q mounted || { echo "RESULT FAIL d0532: $MNT not mounted on $V"; exit 2; }
rs 12 "$V" "echo '$MARK' > /dev/kmsg" >/dev/null
pre=$(rs 12 "$V" "cat /sys/module/mxfs/parameters/ifree_drain_ms" | tr -dc '0-9')
rs 12 "$V" "echo 0 > /sys/module/mxfs/parameters/ifree_drain_ms" >/dev/null
# P71-UNDERFLOW prints at most 300 lines per load, so a line count can only
# under-report; the exact counter (0.87.1) is reset here and read after the
# laps where the build exposes it.
rs 12 "$V" "for c in $CNTS; do [ -w /sys/module/mxfs/parameters/\$c ] && echo 0 > /sys/module/mxfs/parameters/\$c; done; true" >/dev/null
rs 20 "$V" "mkdir -p $D && touch $D/.go && echo goset" | grep -q goset || { echo "RESULT FAIL d0532: could not set up $D on $V"; exit 2; }
peer_rounds=na
if [ -n "$PEER" ]; then
  rs 20 "$PEER" "echo '$MARK' > /dev/kmsg; cd $D && (nohup bash -c 'n=0; while [ -e .go ]; do cat f >/dev/null 2>&1; stat -c %s f >/dev/null 2>&1; n=\$((n+1)); done; echo \$n > .peer_rounds' >/dev/null 2>&1 &) && echo started" | grep -q started || { echo "RESULT FAIL d0532: peer loop on $PEER did not start"; exit 2; }
  sleep 1
fi
T0=$(date +%s)
o=$(rs 60 "$V" "cd $D && for i in \$(seq 1 $LAPS); do echo a > f || echo CREATE_FAIL1; rm -f f; echo b > f || echo CREATE_FAIL2; rm -f f; done; sync; echo laps_done")
W=$(( $(date +%s) - T0 )); echo "$o" > "$OUT/laps.txt"
rs 12 "$V" "echo ${pre:-2000} > /sys/module/mxfs/parameters/ifree_drain_ms" >/dev/null
rs 12 "$V" "rm -f $D/.go" >/dev/null
sleep 2
if [ -n "$PEER" ]; then
  peer_rounds=$(rs 12 "$PEER" "cat $D/.peer_rounds 2>/dev/null" | tr -dc '0-9'); peer_rounds=${peer_rounds:-0}
  rs 30 "$PEER" "dmesg | sed -n \"/$MARK/,\\\$p\"" > "$OUT/dmesg_$PEER.txt"
fi
cnts=$(rs 15 "$V" "for c in $CNTS; do [ -r /sys/module/mxfs/parameters/\$c ] && printf ' %s=%s' \$c \$(cat /sys/module/mxfs/parameters/\$c); done; echo")
rs 30 "$V" "dmesg | sed -n \"/$MARK/,\\\$p\"" > "$OUT/dmesg_$V.txt"
rs 30 "$V" "rm -rf $D" >/dev/null
p139=$(grep -ac 'P139-RECYCLE-UNLINKED' "$OUT/dmesg_$V.txt")
defer=$(grep -ac 'P128-INACT-DEFER' "$OUT/dmesg_$V.txt")
p71lines=$(grep -a 'P71-UNDERFLOW' "$OUT/dmesg_$V.txt" | grep -avc 'comm=kworker')
p71cnt=$(rs 12 "$V" "cat /sys/module/mxfs/parameters/p71_underflows 2>/dev/null" | tr -dc '0-9')
# the counter is exact and includes every task; the line count is the
# fallback on a build without it
if [ -n "$p71cnt" ]; then p71=$p71cnt; else p71=$p71lines; fi
splat=$(grep -aEc 'BUG:|Oops|WARNING: CPU' "$OUT/dmesg_$V.txt")
shut=$(grep -ac 'Filesystem has been shut down\|P-SESSION-POISON\|force-shutdown' "$OUT/dmesg_$V.txt")
echo "  INFO laps=$LAPS wall=${W}s peer=${PEER:-none} peer_rounds=$peer_rounds P128-INACT-DEFER=$defer P139=$p139 p71_underflows=${p71cnt:-na} P71-lines(non-kworker)=$p71lines splat=$splat shutdown=$shut evidence=$OUT/dmesg_$V.txt"
echo "  INFO counters on $V:${cnts} P-RECYCLE-BAST-DROP-lines=$(grep -ac 'P-RECYCLE-BAST-DROP' "$OUT/dmesg_$V.txt") P-RECYCLE-PHANTOM-lines=$(grep -ac 'P-RECYCLE-PHANTOM' "$OUT/dmesg_$V.txt") P-NOINO-RECLAIMABLE-lines=$(grep -ac 'P-NOINO-RECLAIMABLE' "$OUT/dmesg_$V.txt")"
grep -a 'P-RECYCLE-BAST-DROP\|P-RECYCLE-PHANTOM' "$OUT/dmesg_$V.txt" | head -5 | cut -c1-220 | sed 's/^/  /'
grep -a 'P71-UNDERFLOW' "$OUT/dmesg_$V.txt" | grep -av 'comm=kworker' | head -5 | cut -c1-200 | sed 's/^/  /'
echo "$o" | grep -q laps_done || { echo "RESULT FAIL d0532: laps did not complete (wall=${W}s): $(echo "$o" | tail -2 | tr '\n' ' ')"; exit 1; }
echo "$o" | grep -q CREATE_FAIL && { echo "RESULT FAIL d0532: a create failed"; exit 1; }
[ "$p71" = 0 ] && [ "$splat" = 0 ] && [ "$shut" = 0 ] || { echo "RESULT FAIL d0532: P71(non-kworker)=$p71 splat=$splat shutdown=$shut out=$OUT"; exit 1; }
# The shape witness is the exact recycle counter where the build has it: the
# P139 line is print-budgeted per load (s49b: 2000 laps, P139 lines 0 after an
# earlier 200-lap run spent the budget, recycle_grant_cached=3755).
rgc=$(echo "$cnts" | grep -ao 'recycle_grant_cached=[0-9]*' | cut -d= -f2)
recycles=${rgc:-$p139}
[ "${recycles:-0}" -ge 1 ] || { echo "RESULT INCONCLUSIVE d0532: no recycle reached (P139 lines=$p139 recycle_grant_cached=${rgc:-na}; number not reused; defer=$defer) out=$OUT"; exit 3; }
echo "RESULT PASS d0532: $LAPS laps wall=${W}s recycles=$recycles (P139 lines=$p139) defers=$defer P71=0${cnts} out=$OUT"
exit 0
