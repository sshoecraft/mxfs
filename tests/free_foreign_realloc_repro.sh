#!/bin/bash
# free_foreign_realloc_repro.sh — instrumented reproducer for the s433 (0.39.0)
# P55C-FREE-FOREIGN population (164 events on a clean board, uncategorized).
#
# Hypothesis (sess430): a same-node free -> recycle-create -> free chain
# whose middle incarnation never reached the platter ends in a FOREIGN verdict
# against this node's OWN older live image:
#   life 1: create f (gen G), sync  -> platter holds LIVE gen G
#   rm f                            -> FREE obligation {gen G+1}, unpublished
#   life 2: create f (same ino, xfs_iget_recycle: XFS_IRECLAIM_RESET_FLAGS
#           clears MXFS_IF_PUBOB; the store entry keeps kind=FREE) gen R,
#           never flushed
#   rm f                            -> FREE obligation {gen R+1}
#   flush (P55C): platter mode!=0, disk_gen G != R -> "FOREIGN": never write,
#           discharge.  Result: inobt says free, platter says LIVE gen G.
#   peer create of that number      -> P-CR62 DISK-LIVE / P-CR63-DEFER-DISKLIVE
#           -> -EFSCORRUPTED after dialloc dirtied the tp -> peer shutdown.
#
#   tests/free_foreign_realloc_repro.sh <label> [node=test1] [files=100] [peer=test2]
#
# Phase A (node): N x { dd f; sync; rm f; dd f; rm f } in a private dir,
#   recording the inode number of both lives (same ino = the recycle path was
#   taken).  Then sync + drop_caches so xfsaild flushes the freed shells.
# Phase B (peer): create 4 x N files in the SAME dir so the peer's dialloc
#   reallocates the freed numbers.
# Verdict:
#   INFO  same-ino chains, P55C-FREE-FOREIGN count on node and the ino overlap
#         between the FOREIGN inos and the chain inos (the hypothesis' signature)
#   FAIL  any P55C-FREE-FOREIGN whose ino is a chain ino (own image misread as
#         foreign), any P-CR62 / P-CR63-DEFER-DISKLIVE / shutdown on the peer,
#         any peer create error, mount unreadable on node or peer.
# Budget (budget): N=100 x (dd+sync+rm+dd+rm) ~ 100 x 60 ms = 6 s native;
#   drop_caches wait 8 s; peer creates 400 x ~3 ms ~ 1.2 s.  Timeouts below
#   are 2x those plus ssh.
set -u
LABEL=${1:?label}; NODE=${2:-test1}; NFILES=${3:-100}; PEER=${4:-test2}
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd); cd "$REPO"
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_ffr_$LABEL
mkdir -p "$OUT"
fails=0
filt() { grep -av '^Unauthorized\|^Warning:\|^If you'; }
ck0() { if [ "$2" = "0" ]; then echo "  PASS $1 (0)"; else echo "  FAIL $1 got=$2 want=0"; fails=$((fails+1)); fi; }
rs() { timeout "$1" $SSH "$2" "$3" 2>/dev/null | filt; }
D="$MNT/.ffr_$LABEL"
MARK="FFR-$LABEL-$$"
echo "=== free_foreign_realloc_repro label=$LABEL node=$NODE peer=$PEER files=$NFILES out=$OUT $(date -u +%FT%TZ) ==="
want=$(modinfo mxfs.ko | awk '/^srcversion:/{print $2}')
for n in $NODE $PEER; do
    nsv=$(rs 15 "$n" "cat /sys/module/mxfs/srcversion" | tr -dc 'A-F0-9')
    [ "$nsv" = "$want" ] || { echo "ABORT: $n srcversion '$nsv' != tree '$want'"; exit 2; }
    rs 12 "$n" "echo '$MARK' > /dev/kmsg" >/dev/null
    m=$(rs 20 "$n" "mountpoint -q $MNT && mount | grep -q ' on $MNT type mxfs ' && timeout 10 ls $MNT/. >/dev/null && echo mounted")
    [ "$m" = "mounted" ] || { echo "ABORT: $n does not have an mxfs mount at $MNT (prep the cluster first)"; exit 2; }
done
MARKTIME=$(date -u '+%Y-%m-%d %H:%M:%S')
# Phase A — the chain.  Both lives' inode numbers are printed per iteration:
#   "chain <i> <ino1> <ino2>"
wl=$(( NFILES * 120 / 1000 + 30 ))
rs $wl "$NODE" "rm -rf $D; mkdir $D && cd $D && s=\$(date +%s%3N); i=0; bad=0; while [ \$i -lt $NFILES ]; do dd if=/dev/zero of=f\$i bs=4k count=1 status=none || bad=\$((bad+1)); sync -f . ; a=\$(stat -c %i f\$i); rm -f f\$i || bad=\$((bad+1)); dd if=/dev/zero of=f\$i bs=4k count=1 status=none || bad=\$((bad+1)); b=\$(stat -c %i f\$i); rm -f f\$i || bad=\$((bad+1)); echo chain \$i \$a \$b; i=\$((i+1)); done; echo workload_ms=\$(( \$(date +%s%3N) - s )) bad=\$bad" > "$OUT/workload.txt" 2>&1
grep -v '^chain' "$OUT/workload.txt" | sed 's/^/  INFO /'
bad=$(grep -o 'bad=[0-9]*' "$OUT/workload.txt" | cut -d= -f2)
ck0 "workload errors" "${bad:-999}"
chains=$(grep -c '^chain' "$OUT/workload.txt")
same=$(awk '$1=="chain" && $3==$4' "$OUT/workload.txt" | wc -l)
awk '$1=="chain" && $3==$4 {print $3}' "$OUT/workload.txt" | sort -u > "$OUT/chain_inos.txt"
echo "  INFO chains=$chains same_ino_chains=$same distinct_chain_inos=$(wc -l < "$OUT/chain_inos.txt")"
[ "$same" -gt 0 ] || echo "  WARN no chain reused its inode number: the recycle path was not exercised (no verdict)"
# force the flushes of the freed shells (P55C runs in xfs_iflush under xfsaild)
rs 40 "$NODE" "sync; echo 2 > /proc/sys/vm/drop_caches; sleep 3; sync; echo 2 > /proc/sys/vm/drop_caches; sleep 5; echo flush_done" > "$OUT/flush.txt" 2>&1
grep -q flush_done "$OUT/flush.txt" || { echo "  FAIL flush step did not complete: $(cat "$OUT/flush.txt")"; fails=$((fails+1)); }
rs 30 "$NODE" "journalctl -k -q --since '$MARKTIME' -o short-monotonic 2>/dev/null || dmesg | sed -n '/$MARK/,\$p'" > "$OUT/dmesg_${NODE}_A.txt"
grep -ao 'P55C-FREE-FOREIGN ino=[0-9]*' "$OUT/dmesg_${NODE}_A.txt" | awk '{print $2}' | cut -d= -f2 | sort -u > "$OUT/foreign_inos.txt"
nfor=$(grep -ac 'P55C-FREE-FOREIGN' "$OUT/dmesg_${NODE}_A.txt")
overlap=$(comm -12 "$OUT/chain_inos.txt" "$OUT/foreign_inos.txt" | wc -l)
echo "  INFO $NODE phase A tags: $(grep -aoE 'P55C-FREE-[A-Z-]+|P-FREEOB-[A-Z-]+|P-RECYCLE-[A-Z-]+|P128-INACT-DEFER|P32D-DEADINCARN-SKIP' "$OUT/dmesg_${NODE}_A.txt" | sort | uniq -c | sort -rn | tr '\n' ' ')"
echo "  INFO $NODE P55C-FREE-FOREIGN=$nfor distinct_inos=$(wc -l < "$OUT/foreign_inos.txt") overlap_with_chain_inos=$overlap"
if [ "$nfor" -gt 0 ]; then
    # gen arithmetic per FOREIGN line: disk_gen vs gen (older / newer / equal)
    grep -ao 'P55C-FREE-FOREIGN ino=[0-9]* gen=[0-9]* disk_gen=[0-9]* disk_mode=0[0-7]*' "$OUT/dmesg_${NODE}_A.txt" | \
      awk '{split($3,g,"=");split($4,d,"=");x=(d[2]-g[2]); if (x>2147483647) x-=4294967296; if (x<-2147483648) x+=4294967296; if (x<-1) o++; else if (x>0) n++; else e++} END{printf "  INFO foreign gen delta: older=%d newer=%d equal_or_pred=%d\n", o,n,e}'
fi
ck0 "$NODE zero FOREIGN verdicts on this node's own chain inos" "$overlap"
# Phase B — the peer reallocates the numbers
pl=$(( NFILES * 4 * 6 / 1000 + 30 ))
rs $pl "$PEER" "cd $D && s=\$(date +%s%3N); i=0; bad=0; while [ \$i -lt $((NFILES*4)) ]; do : > p\$i || bad=\$((bad+1)); i=\$((i+1)); done; sync -f .; echo peer_ms=\$(( \$(date +%s%3N) - s )) bad=\$bad; stat -c %i p* | sort -u > /tmp/ffr_peer_inos.$$; wc -l < /tmp/ffr_peer_inos.$$; cat /tmp/ffr_peer_inos.$$; rm -f /tmp/ffr_peer_inos.$$" > "$OUT/peer.txt" 2>&1
grep 'peer_ms' "$OUT/peer.txt" | sed 's/^/  INFO /'
pbad=$(grep -o 'bad=[0-9]*' "$OUT/peer.txt" | cut -d= -f2)
ck0 "$PEER create errors" "${pbad:-999}"
grep -E '^[0-9]+$' "$OUT/peer.txt" | sort -u > "$OUT/peer_inos.txt"
echo "  INFO $PEER reallocated $(comm -12 "$OUT/chain_inos.txt" "$OUT/peer_inos.txt" | wc -l) of the chain inos, $(comm -12 "$OUT/foreign_inos.txt" "$OUT/peer_inos.txt" | wc -l) of the FOREIGN inos"
for n in $NODE $PEER; do
    rs 30 "$n" "journalctl -k -q --since '$MARKTIME' -o short-monotonic 2>/dev/null || dmesg | sed -n '/$MARK/,\$p'" > "$OUT/dmesg_$n.txt"
    echo "  INFO $n lines=$(wc -l < "$OUT/dmesg_$n.txt") tags: $(grep -aoE 'P55C-FREE-[A-Z-]+|P-CR62|P-CR63-[A-Z-]+|P-CR3-CANCEL|P237-EVICT-[A-Z]+|P-SESSION-POISON|P-FREEOB-[A-Z-]+|P32D-DEADINCARN-SKIP' "$OUT/dmesg_$n.txt" | sort | uniq -c | sort -rn | tr '\n' ' ')"
    ck0 "$n zero P-CR62 DISK-LIVE" "$(grep -ac 'P-CR62 .*DISK-LIVE' "$OUT/dmesg_$n.txt")"
    ck0 "$n zero P-CR63-DEFER-DISKLIVE" "$(grep -ac 'P-CR63-DEFER-DISKLIVE' "$OUT/dmesg_$n.txt")"
    ck0 "$n zero shutdown signatures" "$(grep -ac 'Filesystem has been shut down\|xfs_do_force_shutdown\|P-SESSION-POISON\|P-CR3-CANCEL' "$OUT/dmesg_$n.txt")"
    m=$(rs 20 "$n" "mountpoint -q $MNT && timeout 10 ls $MNT/. >/dev/null && echo readable")
    if [ "$m" = "readable" ]; then echo "  PASS $n mount readable"; else echo "  FAIL $n mount not readable"; fails=$((fails+1)); fi
done
rs 30 "$PEER" "rm -rf $D" >/dev/null 2>&1
echo "=== free_foreign_realloc_repro RESULT $([ $fails -eq 0 ] && echo PASS || echo FAIL) fails=$fails out=$OUT ==="
[ $fails -eq 0 ]
