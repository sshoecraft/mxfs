#!/bin/bash
# free_home_settle_repro.sh — instrumented reproducer for the s432 (0.38.3) collapse:
# a short-lived file (create + write + rm before its live image reaches the
# platter) takes the P55C-FREE-HOME branch at its sync-inactivation flush; on
# 0.38.3 that left the publication ledger open and the unlinked inode's
# reclaim shut the node down (P237-EVICT-OBLIGATION -> P-SESSION-POISON).
# 0.38.4 settles the ledger by equivalence (P55C-FREE-HOME-SETTLED).
#
#   tests/free_home_settle_repro.sh <label> [node=test1] [files=200] [peer=test2]
#
# Runs on one node of an already-prepped multi-node mount (the FREE obligation
# machinery is multi-node only): N x { dd 4 KiB; rm } into a private dir, then
# forces inode reclaim (sync + drop_caches 2 + a bounded wait) so every freed
# shell reaches xfs_reclaim_inode -> mxfs_dlm_evict.  Verdict from the node's
# dmesg after a kmsg marker:
#   PASS: zero P237-EVICT-OBLIGATION, zero P-SESSION-POISON, zero
#         P55C-FREE-HOME-UNSETTLED, and the mount still readable on node+peer;
#   INFO: counts of P55C-FREE-HOME / -SETTLED / P55C-FREE-FLUSH (which branch
#         the workload actually exercised — a run with zero FREE-HOME lines has
#         not exercised the fixed path and says so).
# Budget (budget): 200 files x (dd+rm) ~ 2 s native; reclaim wait <= 20 s.
set -u
LABEL=${1:?label}; NODE=${2:-test1}; NFILES=${3:-200}; PEER=${4:-test2}
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd); cd "$REPO"
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_fhs_$LABEL
mkdir -p "$OUT"
fails=0
filt() { grep -av '^Unauthorized\|^Warning:\|^If you'; }
ck0() { if [ "$2" = "0" ]; then echo "  PASS $1 (0)"; else echo "  FAIL $1 got=$2 want=0"; fails=$((fails+1)); fi; }
rs() { timeout "$1" $SSH "$2" "$3" 2>/dev/null | filt; }
D="$MNT/.fhs_$LABEL"
MARK="FHS-$LABEL-$$"
echo "=== free_home_settle_repro label=$LABEL node=$NODE peer=$PEER files=$NFILES out=$OUT $(date -u +%FT%TZ) ==="
want=$(modinfo mxfs.ko | awk '/^srcversion:/{print $2}')
for n in $NODE $PEER; do
    nsv=$(rs 15 "$n" "cat /sys/module/mxfs/srcversion" | tr -dc 'A-F0-9')
    [ "$nsv" = "$want" ] || { echo "ABORT: $n srcversion '$nsv' != tree '$want'"; exit 2; }
    rs 12 "$n" "echo '$MARK' > /dev/kmsg" >/dev/null
    # the workload must hit the CLUSTER mount: an unmounted $MNT is a plain
    # directory on the root fs and every check below would pass vacuously
    m=$(rs 20 "$n" "mountpoint -q $MNT && mount | grep -q ' on $MNT type mxfs ' && timeout 10 ls $MNT/. >/dev/null && echo mounted")
    [ "$m" = "mounted" ] || { echo "ABORT: $n does not have an mxfs mount at $MNT (prep the cluster first)"; exit 2; }
done
MARKTIME=$(date -u '+%Y-%m-%d %H:%M:%S')
# the workload: create+write+rm as fast as possible so the live image never
# reaches the platter (the s432 ino-133 sequence: dd then rm 6 ms later)
rs 60 "$NODE" "rm -rf $D; mkdir $D && cd $D && s=\$(date +%s%3N); i=0; bad=0; while [ \$i -lt $NFILES ]; do dd if=/dev/zero of=f\$i bs=4k count=1 status=none || bad=\$((bad+1)); rm -f f\$i || bad=\$((bad+1)); i=\$((i+1)); done; echo workload_ms=\$(( \$(date +%s%3N) - s )) bad=\$bad; cd /; rmdir $D; echo rmdir_rc=\$?" > "$OUT/workload.txt" 2>&1
cat "$OUT/workload.txt" | sed 's/^/  INFO /'
bad=$(grep -o 'bad=[0-9]*' "$OUT/workload.txt" | cut -d= -f2)
ck0 "workload errors" "${bad:-999}"
# force reclaim of the freed shells: sync, drop inode caches, then wait for
# the reclaim worker (bounded)
rs 40 "$NODE" "sync; echo 2 > /proc/sys/vm/drop_caches; sleep 3; sync; echo 2 > /proc/sys/vm/drop_caches; sleep 5; echo reclaim_done" > "$OUT/reclaim.txt" 2>&1
grep -q reclaim_done "$OUT/reclaim.txt" || { echo "  FAIL reclaim step did not complete: $(cat "$OUT/reclaim.txt")"; fails=$((fails+1)); }
# evidence
for n in $NODE $PEER; do
    # journald, not the dmesg ring: the ring wraps within minutes under the
    # probe volume (sess429: a 32/caw board left ~2 min of ring on test1)
    rs 30 "$n" "journalctl -k -q --since '$MARKTIME' -o short-monotonic 2>/dev/null || dmesg | sed -n '/$MARK/,\$p'" > "$OUT/dmesg_$n.txt"
    echo "  INFO $n lines=$(wc -l < "$OUT/dmesg_$n.txt") tags: $(grep -aoE 'P55C-FREE-[A-Z-]+|P237-EVICT-[A-Z]+|P-SESSION-POISON|P128-INACT-DEFER|P32D-DEADINCARN-SKIP|P383-HOME-VS-OWED|P177-[A-Z-]+' "$OUT/dmesg_$n.txt" | sort | uniq -c | sort -rn | tr '\n' ' ')"
    ck0 "$n zero P237-EVICT-OBLIGATION" "$(grep -ac 'P237-EVICT-OBLIGATION' "$OUT/dmesg_$n.txt")"
    ck0 "$n zero P-SESSION-POISON" "$(grep -ac 'P-SESSION-POISON' "$OUT/dmesg_$n.txt")"
    ck0 "$n zero P55C-FREE-HOME-UNSETTLED" "$(grep -ac 'P55C-FREE-HOME-UNSETTLED' "$OUT/dmesg_$n.txt")"
    ck0 "$n zero P55C-FREE-FOREIGN" "$(grep -ac 'P55C-FREE-FOREIGN' "$OUT/dmesg_$n.txt")"
    m=$(rs 20 "$n" "mountpoint -q $MNT && timeout 10 ls $MNT/. >/dev/null && echo readable")
    if [ "$m" = "readable" ]; then echo "  PASS $n mount readable"; else echo "  FAIL $n mount not readable"; fails=$((fails+1)); fi
done
home=$(grep -ac 'P55C-FREE-HOME ' "$OUT/dmesg_$NODE.txt"); settled=$(grep -ac 'P55C-FREE-HOME-SETTLED' "$OUT/dmesg_$NODE.txt")
echo "  INFO $NODE exercised: free_home=$home settled=$settled free_flush=$(grep -ac 'P55C-FREE-FLUSH' "$OUT/dmesg_$NODE.txt")"
[ "$home" -gt 0 ] || echo "  WARN the FREE-HOME branch was NOT exercised by this run (no verdict on the settle path)"
[ "$home" -eq "$settled" ] || { echo "  FAIL FREE-HOME lines ($home) != SETTLED lines ($settled)"; fails=$((fails+1)); }
echo "=== free_home_settle_repro RESULT $([ $fails -eq 0 ] && echo PASS || echo FAIL) fails=$fails out=$OUT ==="
[ $fails -eq 0 ]
