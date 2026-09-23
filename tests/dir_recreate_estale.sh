#!/bin/bash
# dir_recreate_estale.sh — D-RECREATED-SHARED-DIR-PEER-MKDIR-ESTALE-0346
# instrument step 1: reproduce and NAME the stale object.
#
# Observed (32/caw board 20260828T103802Z, fence_during_write): rank 1 does
# `rm -rf D; mkdir D` on a shared directory and 11/32 peers get ESTALE from
# `mkdir -p D/nodeN` — for BOTH the child and the parent path — for ~0.5 s.
#
# Shape: A (recreator) runs L laps of `rm -rf D; mkdir D` with a short gap;
# peers B/C/D run a tight `mkdir -p D/nodeN` loop for the same window and
# record every non-zero rc with errno text + monotonic timestamp.  The whole
# lap window is bracketed by a kmsg MARK on every node so the P-lines
# (P165-AFFINE-STALE, P128-REARM-UNPUB, P-IGET*, ESTALE) can be pulled for
# D's inode(s) on the ESTALE node.
#
# PASS iff zero ESTALE (or any error other than ENOENT, which is legal when
# the peer's mkdir races the rm: the parent may honestly not exist at that
# instant) on every peer across all laps.
#
# the budget rule (derived): laps L=20 at 250 ms => 5 s workload; per-node ssh ~1 s x
# 4 nodes for mark/collect x 3 rounds ~12 s; dmesg pull 4 x 3 s.  ~30 s;
# caller bound 60 s.
#
# Usage: tests/dir_recreate_estale.sh <label> [A] [B] [C] [D] [laps] [gap_ms]
set -u
LABEL=${1:?label}; A=${2:-test1}; B=${3:-test2}; C=${4:-test3}; DN=${5:-test4}
LAPS=${6:-20}; GAP_MS=${7:-250}
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd); cd "$REPO"
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_dre_$LABEL
mkdir -p "$OUT"
fails=0
ck() { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
# rs/rsx/measure/capture_require (tests/lib/rig.sh): every capture a verdict
# is counted from crosses the boundary in the parent shell first; a failed
# acquisition is an ABORT, never a count of zero.  Adopted by reading (a
# 4-node harness: no fault/healthy lap on the 2-node rig).
. "$(dirname "$0")/lib/rig.sh"
D="$MNT/.dre_$LABEL"
MARK="DRE-$LABEL-$$"
WINDOW_S=$(( (LAPS * GAP_MS) / 1000 + 3 ))

echo "=== dir_recreate_estale label=$LABEL A=$A peers=$B,$C,$DN laps=$LAPS gap=${GAP_MS}ms out=$OUT $(date -u +%FT%TZ) ==="
want=$(modinfo mxfs.ko | awk '/^srcversion:/{print $2}')
for n in $A $B $C $DN; do
    nsv=$(rs 15 "$n" "cat /sys/module/mxfs/srcversion" | tr -dc 'A-F0-9')
    [ "$nsv" = "$want" ] || { echo "ABORT: $n srcversion '$nsv' != tree '$want'"; exit 2; }
    rs 12 "$n" "echo '$MARK' > /dev/kmsg" >/dev/null
done
rs 20 "$A" "rm -rf $D; mkdir $D && stat -c %i $D" > "$OUT/ino0.txt"
ino0=$(tr -dc '0-9' < "$OUT/ino0.txt")
[ -n "$ino0" ] || { echo "ABORT: A setup failed: $(cat "$OUT/ino0.txt")"; exit 2; }
echo "  INFO initial D ino=$ino0"

# peers: tight mkdir loop for WINDOW_S, one line per attempt:
#   <monotonic_ms> rc=<n> [err=<text>]
peer_loop() {
    local n=$1
    rs $((WINDOW_S + 15)) "$n" "end=\$(( \$(date +%s%3N) + ${WINDOW_S}000 )); i=0; while [ \$(date +%s%3N) -lt \$end ]; do e=\$(mkdir -p $D/$n 2>&1); rc=\$?; [ \$rc -ne 0 ] && echo \"\$(date +%s%3N) rc=\$rc err=[\$e]\"; i=\$((i+1)); done; echo \"attempts=\$i\"" > "$OUT/peer_$n.txt" 2>&1 &
}
peer_loop "$B"; peer_loop "$C"; peer_loop "$DN"
sleep 1
# A: L laps of recreate, logging each new inode number with its timestamp
# sess427: capture the recreator's rm/mkdir rc BEFORE any command substitution
# ($(date) inside the echo reset $? to 0, so every lap printed mkdir_rc=0 even
# when mkdir failed); one line per lap with both rcs and the errno text.
rs $((WINDOW_S + 15)) "$A" "for l in \$(seq 1 $LAPS); do e1=\$(rm -rf $D 2>&1); r1=\$?; e2=\$(mkdir $D 2>&1); r2=\$?; t=\$(date +%s%3N); [ \$r1 -ne 0 -o \$r2 -ne 0 ] && echo \"\$t lap=\$l rm_rc=\$r1 mkdir_rc=\$r2 err=[\$e1|\$e2]\"; echo \"\$t lap=\$l ino=\$(stat -c %i $D 2>/dev/null)\"; sleep $(awk "BEGIN{print $GAP_MS/1000}"); done; echo recreator_done" > "$OUT/recreator.txt" 2>&1
wait
inos=$(grep -ao 'ino=[0-9]*' "$OUT/recreator.txt" | cut -d= -f2 | sort -u | tr '\n' ' ')
echo "  INFO recreator laps=$(grep -ac 'ino=' "$OUT/recreator.txt") inos=[$inos] done=$(grep -ac recreator_done "$OUT/recreator.txt")"
# sess428: `rm -rf D` racing three peers that keep creating D/<peer> can
# legally end in ENOTEMPTY (a peer re-created an entry between the unlink
# sweep and the rmdir), and the following `mkdir D` then legally sees EEXIST
# — the workload's stated shape, not a defect (s431a: 12/20 laps).  Only
# OTHER rm/mkdir errors (EIO, ESTALE, EUCLEAN ...) fail the recreator.
rrace=$(grep -a 'mkdir_rc=[1-9]\|rm_rc=[1-9]' "$OUT/recreator.txt" | grep -ac 'Directory not empty\|File exists')
rfail=$(grep -a 'mkdir_rc=[1-9]\|rm_rc=[1-9]' "$OUT/recreator.txt" | grep -avc 'Directory not empty\|File exists')
echo "  INFO recreator race-legal laps (ENOTEMPTY/EEXIST)=$rrace"
ck "recreator zero non-race rm/mkdir failures" "$rfail" "0"
[ "$rfail" -gt 0 ] && grep -a 'mkdir_rc=[1-9]\|rm_rc=[1-9]' "$OUT/recreator.txt" | grep -av 'Directory not empty\|File exists' | head -3 | sed 's/^/    /'

for n in $B $C $DN; do
    att=$(sed -n 's/^attempts=//p' "$OUT/peer_$n.txt")
    estale=$(grep -ac 'Stale file handle' "$OUT/peer_$n.txt")
    enoent=$(grep -ac 'No such file' "$OUT/peer_$n.txt")
    # sess428: `mkdir -p` reports EEXIST when the entry existed at mkdir(2)
    # and was gone again by its follow-up stat — the same recreate race.
    eexist=$(grep -ac 'File exists' "$OUT/peer_$n.txt")
    other=$(grep -a 'rc=' "$OUT/peer_$n.txt" | grep -avc 'Stale file handle\|No such file\|File exists')
    echo "  INFO $n attempts=$att estale=$estale enoent=$enoent eexist=$eexist other=$other"
    ck "$n zero ESTALE" "$estale" "0"
    ck "$n zero other errors" "$other" "0"
    [ "$estale" -gt 0 ] && grep -a 'Stale' "$OUT/peer_$n.txt" | head -3 | sed 's/^/    /'
done

# dmesg since MARK on every node, plus the lines that name D's inodes
for n in $A $B $C $DN; do
    measure "$n" 30 "$OUT/dmesg_$n.txt" '^DMESG_END$' "the kernel log on $n from the lap marker" "dmesg | sed -n '/$MARK/,\$p'; echo DMESG_END"
    pat=$(echo "$ino0 $inos" | tr ' ' '\n' | grep -v '^$' | sed 's/^/ino=/' | paste -sd'|')
    grep -aE "$pat|P34H-POISON|P-DIRCRC|P-LKERR" "$OUT/dmesg_$n.txt" > "$OUT/dlines_$n.txt"
    echo "  INFO $n dmesg=$(wc -l < "$OUT/dmesg_$n.txt") d-inode-lines=$(wc -l < "$OUT/dlines_$n.txt") tags: $(grep -aoE 'P[0-9A-Z-]+' "$OUT/dlines_$n.txt" | sort | uniq -c | sort -rn | head -8 | tr '\n' ' ')"
done
# sess427: a peer that SHUT DOWN during the window is the D-380/D-0351 face —
# report it explicitly (the EIO storm in peer_*.txt is its symptom).
# sess428: runs AFTER the dmesg pull (it read a not-yet-collected file and
# failed every node with an empty count on s431a/b); also reports the
# D-0351 publication evidence per node.
for n in $B $C $DN $A; do
    sd=$(grep -ac 'P-CR3-CANCEL\|Internal error\|P-SESSION-POISON\|force-shutdown' "$OUT/dmesg_$n.txt")
    ck "$n zero shutdown signatures" "$sd" "0"
    echo "  INFO $n freepub: $(grep -aoE 'P55C-FREE-[A-Z]+|P-FREEOB-[A-Z]+|P-CR62|P-CR63-DEFER-DISKLIVE' "$OUT/dmesg_$n.txt" | sort | uniq -c | sort -rn | tr '\n' ' ')"
    ck "$n zero FREE-PUBLISH violations" "$(grep -ac 'P-CR62\|P-CR63-DEFER-DISKLIVE\|P-FREEOB-REFUSED\|P-FREEOB-FOREIGN\|P-FREEOB-NOSHELL\|P-FREEOB-NOEPOCH\|P55C-FREE-FOREIGN' "$OUT/dmesg_$n.txt")" "0"
done
rs 20 "$A" "rm -rf $D" >/dev/null
echo "=== dir_recreate_estale RESULT $([ $fails -eq 0 ] && echo PASS || echo FAIL) fails=$fails out=$OUT ==="
exit $((fails > 0))
