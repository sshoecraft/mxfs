#!/bin/bash
# tauth_slot_reuse.sh — the slot-reuse arm for
# D-TCP-PURGED-SLOT-POISONS-LATER-OCCUPANT-RECORDS-0344: a heartbeat slot freed
# by a recovery purge is reused by a later mount, and that occupant's grants
# must not be treated as the dead node's on the next membership change.
#
# Shape (TCP; four nodes: A survivor/master, X victim, N the slot's next
# occupant, J a later joiner):
#   0. A and X are mounted on TCP (from a prep); N and J have no module.
#   1. X writes F and syncs (X holds F's inode EX); X's slot and id recorded.
#   2. virsh destroy X.  A: heartbeat expiry -> fence -> slice replay ->
#      recovery complete -> ledger purge of X (P-TAUTH-PURGE node=<X>).
#   3. N mounts: it must claim X's freed slot (lowest free).
#   4. N creates NFILES files in its own directory (their inode grants are
#      mastered by A or N by hash — roughly half by A) and reads F back
#      (must equal X's md5: the replay carried X's acknowledged data).
#   5. J mounts: a membership change on A and N (active_count=3).
#   6. The defect would now show as: A (or J) purging N's records because
#      N sits on the purged slot ('P-TAUTH-PURGE node=<N>'), N's releases
#      refused -ESTALE, or a second EX granted over N's.  Assertions: zero
#      purge lines naming N anywhere, zero P-TAUTH-DOUBLE-GRANT, N rewrites
#      every file (its EX still live: zero stale-release lines), A and J read
#      all of them with N's md5, A overwrites one (BASTs N) and N reads A's
#      content back.
#   7. J and N leave cleanly; X is started again (the next prep re-forms).
#
# budget: expiry+replay on this rig measures ~80 s (tcp_death_replay
# replay_s=78), two mounts ~10 s each, the file work ~10 s: ~130 s expected,
# bound 300 s.  Usage: tests/tauth_slot_reuse.sh <label> [A] [X] [N] [J]
# Env: MXFS_DEV (default: the device of A's live mxfs mount, resolved by
#      mxfs_dev_resolve — no rig's device path is assumed), MXFS_MNT,
#      SR_NFILES (default 32), SR_MODARGS for N/J (default force_transport=1
#      target_cache_protected=1), MXFS_FAULT_UNREACHABLE=<stage>
#      (capture-contract verification only: the named acquisition, join_<tag>
#      e.g. join_3, is issued to a host that does not resolve — a real ssh
#      failure — and the lap must then ABORT, never reach a verdict).
#
# Every capture a verdict is taken from crosses tests/lib/rig.sh's boundary
# (rsx + capture_require in the parent shell) before it is counted.
set -u
LABEL=${1:?label}
A=${2:-test1}; X=${3:-test2}; N=${4:-test3}; J=${5:-test4}
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
VIRSH="sudo -n virsh -c qemu:///system"
MNT=${MXFS_MNT:-/mnt/shared}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
NFILES=${SR_NFILES:-32}
MODARGS=${SR_MODARGS:-force_transport=1 target_cache_protected=1}
KO=/src/mxfs/mxfs.ko
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_slot_reuse_$LABEL
mkdir -p "$OUT"
fails=0
ck() { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
ckge() { if [ "${2:-0}" -ge "$3" ] 2>/dev/null; then echo "  PASS $1 ($2 >= $3)"; else echo "  FAIL $1 got=${2:-?} want>=$3"; fails=$((fails+1)); fi; }
# rs/rsx/capture_require/require_epoch/mxfs_dev_resolve (tests/lib/rig.sh)
. "$(dirname "$0")/lib/rig.sh"
sshq() { rs "$@"; }
# jl <node> <mark> > <file>: a kernel journal window; the caller validates
# the file with capture_require 'kernel: ' before counting anything in it
jl() { rsx 25 "$1" "journalctl -k --since @$2 --no-pager 2>/dev/null | cut -c1-600"; }
field() { grep -ao "^$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }
fault_host() { # <stage> <node> -> the node to acquire from
    if [ "${MXFS_FAULT_UNREACHABLE:-}" = "$1" ]; then
        echo "STAGE FAULT: acquiring $1 from an unresolvable host instead of $2" >&2
        echo "$2-unreachable.invalid"
    else
        echo "$2"
    fi
}
MD5_SHAPE='^[0-9a-f]{32}$'

# join <node> <tag>: bounded mount under nohup, slot/id/transport recorded
join() {
    local h; h=$(fault_host "join_$2" "$1")
    rsx 90 "$h" "M=\$(date +%s); echo MARK=\$M; modprobe libcrc32c 2>/dev/null; insmod $KO $MODARGS; echo INSMOD_RC=\$?; rm -f /root/sr_mount.rc; T0=\$(date +%s); nohup sh -c 'mount -t mxfs $DEV $MNT; echo \$? > /root/sr_mount.rc' >/dev/null 2>&1 & for i in \$(seq 1 60); do sleep 1; [ -f /root/sr_mount.rc ] && break; done; if [ -f /root/sr_mount.rc ]; then echo MOUNT_RC=\$(cat /root/sr_mount.rc); else echo MOUNT_RC=HUNG; for p in \$(pidof mount); do echo \"--- mount pid \$p\"; cat /proc/\$p/stack; done; fi; echo WALL=\$(( \$(date +%s) - T0 )); journalctl -k --since @\$M --no-pager 2>/dev/null | grep -a 'DLM init: node_id=' | tail -1 | sed 's/.*node_id=\([0-9]*\).*transport=\([a-z]*\).*/NODE_ID=\1\nTRANSPORT=\2/'; journalctl -k --since @\$M --no-pager 2>/dev/null | grep -ao 'claimed heartbeat slot [0-9]*' | tail -1 | sed 's/.*slot /SLOT=/'; true" > "$OUT/$2_join.txt"
    capture_require "$OUT/$2_join.txt" '^MOUNT_RC=' "$2: the mount on $1"
    capture_require "$OUT/$2_join.txt" '^MARK=[0-9]+$' "$2: the clock mark of $1's mount"
    jl "$1" "$(field "$OUT/$2_join.txt" MARK)" > "$OUT/$2_join_journal.txt"
    capture_require "$OUT/$2_join_journal.txt" 'kernel: ' "$2: the kernel journal on $1 across its mount"
    ck "$2: $1 mounted (rc=$(field "$OUT/$2_join.txt" MOUNT_RC) wall=$(field "$OUT/$2_join.txt" WALL)s)" "$(field "$OUT/$2_join.txt" MOUNT_RC)" "0"
    ck "$2: $1 on transport=tcp" "$(field "$OUT/$2_join.txt" TRANSPORT)" "tcp"
    echo "  INFO $2: $1 node_id=$(field "$OUT/$2_join.txt" NODE_ID) slot=$(field "$OUT/$2_join.txt" SLOT)"
}
leave() {   # <node> <tag>
    rsx 90 "$1" "timeout -s KILL 60 umount $MNT; echo UMOUNT_RC=\$?; for i in 1 2 3 4 5 6; do rmmod mxfs 2>/dev/null; lsmod | grep -q '^mxfs' || break; sleep 2; done; lsmod | grep -q '^mxfs' && echo STILL_LOADED || echo UNLOADED" > "$OUT/$2_leave.txt"
    capture_require "$OUT/$2_leave.txt" '^(UNLOADED|STILL_LOADED)$' "$2: the departure of $1"
    ck "$2: $1 unmounted (rc=$(field "$OUT/$2_leave.txt" UMOUNT_RC)) and unloaded" "$(grep -c '^UNLOADED' "$OUT/$2_leave.txt")" "1"
}
# mark <node> <what>: a validated node-side epoch mark, printed
markof() { rsx 10 "$1" "date +%s" | tail -1; }

# 0. preconditions
measure "$A" 20 "$OUT/rv_pre_1.txt" '^READ_RC=[0-9]+$' "pre on $A" "mountpoint -q $MNT && echo A_M; cat /sys/module/mxfs/parameters/force_transport 2>/dev/null; journalctl -k --no-pager 2>/dev/null | grep -ao 'DLM init: node_id=[0-9]*' | tail -1 | sed 's/.*node_id=//'; printf '\nREAD_RC=%s\n' \$?"; pre=$(grep -av '^READ_RC=' "$OUT/rv_pre_1.txt" | tr '\n' ' ')
measure "$X" 20 "$OUT/rv_prex_2.txt" '^READ_RC=[0-9]+$' "prex on $X" "mountpoint -q $MNT && echo X_M; journalctl -k --no-pager 2>/dev/null | grep -ao 'DLM init: node_id=[0-9]*' | tail -1 | sed 's/.*node_id=//'; journalctl -k --no-pager 2>/dev/null | grep -ao 'claimed heartbeat slot [0-9]*' | tail -1 | sed 's/.*slot //'; printf '\nREAD_RC=%s\n' \$?"; prex=$(grep -av '^READ_RC=' "$OUT/rv_prex_2.txt" | tr '\n' ' ')
value_now_into pren "$N" 20 "$OUT/rv_pren_3.txt" '^[0-9]+$' "pren on $N" "lsmod | grep -c '^mxfs ' || [ \$? = 1 ]"; value_now_into prej "$J" 20 "$OUT/rv_prej_4.txt" '^[0-9]+$' "prej on $J" "lsmod | grep -c '^mxfs ' || [ \$? = 1 ]"
A_ID=$(echo "$pre" | awk '{print $3}'); X_ID=$(echo "$prex" | awk '{print $2}'); X_SLOT=$(echo "$prex" | awk '{print $3}')
ck "precondition: $A mounted on force_transport=1 (id ${A_ID:-?})" "$(echo "$pre" | grep -c '^A_M 1 [0-9]')" "1"
ck "precondition: $X mounted (id ${X_ID:-?} slot ${X_SLOT:-?})" "$(echo "$prex" | grep -c '^X_M [0-9]* [0-9]')" "1"
ck "precondition: no module on $N and $J" "${pren:-1}${prej:-1}" "00"
[ "$fails" = 0 ] || { echo "INFRA: preconditions not met — prep 2/tcp on $A,$X first"; exit 2; }
# the LUN as MXFS actually uses it, from A's live mount (MXFS_DEV overrides)
mxfs_dev_resolve "$A"
DEV=$MXFS_DEV_RESOLVED
echo "=== tauth_slot_reuse label=$LABEL A=$A X=$X N=$N J=$J dev=$DEV nfiles=$NFILES sv=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p') out=$OUT $(date -u +%FT%TZ) ==="

# 1. X holds F
F=$MNT/sr_$LABEL.F
rsx 30 "$X" "head -c 65536 /dev/urandom > $F && sync -f $MNT && md5sum $F | cut -c1-32" > "$OUT/1_write_X.txt"
capture_require "$OUT/1_write_X.txt" "$MD5_SHAPE" "1: the write of F on $X"
MD5_X=$(head -1 "$OUT/1_write_X.txt")
ck "1: $X wrote F and holds its grant (md5 recorded)" "$([ -n "$MD5_X" ] && echo 1 || echo 0)" "1"

# 2. X dies; A recovers and purges X
am=$(markof "$A")
require_epoch "$am" "2: $A's clock mark before $X's death"
$VIRSH destroy "$X" > "$OUT/virsh_destroy.txt" 2>&1; echo "  INFO 2: virsh destroy $X rc=$? at $(date -u +%T)"
tk=$(date +%s); rep=""
while [ $(( $(date +%s) - tk )) -lt 150 ]; do
    rep=$(jl "$A" "$am" | grep -a "foreign replay of slot ${X_SLOT:-9} complete\|foreign replay of slot ${X_SLOT:-9} failed\|P-TAUTH-PURGE node=${X_ID:-0} " | tail -2)
    echo "$rep" | grep -aq "P-TAUTH-PURGE node=${X_ID:-0} " && break
    sleep 5
done
trec=$(( $(date +%s) - tk ))
jl "$A" "$am" > "$OUT/2_journal_A.txt"
capture_require "$OUT/2_journal_A.txt" 'kernel: ' "2: the kernel journal on $A across $X's recovery"
echo "  INFO 2: recovery+purge of $X on $A after ${trec}s: $(echo "$rep" | sed 's/.*kernel: //' | cut -c1-150 | tr '\n' '|')"
ckge "2: $A completed $X's slice replay (foreign replay of slot $X_SLOT complete)" "$(grep -ac "foreign replay of slot ${X_SLOT:-9} complete" "$OUT/2_journal_A.txt")" 1
ckge "2: $A purged $X's ledger records (P-TAUTH-PURGE node=$X_ID)" "$(grep -ac "P-TAUTH-PURGE node=${X_ID:-0} " "$OUT/2_journal_A.txt")" 1
ck "2: recovery of $X within 150 s (got ${trec}s)" "$([ "$trec" -lt 150 ] && echo 1 || echo 0)" "1"
sleep 5   # the freed slot's release lands

# 3. N takes the freed slot
nm=$(markof "$A")
require_epoch "$nm" "3: $A's clock mark before $N's mount"
join "$N" 3
N_ID=$(field "$OUT/3_join.txt" NODE_ID); N_SLOT=$(field "$OUT/3_join.txt" SLOT)
ck "3: $N claimed $X's freed slot (slot $X_SLOT)" "${N_SLOT:-?}" "${X_SLOT:-?}"

# 4. N's grants: NFILES own files + F read back
DN=$MNT/sr_${LABEL}_N
rsx 90 "$N" "mkdir -p $DN && for i in \$(seq 1 $NFILES); do head -c 32768 /dev/urandom > $DN/f\$i; done; sync -f $DN; echo AGG=\$(md5sum $DN/f* | cut -c1-32 | sort | md5sum | cut -c1-32); echo F=\$(md5sum $F | cut -c1-32)" > "$OUT/4_work_N.txt"
capture_require "$OUT/4_work_N.txt" '^F=[0-9a-f]{32}$' "4: the file work on $N"
MD5_N=$(field "$OUT/4_work_N.txt" AGG); MD5_F_N=$(field "$OUT/4_work_N.txt" F)
ck "4: $N created $NFILES files in its directory (aggregate md5 recorded)" "$([ -n "$MD5_N" ] && echo 1 || echo 0)" "1"
ck "4: $N reads F with $X's md5 (the replay carried X's acknowledged data)" "$MD5_F_N" "$MD5_X"

# 5. J joins: membership change
join "$J" 5
J_ID=$(field "$OUT/5_join.txt" NODE_ID); J_SLOT=$(field "$OUT/5_join.txt" SLOT)
ck "5: $J took a different slot than $N" "$([ "${J_SLOT:-x}" != "${N_SLOT:-y}" ] && echo 1 || echo 0)" "1"
sleep 8
jl "$A" "$nm" > "$OUT/5_journal_A.txt"; jl "$N" "$(field "$OUT/3_join.txt" MARK)" > "$OUT/5_journal_N.txt"; jl "$J" "$(field "$OUT/5_join.txt" MARK)" > "$OUT/5_journal_J.txt"
capture_require "$OUT/5_journal_A.txt" 'kernel: ' "5: the kernel journal on $A since $N's mount"
capture_require "$OUT/5_journal_N.txt" 'kernel: ' "5: the kernel journal on $N since its mount"
capture_require "$OUT/5_journal_J.txt" 'kernel: ' "5: the kernel journal on $J since its mount"
ckge "5: $A saw the membership reach 3 (MXFS-MEMBERSHIP active_count=3)" "$(grep -ac 'MXFS-MEMBERSHIP .*active_count=3' "$OUT/5_journal_A.txt")" 1

# 6. the defect's signatures, then the grants in use
for n in A N J; do
    capture_require "$OUT/5_journal_$n.txt" 'kernel: ' "6: the kernel journal on $n"
    ck "6: zero ledger purge naming $N's id $N_ID on $n (P-TAUTH-PURGE node=$N_ID)" "$(grep -ac "P-TAUTH-PURGE[A-Z-]* node=${N_ID:-0} " "$OUT/5_journal_$n.txt")" "0"
    ck "6: zero P-TAUTH-DOUBLE-GRANT on $n" "$(grep -ac 'P-TAUTH-DOUBLE-GRANT' "$OUT/5_journal_$n.txt")" "0"
    ck "6: zero 'Shutting down filesystem' on $n" "$(grep -ac 'Shutting down filesystem' "$OUT/5_journal_$n.txt")" "0"
done
echo "  INFO 6: purge lines on $A since $N's mount: $(grep -ao 'P-TAUTH-PURGE[A-Z-]* node=[0-9]*[^|]*' "$OUT/5_journal_A.txt" | cut -c1-80 | sort | uniq -c | tr '\n' '|' | cut -c1-400)"
rm6=$(markof "$N")
require_epoch "$rm6" "6: $N's clock mark before the rewrite"
rsx 90 "$N" "for i in \$(seq 1 $NFILES); do head -c 32768 /dev/urandom > $DN/f\$i || echo WRITE_FAIL_\$i; done; sync -f $DN; echo RW_RC=\$?; echo AGG=\$(md5sum $DN/f* | cut -c1-32 | sort | md5sum | cut -c1-32)" > "$OUT/6_rewrite_N.txt"
capture_require "$OUT/6_rewrite_N.txt" '^AGG=[0-9a-f]{32}$' "6: the rewrite on $N"
MD5_N2=$(field "$OUT/6_rewrite_N.txt" AGG)
ck "6: $N rewrote all $NFILES files under its live grants (RW_RC=0, no WRITE_FAIL)" "$(grep -c '^RW_RC=0' "$OUT/6_rewrite_N.txt"; grep -c WRITE_FAIL "$OUT/6_rewrite_N.txt")" "1
0"
jl "$N" "$rm6" > "$OUT/6_journal_N.txt"
capture_require "$OUT/6_journal_N.txt" 'kernel: ' "6: the kernel journal on $N across the rewrite"
ck "6: zero stale-release refusals on $N (P6G-STALE-RELEASE-SKIP / P-TAUTH-SEALED-RELEASE-REFUSED / release rc=-116)" "$(grep -ac 'P6G-STALE-RELEASE-SKIP\|P-TAUTH-SEALED-RELEASE-REFUSED\|LOCK_RELEASE.*-116\|release refused' "$OUT/6_journal_N.txt")" "0"
for n in "$A" "$J"; do
    # a failed md5sum (EIO, ENOENT) is the measurement: its text is output
    rsx 60 "$n" "md5sum $DN/f* 2>&1 | cut -c1-32 | sort | md5sum | cut -c1-32" > "$OUT/6_read_$n.txt"
    capture_require "$OUT/6_read_$n.txt" "$MD5_SHAPE" "6: the read of $N's files on $n"
    ck "6: $n reads all $NFILES of $N's files with $N's md5" "$(head -1 "$OUT/6_read_$n.txt")" "$MD5_N2"
done
rsx 30 "$A" "head -c 32768 /dev/urandom > $DN/f1 && sync -f $DN && md5sum $DN/f1 | cut -c1-32" > "$OUT/6_overwrite_A.txt"
capture_require "$OUT/6_overwrite_A.txt" "$MD5_SHAPE" "6: the overwrite of f1 on $A"
rsx 30 "$N" "md5sum $DN/f1 2>&1 | cut -c1-32; true" > "$OUT/6_readback_N.txt"
capture_require "$OUT/6_readback_N.txt" '.' "6: the read-back of f1 on $N"
ck "6: $A overwrote f1 (BAST of $N's EX) and $N reads $A's content" "$(head -1 "$OUT/6_readback_N.txt")" "$(head -1 "$OUT/6_overwrite_A.txt")"

# 7. leave; X restarted for the next prep
leave "$J" 7J; leave "$N" 7N
$VIRSH start "$X" > "$OUT/virsh_start.txt" 2>&1; echo "  INFO 7: virsh start $X rc=$?"
# wait for X's ssh (bounded 120 s; a boot measures ~45 s): a prep chained
# right behind this lap found X unreachable and aborted (s517e3)
xi=0; while [ $xi -lt 120 ]; do timeout 8 "$SSH" "$X" "true" >/dev/null 2>&1 && break; sleep 5; xi=$((xi+5)); done
echo "  INFO 7: $X ssh reachable after ${xi}s"
echo "RESULT: $([ "$fails" = 0 ] && echo PASS || echo FAIL) label=$LABEL fails=$fails evidence=$OUT $(date -u +%FT%TZ)"
[ "$fails" = 0 ]
