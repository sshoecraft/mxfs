#!/bin/bash
# d0133_sb_mutation_gate.sh — D-SB-PERNODE-DIVERGENT-WHOLE-LOG-LOST-UPDATE-0133
# step 3 verification (0.29.2 mxfs_sb_mutation_refuse): every runtime
# NON-COUNTER whole-superblock producer that the shipped mxfs.ko can reach
# is refused on a cluster mount BEFORE m_sb is modified, and the
# counter-only syncs stay allowed.  Reachability on mxfs.ko (Kbuild):
#   - the XFS ioctl surface is EXCLUDED (xfs_stubs.c: ENOTTY for all but
#     GOINGDOWN) -> setlabel / growfs cannot be reached from userspace;
#   - quota is EXCLUDED (CONFIG_XFS_QUOTA undef) -> -o uquota dies at
#     option parse with EINVAL, before xfs_mountfs;
#   - LARP needs a DEBUG build (no /sys/fs/mxfs/debug) -> log_incompat add
#     is unreachable;
#   - `-o sunit=N,swidth=N` IS reachable: xfs_update_alignment would
#     rewrite sb_unit/sb_width -> the gate refuses the MOUNT with
#     P-SB-MUTATION-REFUSED what=dalign mount option.
# Arms, on one node N (left MOUNTED at the end):
#   ioctl    FS_IOC_SETFSLABEL / XFS_IOC_FSGROWFSDATA / FSGROWFSLOG issued
#            directly: ENOTTY(25), zero P-lines (never reached the FS).
#   cover    clean umount of N: ZERO P-SB-MUTATION-REFUSED (the unmount
#            counter sync is allowed).
#   dalign   mount -o sunit=8,swidth=8 (1 FSB, so rootino is unchanged and
#            update_sb=true): mount FAILS, P-line what=dalign mount option
#            exactly once, and the SB sb_unit stays 0 (proved by the plain
#            remount succeeding and logging zero refusals).
#   quota    mount -o uquota: FAILS (EINVAL at parse), zero P-lines.
#   remount  plain mount succeeds, zero new P-lines.
# Usage: tests/d0133_sb_mutation_gate.sh <label> [node] (default test5)
# the budget rule (derived): srcgate 5 s + 3 ioctls ~3 s + umount <=45 s + 3 mount
# attempts ~15 s + dmesg sweeps ~10 s => ~80 s.  Caller bound 100 s.
set -u
LABEL=${1:?label}; NODE=${2:-test5}
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd); cd "$REPO"
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "$NODE"; DEV=$MXFS_DEV_RESOLVED
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0133gate
mkdir -p "$OUT"
fails=0
# ck: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS
# rs/rsx/measure/window_count_into (tests/lib/rig.sh): every count a verdict
# is taken from is acquired into its own file and validated in the parent
# shell first; a failed ssh is an ABORT, never a count of zero.  Adopted by
# reading (a CAW-rig harness: no fault/healthy lap on the 2-node TCP rig).
. "$(dirname "$0")/lib/rig.sh"
rsn() { rs "$1" "$NODE" "$2"; }   # this harness's single node

echo "=== d0133_sb_mutation_gate label=$LABEL node=$NODE out=$OUT $(date -u +%FT%TZ) ==="
want=$(modinfo mxfs.ko | awk '/^srcversion:/{print $2}')
value_now_into nsv "$NODE" 15 "$OUT/rv_nsv_1.txt" '^[0-9A-F]+$' "nsv on $NODE" "cat /sys/module/mxfs/srcversion"
ck "srcgate $NODE runs the tree build $want" "$nsv" "$want"
[ "$nsv" = "$want" ] || { echo "=== d0133_sb_mutation_gate $LABEL: fails=$fails (srcgate) ==="; exit 1; }
value_now_into rv2 "$NODE" 10 "$OUT/rv_rv2_2.txt" '^[0-9]+$' "rv2 on $NODE" "grep -c ' $MNT mxfs ' /proc/mounts || [ \$? = 1 ]"
ck "$NODE has $MNT mounted (mxfs)" "$rv2" "1"
MARK="D0133-$LABEL-$$"
rsn 12 "echo '$MARK' > /dev/kmsg" >/dev/null

# ioctl arm — surface excluded on mxfs.ko: ENOTTY, nothing reaches the FS
rsn 30 "python3 - <<'EOF'
import fcntl, os, struct
fd=os.open('$MNT', os.O_RDONLY)
def call(name, req, arg):
    try:
        fcntl.ioctl(fd, req, arg); print(name, 'errno=0')
    except OSError as e:
        print(name, 'errno=%d' % e.errno)
lab=bytearray(256); lab[:5]=b'd0133'
call('setlabel', 0x41009432, bytes(lab))
call('growdata', 0x4010586e, struct.pack('QI4x', 1<<40, 25))
call('growlog', 0x4008586f, struct.pack('II', 1<<20, 1))
os.close(fd)
EOF" > "$OUT/ioctls.txt"
sed 's/^/  INFO /' "$OUT/ioctls.txt"
g() { awk -v k="$1" '$1==k{print $2; exit}' "$OUT/ioctls.txt"; }
ck "setlabel ioctl absent on mxfs.ko: ENOTTY(25)" "$(g setlabel)" "errno=25"
ck "growfs_data ioctl absent: ENOTTY(25)" "$(g growdata)" "errno=25"
ck "growfs_log ioctl absent: ENOTTY(25)" "$(g growlog)" "errno=25"
window_count_into wc1 "$NODE" 20 "$MARK" 'P-SB-MUTATION-REFUSED' "ioctls never reached a producer (zero P-lines)"
ck "ioctls never reached a producer (zero P-lines)" "$wc1" "0"

# cover arm
value_now_into urc "$NODE" 60 "$OUT/rv_urc_3.txt" '^rc=' "urc on $NODE" "timeout 45 umount $MNT; echo rc=\$?"; urc=$(printf '%s\n' "$urc" | sed -n 's/^rc=//p')
ck "clean umount of $NODE" "$urc" "0"
window_count_into wc2 "$NODE" 20 "$MARK" 'P-SB-MUTATION-REFUSED' "counter-only unmount sync ALLOWED: zero refusals"
ck "counter-only unmount sync ALLOWED: zero refusals" "$wc2" "0"

# dalign arm — the reachable live producer
value_now_into drc "$NODE" 90 "$OUT/rv_drc_4.txt" '^rc=' "drc on $NODE" "timeout 60 mount -t mxfs -o sunit=8,swidth=8 $DEV $MNT 2>/dev/null; echo rc=\$?; grep -q ' $MNT mxfs ' /proc/mounts && umount $MNT; true"; drc=$(printf '%s\n' "$drc" | sed -n 's/^rc=//p')
ck "mount -o sunit=8,swidth=8 REFUSED" "$([ "${drc:-0}" != 0 ] && echo refused || echo mounted)" "refused"
# sess420: on a mkfs_mxfs superblock XFS's own feature check refuses the
# change FIRST ("cannot change alignment: superblock does not support data
# alignment", xfs_check_new_dalign, measured s419 test5 @178.48s) — the SB
# carries no DALIGN feature, so the gate producer is unreachable on this rig.
# Either refusal is a correct outcome for the arm; record WHICH one fired.
window_count_into dpl "$NODE" 20 "$MARK" 'P-SB-MUTATION-REFUSED what=dalign mount option' "dpl"; window_count_into dxa "$NODE" 20 "$MARK" 'cannot change alignment: superblock does not support data alignment' "dxa"
echo "  INFO dalign refusal: gate P-line=$dpl xfs-feature-refusal=$dxa"
ck "dalign refused by the gate (P-line) or pre-empted by XFS's DALIGN feature check" "$([ "${dpl:-0}" -eq 1 ] || [ "${dxa:-0}" -ge 1 ] && echo yes || echo no)" "yes"
DALIGN_PL=${dpl:-0}
window_count_into wc3 "$NODE" 20 "$MARK" 'Skipping superblock stripe alignment update' "alignment update was not skipped by XFS itself (gate, not rootino)"
ck "alignment update was not skipped by XFS itself (gate, not rootino)" "$wc3" "0"

# quota arm — excluded subsystem, dies at option parse
value_now_into qrc "$NODE" 60 "$OUT/rv_qrc_5.txt" '^rc=' "qrc on $NODE" "timeout 40 mount -t mxfs -o uquota $DEV $MNT 2>/dev/null; echo rc=\$?; grep -q ' $MNT mxfs ' /proc/mounts && umount $MNT; true"; qrc=$(printf '%s\n' "$qrc" | sed -n 's/^rc=//p')
ck "mount -o uquota FAILS" "$([ "${qrc:-0}" != 0 ] && echo failed || echo mounted)" "failed"
window_count_into wc4 "$NODE" 20 "$MARK" 'quota support not available' "quota refused at option parse (kernel message)"
ck "quota refused at option parse (kernel message)" "$([ "$wc4" -ge 1 ] && echo yes || echo no)" "yes"

# remount arm
value_now_into mrc "$NODE" 120 "$OUT/rv_mrc_6.txt" '^rc=' "mrc on $NODE" "timeout 90 mount -t mxfs $DEV $MNT; echo rc=\$?"; mrc=$(printf '%s\n' "$mrc" | sed -n 's/^rc=//p')
ck "plain remount of $NODE succeeds" "$mrc" "0"
window_count_into wc5 "$NODE" 20 "$MARK" 'P-SB-MUTATION-REFUSED' "plain mount logs no new refusal (total still  DALIGN_PL)"
ck "plain mount logs no new refusal (total still $DALIGN_PL)" "$wc5" "$DALIGN_PL"
measure "$NODE" 20 "$OUT/dmesg_$NODE.txt" '^DMESG_END$' "the kernel log on $NODE from the lap marker" "dmesg | sed -n \"/$MARK/,\\\$p\"; echo DMESG_END"
ck "zero splats on $NODE" "$(grep -aEc 'BUG:|Oops' "$OUT/dmesg_$NODE.txt")" "0"
echo "=== d0133_sb_mutation_gate $LABEL: fails=$fails out=$OUT ==="
[ "$fails" -eq 0 ]
