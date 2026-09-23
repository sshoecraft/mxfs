#!/bin/bash
# tcp_lockreq_blackhole.sh — does an inode acquire against a LIVE remote master
# that will never answer terminate, or does it wait forever?
#
# The post-budget classifier keeps waiting whenever the party it waits on is
# live.  On the TCP transport the requester cannot read a remote master's
# holder table, so "live" there is answered by membership alone: it does not
# establish that a holder exists or that anything is draining.  This harness
# produces the case that distinction hides — a request that is never delivered,
# so the master creates no queue entry, no grant, and answers nothing — while
# the master stays a healthy live member serving everything else.
#
# W arms dl_drop_lockreq_ino for ONE inode, remotely mastered from W, then
# reads it.  H does not touch that inode and is shown to be alive and serving
# throughout.  After the armed window the knob is cleared: the next lap sends
# the request for real, which separates "waited for a message that never came"
# from "wedged".
#
# Verdict: the armed window is EVIDENCE, not a pass/fail — what W does in it is
# the measurement.  The FAIL conditions are the ones that would invalidate it:
# the drop never fired, H was not healthy, or the read did not recover on
# disarm.
#
# the budget rule (derived): one acquire budget is 3 attempts x 60 retries x
# 1 s = 180 s.  setup (candidate search, <= 8 x 13 s) + ARMED_S (>= 1 budget)
# + recovery (<= 60 s) + captures (~20 s).
#
# FAULT=drop_req (default) discards W's outbound LOCK_REQ for the target at
# W; the master never sees the request.  FAULT=drop_grant instead lets every
# request through and has the MASTER (H, since the target is remotely mastered
# from W) record its grant durably and never deliver it: W keeps re-sending,
# each re-send re-affirms a grant that is dropped again, W sees no receipt and
# gives up at the budget — and W's undelivered grant is then a blocker at H:
# H's own write of the file queues behind it and its blocking notifications
# reach a node that holds nothing.  Before 0.84.1 the only thing that retired
# it was the phantom reconcile on W (two no-mirror notifications inside 15 s
# queue a mirror-bypassing release): MEASURED on the control arm (s585d) as
# H's write blocked 10 s, and it depends on those notifications reaching W
# over the same transport that lost the grant.  0.84.1 sends LOCK_CANCEL on
# abandonment: the master retires the grant by name and promotes H (s585c:
# ack in 3.5 ms, H's write done in 1 s, no reconcile).  The drop_grant lap
# therefore asserts what H's write does AFTER W has given up and WHICH
# mechanism let it through.
#
# THE LEASE ARM (LEASE_PARK_MS, 0.89.21).  Optional, off by default.  Once W is
# confirmed blocked in a dropped request, park W's heartbeat so its authority
# over the shared LUN expires UNDER the waiter, and measure one interval: from
# the kernel's own P290-AUTH-CLOSED to the waiting task ceasing to exist.  That
# ordering — request outstanding FIRST, authority lost SECOND — is the one no
# workload reaches and the one the point-of-use write gate cannot see, because
# a task parked inside a lock request submits nothing and asks nothing.
# EXPECT=lease_abort asserts the interval is within LEASE_ABORT_BOUND_S; under
# EXPECT=observe the interval is simply reported, which is how the unfixed
# behaviour is established.  Adds LEASE_PARK_MS/1000 + up to LEASE_WATCH_S to
# the wall, and always waits the park out before returning: an injected
# heartbeat sleep left armed stalls the NEXT prep's unmount.
#
# Usage: tests/tcp_lockreq_blackhole.sh <label> [W=test2] [H=test1]
# Env:   MXFS_MNT (default /mnt/shared), ARMED_S (default 420),
#        LEASE_PARK_MS (0 = off), LEASE_WATCH_S (240),
#        LEASE_ABORT_BOUND_S (10),
#        FAULT=drop_req|drop_grant (default drop_req),
#        EXPECT=observe|hang|bounded|degraded (default observe).  "hang"
#        asserts the behaviour as measured on 0.80.x; "bounded" asserts that
#        a fix ended the wait inside the window WITHOUT a self-shutdown (the
#        fallible open() path); "degraded" asserts bounded DETECTION for a
#        caller that cannot be failed (WORKLOAD=held_fd): still blocked, no
#        shutdown, reported DEGRADED inside acq_degrade_ms of the first
#        dropped request, listed in debugfs while armed, delisted after.
#        DEGRADE_BOUND_S (default 45) is that bound in seconds.
#        WORKLOAD=open|held_fd|held_fd_read|held_dir_readdir|leaf_midlist
#        (default open).  held_fd runs md5sum on an fd opened before the
#        fault, which fstat()s first, so its acquire is getattr's (s581c
#        blocked in vfs_fstat); held_fd_read issues a bare read(2) on that fd
#        from python3, so its acquire is the read path's coherency envelope.
#        From 0.84.2 both are fallible.  held_dir_readdir does the same with
#        a DIRECTORY: the candidates are leaf-format directories, the held fd
#        is the dir, and W issues getdents64 itself on it (tests/getdents64.py
#        — opendir is an open() and fdopendir fstat()s first, both
#        already-audited sites), so the acquire under the fault is readdir's.
#        leaf_midlist is the readdir site reached only AFTER entries were
#        emitted: a leaf listing re-acquires the dir once per data block, and
#        with the test-only mxfs.readdir_leaf_pause_ms widening the gap
#        between two blocks, H's create in that gap revokes W's cached grant
#        so the next block's acquire is a real request the fault meets.  From
#        0.84.4 every readdir acquire is fallible and names its stage
#        (P958-READDIR-REFUSED stage=refresh|sf|map|leaf|shard-pin|shard-sf).
#        dir_create (0.84.11) is the namespace path: the candidates are
#        directories, W re-lists the target and stats the name it is about
#        to create so both the directory's PR and the negative lookup are
#        cached BEFORE the fault, and then creates the name through
#        python's os.open(O_CREAT|O_EXCL) — the create's own PR-to-EX
#        request on the directory is the one the fault meets, inside
#        xfs_create after the transaction has been reserved and before
#        anything is allocated.  H's revoke is still applied (step 2b) so the
#        reference digest is H's; W re-caches afterwards.  Under
#        EXPECT=bounded the refusal must be the create's (P958-NAMESPACE-
#        REFUSED op=create), the cancelled transaction must have been CLEAN
#        (P-CR3-CANCEL trans_dirty=0), the name must exist on NEITHER node
#        afterwards, and no fd may have been returned.
#        dir_unlink, dir_rename, dir_link, dir_symlink (0.84.12) are the same
#        shape for the other namespace operations: W re-caches the directory's
#        PR, the positive lookup of entry_000000000000000000 (what unlink,
#        rename and link read) and the negative lookup of the name the op
#        would write, then issues os.unlink / os.rename / os.link /
#        os.symlink.  Their first acquire is the pair inside
#        xfs_trans_alloc_dir (unlink, link), the set inside xfs_lock_inodes
#        (rename) or the parent inside xfs_symlink.  Under EXPECT=bounded the
#        refusal must name the op (op=remove|rename|link|symlink), the
#        existing entry must survive on both nodes and the new name must
#        exist on neither.
#
# WHY THERE ARE TWO WORKLOADS.  The refusal that ends the wait is opt-in per
# call site, and open() is the only site that opted in.  A run whose workload is
# `md5sum FILE` is therefore refused at open(), before a single read is issued —
# so it measures the open path and says nothing about any other caller.
# WORKLOAD=held_fd measures the rest of the filesystem: W opens the fd FIRST,
# H then rewrites the file (which revokes W's grant), the drop is armed, and
# only then does W read THROUGH THE FD IT ALREADY HOLDS.  That read's acquire
# carries no fallible registration, so it takes the unchanged park-and-restart
# loop.  The two workloads differ in exactly one thing — whether the acquire
# under the fault belongs to a caller that can be failed — which is what makes
# the pair a measurement of that distinction rather than of two shapes.
# Leaves both nodes mounted and the knob cleared.  Exit 0 PASS, 1 FAIL,
# 2 INFRA/ABORT.
set -u
LABEL=${1:?label}
W=${2:-test2}; H=${3:-test1}
ARMED_S=${ARMED_S:-420}
WORKLOAD=${WORKLOAD:-open}
case "$WORKLOAD" in open|held_fd|held_fd_read|held_fd_write|held_fd_dio_unaligned|held_fd_chmod|held_fd_fallocate|held_fd_truncate|held_fd_getxattr|held_fd_listxattr|held_fd_setxattr|held_fd_removexattr|held_fd_setxattr_nofork|held_fd_mmap_read|held_fd_mmap_write) ISDIR=0 ;; held_dir_readdir|leaf_midlist|dir_create|dir_unlink|dir_rename|dir_link|dir_symlink|dir_lookup) ISDIR=1 ;; *) echo "ABORT: WORKLOAD must be open, held_fd, held_fd_read, held_fd_write, held_fd_dio_unaligned, held_fd_chmod, held_fd_fallocate, held_fd_truncate, held_fd_getxattr, held_fd_listxattr, held_fd_setxattr, held_fd_removexattr, held_fd_setxattr_nofork, held_fd_mmap_read, held_fd_mmap_write, held_dir_readdir, leaf_midlist, dir_create, dir_unlink, dir_rename, dir_link, dir_symlink or dir_lookup"; exit 2;; esac
# held_fd_setxattr_nofork: every new inode on this build carries an empty
# extents-format attr fork from creation (the default attr offset), so a
# plain setxattr never reaches xfs_attr_add_fork (s606i, s607b: stage=set on a
# fresh file, P958-XATTRSET-PATH has_af=1 af_fmt=2).  This workload has the
# driver set and remove user.d958 before announcing — removing the last
# attribute drops the fork — so the change's first request is the add-fork
# reservation (stage=addfork).
# held_fd_mmap_read / held_fd_mmap_write (0.84.21): the driver maps the file
# MAP_SHARED before the fault and, on release, a forked CHILD reads the first
# 4 bytes (a read fault: xfs_filemap_fault's counted PR hold, stage=read-hold)
# or stores b'mmw!' at offset 0 and msyncs (a write fault).  For the write,
# W re-caches the file's PR and page cache with a plain read after H's
# rewrite, so the read-fault hold is a cached fast path and the first
# request is page_mkwrite's timestamp update (stage=timestamp) or, when no
# update is due, its counted EX hold (stage=write-hold).  A refused fault is
# SIGBUS to the child, reported by the parent as `<op>_rc=-7 SIGBUS`; the
# child's pid (in /tmp/bh_go.child) is the task sampled.  A refused store
# must have changed no byte on either node.
case "$WORKLOAD" in held_fd_mmap_read|held_fd_mmap_write) FAULTOP=${WORKLOAD#held_fd_} ;; *) FAULTOP="" ;; esac
# held_fd_setxattr / held_fd_removexattr (0.84.20): the same driver.
# setxattr sets nothing beforehand, so the file has no attr fork and the
# change's first request is xfs_attr_add_fork's reservation
# (P958-XATTRSET-REFUSED stage=addfork); removexattr sets user.d958 first,
# so the first request is xfs_attr_set's own reservation (stage=remove).  A
# refused change must have changed nothing cold on either node: user.d958
# absent (setxattr), still v958 (removexattr).  (FS_IOC_FSSETXATTR is not a
# workload: the module does not compile pal/linux/xfs_ioctl.c and answers
# EOPNOTSUPP from a stub.)
# held_fd_getxattr / held_fd_listxattr (0.84.19): the parked driver sets
# user.d958=v958 on the fd before announcing (its own EX, landed and then
# revoked by H's rewrite), and on release issues one fgetxattr / flistxattr.
# The read's attr-fork lock (xfs_attr_get / xfs_attr_list through
# xfs_ilock_attr_map_shared_fallible, a cluster PR) is the first request it
# sends (P958-XATTR-REFUSED op=get|list).  A refused read must have returned
# nothing to the driver and changed nothing; the attribute must still read
# v958 cold on both nodes afterwards.
# held_fd_truncate (0.84.15) is the RESIDUAL class, run under EXPECT=degraded:
# ftruncate(fd, 4096)'s first cluster acquire is xfs_setattr_size's ILOCK_EXCL,
# taken after truncate_setsize has already changed the in-core size, so it is
# not an audited boundary and the wait is kept and reported DEGRADED.  The
# lap asserts that report (still blocked, no shutdown, listed while armed,
# delisted after) and that the truncate then lands correctly once the
# requests flow again (size 4096 on both nodes, cold).
# held_fd_chmod / held_fd_fallocate (0.84.15): the parked process is
# tests/held_fd_op.py, which opens O_RDWR before the fault and, on release,
# issues one fchmod (0640) or one fallocate(1 MiB, 4096: the size grows) on the fd.
# H's rewrite (2b) has revoked W's grant, and neither op re-caches anything,
# so the first request the operation sends is its own EX: the ILOCK_EXCL
# inside xfs_trans_alloc_ichange (P958-SETATTR-REFUSED op=chmod) or
# fallocate's IOLOCK_EXCL take (P958-FALLOCATE-REFUSED).  A refused chmod
# must have changed the mode on neither node; a refused fallocate must have
# allocated nothing (size unchanged).
case "$WORKLOAD" in held_fd_chmod|held_fd_fallocate|held_fd_truncate|held_fd_getxattr|held_fd_listxattr|held_fd_setxattr|held_fd_removexattr|held_fd_setxattr_nofork|held_fd_mmap_read|held_fd_mmap_write) ATTROP=${WORKLOAD#held_fd_} ;; *) ATTROP="" ;; esac
# The refusal line each xattr workload must produce, and the field on it (a
# grep pattern; the trailing space anchors the value).  setxattr accepts
# either reservation: addfork when the inode had no attr fork, set when it
# had one — the kernel's P958-XATTRSET-PATH line says which it saw.
case "$WORKLOAD" in
held_fd_getxattr)    XATTROP=get;      XPROBE=P958-XATTR-REFUSED;    XFIELD="op=get " ;;
held_fd_listxattr)   XATTROP=list;     XPROBE=P958-XATTR-REFUSED;    XFIELD="op=list " ;;
held_fd_setxattr)    XATTROP=set;      XPROBE=P958-XATTRSET-REFUSED; XFIELD="stage=addfork \|stage=set " ;;
held_fd_removexattr) XATTROP=remove;   XPROBE=P958-XATTRSET-REFUSED; XFIELD="stage=remove " ;;
held_fd_setxattr_nofork) XATTROP=addfork; XPROBE=P958-XATTRSET-REFUSED; XFIELD="stage=addfork " ;;
*) XATTROP=""; XPROBE=""; XFIELD="" ;;
esac
# held_fd_dio_unaligned (0.84.13, rewired 0.84.14): the candidates are files
# with an UNWRITTEN region (fallocate, first block written); W's parked
# process is tests/dio_unaligned_pwrite.py, which opens O_WRONLY|O_DIRECT
# BEFORE the fault (a shell cannot; s596d opened inside the armed command and
# the refusal landed on open's own boundary) and, on release, issues one
# pwrite of 4096 bytes at a 512-aligned, block-unaligned offset inside the
# unwritten region.  W re-caches the file's PR after H's rewrite, so the
# first ride (IOLOCK_SHARED) is a cached fast path and the FIRST request the
# write sends is the mtime/ctime update's ILOCK_EXCL inside kiocb_modified
# (xfs_vn_update_time: a cluster EX in a reserved, clean transaction) — the
# acquire under test since 0.84.14 (P958-WRITE-REFUSED stage=timestamp).  The
# exclusive retry's own ride (stage=unaligned-excl-retry) sits behind it and
# is reached only when the timestamp needed no update; the verdict accepts
# either stage and prints which.
# dir_lookup (0.84.13): no re-cache at all — after H's revoke W stats an
# existing entry by path, so the lookup's own acquire of the directory is the
# request the fault meets (P958-LOOKUP-REFUSED stage=refresh|dir).
# The namespace workloads (0.84.11): dir_unlink, dir_rename, dir_link and
# dir_symlink are the dir_create shape for the other namespace operations.
# Each acts on the target directory through python's os.<op> and nothing
# else, after the directory's PR and the lookups it needs are re-cached.
# ENAME is the existing entry the operation reads (unlink, rename, link
# source); WNAME is the new name it would write (create, rename, link,
# symlink).  Under EXPECT=bounded a refused operation must have changed
# NEITHER name on EITHER node.
case "$WORKLOAD" in dir_lookup) NSOP="" ;; dir_*) NSOP=${WORKLOAD#dir_} ;; *) NSOP="" ;; esac
WNAME=.armed_${NSOP:-create}_by_w
ENAME=entry_000000000000000000
# A directory candidate is leaf format with several data blocks (DIR_ENTRIES
# names of 24 chars at 4 KiB blocks: ~100 per block), so leaf_midlist has a
# block boundary to stop at and held_dir_readdir lists what a real tree has.
DIR_ENTRIES=${DIR_ENTRIES:-400}
# The between-block pause leaf_midlist relies on, in ms: long enough for H's
# create to be issued, granted and its revoke to land at W (measured
# cross-node create + BAST round trip well under 1 s), short enough not to
# stretch the listing past the window.
LEAF_PAUSE_MS=${LEAF_PAUSE_MS:-4000}
FAULT=${FAULT:-drop_req}
case "$FAULT" in drop_req|drop_grant) ;; *) echo "ABORT: FAULT must be drop_req or drop_grant"; exit 2;; esac
# CONTROL_NO_CANCEL=1 (drop_grant only): W abandons WITHOUT sending
# LOCK_CANCEL (dl_no_cancel, the pre-0.84.1 behaviour) so the lap shows, on
# the same build, that H's write of the file then blocks behind W's
# undelivered grant until W's phantom reconcile releases it — the second
# defence the cancel replaces, and the one the control must be seen to hit.
CONTROL_NO_CANCEL=${CONTROL_NO_CANCEL:-0}
[ "$CONTROL_NO_CANCEL" = "1" ] && [ "$FAULT" != "drop_grant" ] && { echo "ABORT: CONTROL_NO_CANCEL needs FAULT=drop_grant"; exit 2; }
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
P=/sys/module/mxfs/parameters
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_lockreqbh_$LABEL
mkdir -p "$OUT"
# rs/rsx/capture_require (tests/lib/rig.sh): every capture a verdict is taken
# from is proven to hold its tool's shape first; a failed acquisition is an
# ABORT, never a count of zero.  A node's kernel log is always taken from the
# lap marker, so the marker line IS its shape.
. "$(dirname "$0")/lib/rig.sh"
fails=0
# ck: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS
hd() { rsx 25 "$1" "dmesg | sed -n \"/$MARK/,\\\$p\""; }
# hdcap <node> <file>: the node's log from the lap marker, validated
hdcap() { hd "$1" > "$2"; capture_require "$2" "$MARK" "the kernel log on $1 from the lap marker (${2##*/})"; }
# probe <node> <timeout> <file> <shape> <what> <cmd>: a one-shot remote
# measurement whose lines feed a verdict, validated
probe() { rsx "$2" "$1" "$6" > "$3"; capture_require "$3" "$4" "$5"; }
disarm() {
    timeout 20 $SSH "$W" "echo 0 > $P/dl_drop_lockreq_ino; echo 0 > $P/dl_no_cancel; echo 0 > $P/readdir_leaf_pause_ms 2>/dev/null; echo 0 > $P/watch_ino" >/dev/null 2>&1
    timeout 20 $SSH "$H" "echo 0 > $P/dl_drop_grant_ino" >/dev/null 2>&1
}
# The digest a node reports for the target: the file's bytes, or the sorted
# names of the directory.  Both sides of every comparison use this.
dig() { if [ "$ISDIR" = "1" ]; then echo "ls -1A '$1' | sort | md5sum | cut -d' ' -f1"; else echo "md5sum '$1' | cut -d' ' -f1"; fi; }
# Arm THE fault for the target: the request drop lives on W (the sender), the
# grant drop on H (the master).  The candidate search always uses the request
# drop, because its firing is what proves the target is remotely mastered.
arm_fault() {
    if [ "$FAULT" = "drop_grant" ]; then
        timeout 20 $SSH "$H" "echo $1 > $P/dl_drop_grant_ino" </dev/null >/dev/null 2>&1
        timeout 20 $SSH "$W" "echo 3 > /proc/sys/vm/drop_caches; echo $CONTROL_NO_CANCEL > $P/dl_no_cancel" </dev/null >/dev/null 2>&1
    else
        timeout 20 $SSH "$W" "echo 3 > /proc/sys/vm/drop_caches; echo $1 > $P/dl_drop_lockreq_ino" </dev/null >/dev/null 2>&1
    fi
}
t0=$(date +%s)
el() { echo $(( $(date +%s) - t0 )); }

echo "=== tcp_lockreq_blackhole label=$LABEL W=$W H=$H armed_s=$ARMED_S out=$OUT $(date -u +%FT%TZ) ==="
TREESV=$(modinfo mxfs.ko 2>/dev/null | sed -n 's/^srcversion: *//p')
for n in "$W" "$H"; do
    info=$(timeout 20 $SSH "$n" "echo sv=\$(cat /sys/module/mxfs/srcversion) ft=\$(cat $P/force_transport) m=\$(grep -c ' mxfs ' /proc/mounts) k=\$(test -w $P/dl_drop_lockreq_ino && echo 1 || echo 0) c=\$(test -r $P/dl_drop_lockreq_n && echo 1 || echo 0)" 2>/dev/null | filt | tr -d '\r')
    echo "  INFO $n $info"
    [[ "$info" == *"sv=$TREESV"* ]] || { echo "ABORT: $n srcversion != tree '$TREESV' ($info)"; exit 2; }
    [[ "$info" == *"m=1"* ]]        || { echo "ABORT: $n not mounted ($info)"; exit 2; }
    [[ "$info" == *"k=1"* ]]        || { echo "ABORT: $n has no writable dl_drop_lockreq_ino knob ($info)"; exit 2; }
    # Every drop count below is read from the knob's own counter, which the
    # build resets each time the knob is armed.  The probe LINE prints only
    # the first 8 drops and every 64th after them per arm: two laps (s585c2,
    # s585e) chose no target because the module load's print budget was
    # already spent and every candidate read as locally mastered.
    [[ "$info" == *"c=1"* ]]        || { echo "ABORT: $n has no readable dl_drop_lockreq_n counter (build older than 0.84.2) ($info)"; exit 2; }
done
if [ "$FAULT" = "drop_grant" ]; then
    g=$(timeout 15 $SSH "$H" "test -w $P/dl_drop_grant_ino && echo 1 || echo 0" 2>/dev/null | filt | tr -dc '0-9')
    [ "${g:-0}" = "1" ] || { echo "ABORT: $H has no writable dl_drop_grant_ino knob (build older than 0.84.1)"; exit 2; }
fi
MARK="LOCKREQBH-$LABEL-$$"
for n in "$W" "$H"; do timeout 15 $SSH "$n" "echo '$MARK' > /dev/kmsg" >/dev/null 2>&1; done
# EVERY count below reads THIS RUN's kernel log, never the whole ring.  A bare
# `dmesg | grep -c` carries the previous run's lines forward: s578c selected
# its target inode from 15 drop-probe hits left by s578b, armed a knob for an
# inode that was locally mastered this time, and scored nine PASSes on a read
# that never went near the code under test.
DM="dmesg | awk '/$MARK/{f=1} f'"

# 1. H writes eight candidate files.  Which node masters a resource is a hash of
#    the resource id, so the one inode this measurement needs — remotely
#    mastered FROM W — is found by asking, not by assuming.
if [ "$ISDIR" = "1" ]; then
    # Eight leaf-format directories.  Bound: 8 x DIR_ENTRIES creates at a
    # measured ~14 ms each (3200 creates = 45 s) plus the sync.
    timeout $(( 8 * DIR_ENTRIES / 50 + 40 )) $SSH "$H" "
        for i in 1 2 3 4 5 6 7 8; do
            f='$MNT/.lockreqbh_${LABEL}_'\$i
            mkdir -p \"\$f\" || exit 1
            j=0; while [ \$j -lt $DIR_ENTRIES ]; do : > \"\$f/entry_\$(printf %018d \$j)\" || exit 1; j=\$((j+1)); done
            echo \$i \$(stat -c %i \"\$f\") \$(ls -1A \"\$f\" | sort | md5sum | cut -d' ' -f1)
        done
        sync
      " 2>"$OUT/h_setup.err" | filt > "$OUT/h_setup.txt"
elif [ "$WORKLOAD" = "held_fd_dio_unaligned" ]; then
# 64 KiB fallocated (unwritten), the first block written: blocks 1..15 stay
# unwritten, which is what makes the unaligned overwrite-only attempt answer
# -EAGAIN and take the exclusive retry.
timeout 40 $SSH "$H" "
    for i in 1 2 3 4 5 6 7 8; do
        f='$MNT/.lockreqbh_${LABEL}_'\$i
        rm -f \"\$f\"; fallocate -l 65536 \"\$f\" || exit 1
        dd if=/dev/urandom of=\"\$f\" bs=4096 count=1 conv=notrunc status=none || exit 1
        echo \$i \$(stat -c %i \"\$f\") \$(md5sum \"\$f\" | cut -d' ' -f1)
    done
    sync
  " 2>"$OUT/h_setup.err" | filt > "$OUT/h_setup.txt"
else
timeout 40 $SSH "$H" "
    for i in 1 2 3 4 5 6 7 8; do
        f='$MNT/.lockreqbh_${LABEL}_'\$i
        dd if=/dev/urandom of=\"\$f\" bs=4096 count=4 status=none || exit 1
        echo \$i \$(stat -c %i \"\$f\") \$(md5sum \"\$f\" | cut -d' ' -f1)
    done
    sync
  " 2>"$OUT/h_setup.err" | filt > "$OUT/h_setup.txt"
fi
[ "$(grep -ac . "$OUT/h_setup.txt")" = "8" ] || {
    echo "ABORT: H setup wrote $(grep -ac . "$OUT/h_setup.txt")/8 candidates: [$(filt < "$OUT/h_setup.err" | tail -3 | tr '\n' ' ')]"; exit 2; }
cat "$OUT/h_setup.txt" | sed 's/^/  INFO candidate /'

# 2. Find a candidate whose LOCK_REQ from W actually goes to a remote master:
#    the drop site sits on the remote-master send path only, so its probe
#    firing IS the proof that this inode is remotely mastered from W.
TARGET=""; MD5_H=""; CAND=""
while read -r idx ino md5 <&3; do
    [ -n "$ino" ] || continue
    f="$MNT/.lockreqbh_${LABEL}_$idx"
    timeout 20 $SSH "$W" "echo 3 > /proc/sys/vm/drop_caches; echo $ino > $P/dl_drop_lockreq_ino" </dev/null >/dev/null 2>&1
    if [ "$ISDIR" = "1" ]; then
        timeout 20 $SSH "$W" "nohup sh -c 'ls -f \"$f\" > /tmp/bh_probe.out 2>&1' >/dev/null 2>&1 &" </dev/null >/dev/null 2>&1
    else
        timeout 20 $SSH "$W" "nohup sh -c 'md5sum \"$f\" > /tmp/bh_probe.out 2>&1' >/dev/null 2>&1 &" </dev/null >/dev/null 2>&1
    fi
    sleep 9
    # The counter was reset when the knob was armed for this inode, so it
    # counts this candidate's drops alone.
    got=$(timeout 20 $SSH "$W" "cat $P/dl_drop_lockreq_n" </dev/null 2>/dev/null | filt | tr -dc '0-9')
    echo "  INFO candidate idx=$idx ino=$ino drop_hits=${got:-0} at +$(el)s"
    disarm
    sleep 4
    if [ "${got:-0}" -ge 1 ]; then TARGET=$ino; MD5_H=$md5; CAND=$idx; break; fi
done 3< "$OUT/h_setup.txt"
[ -n "$TARGET" ] || { echo "ABORT: no candidate inode is remotely mastered from $W (all eight locally mastered)"; disarm; exit 2; }
F="$MNT/.lockreqbh_${LABEL}_$CAND"
echo "  INFO target ino=$TARGET file=$F md5_H(from setup)=$MD5_H at +$(el)s"

# 2a. held_fd only: W takes the open BEFORE the fault exists and before the
#     grant is revoked, then parks.  Order matters and cannot be rearranged:
#     the open must precede H's rewrite (so the later read finds its grant
#     gone and must re-acquire) and must precede the arming (so the open's own
#     acquire is not the one under test).  The read is issued through the
#     inherited fd — `md5sum <&9`, never `md5sum "$F"` and never
#     /dev/fd/9, both of which are a fresh open() and would land back on the
#     one call site that has already been fixed.
if [ "$WORKLOAD" != "open" ]; then
    # held_fd: md5sum fstat()s its input before reading it, so the acquire
    # under the fault is getattr's.  held_fd_read: one bare read(2) on the
    # inherited fd — python's os.read is the syscall and nothing else — so
    # the acquire under the fault is the read path's.
    FDOPEN="exec 9< \"$F\""
    if [ "$WORKLOAD" = "held_fd_read" ]; then
        RCMD='exec python3 -c "import os,sys; d=os.read(9,65536); sys.stdout.write(\"read_bytes=%d\\n\" % len(d))"'
    elif [ "$WORKLOAD" = "held_fd_write" ]; then
        # 0.84.10 (D-0958): one bare write(2) on an fd opened for APPEND
        # before the fault — python's os.write is the syscall and nothing
        # else — so the acquire under the fault is the buffered write path's
        # own IOLOCK ride (xfs_file_buffered_write, stage=first).  Append,
        # never truncate: the open must change nothing, so the recovered
        # read afterwards still compares against H's bytes when the write
        # was refused.
        FDOPEN="exec 9>> \"$F\""
        RCMD='exec python3 -c "import os,sys; n=os.write(9,b\"w\"*4096); sys.stdout.write(\"write_bytes=%d\\n\" % n)"'
    elif [ "$WORKLOAD" = "leaf_midlist" ]; then
        # getdents64 issued directly on the inherited directory fd: no
        # open(), no fstat() (tests/getdents64.py says why).  Two calls, so
        # a leaf listing stopped between blocks shows both what it returned
        # and the error the next call gets — two serial budgets, like held_fd.
        RCMD='exec python3 /src/mxfs/tests/getdents64.py 9 2'
    elif [ "$WORKLOAD" = "held_fd_dio_unaligned" ]; then
        # 0.84.14: the parked process is the python script itself — it
        # opens O_WRONLY|O_DIRECT, writes the opened marker, waits for the
        # go marker, then issues one pwrite of a page-aligned 4096-byte
        # buffer at file offset 8704 (512-aligned, not block-aligned, inside
        # the unwritten region, not extending).  The launch below execs it
        # in place of the shell park, so the open precedes the fault.
        RCMD='exec python3 /src/mxfs/tests/dio_unaligned_pwrite.py "'"$F"'" 8704 4096 /tmp/bh_fd.open /tmp/bh_go'
    elif [ -n "$ATTROP" ]; then
        # 0.84.15: the parked process opens O_RDWR itself, announces, waits
        # for the go marker and issues the one attribute operation on the fd.
        RCMD='exec python3 /src/mxfs/tests/held_fd_op.py "'"$F"'" '"$ATTROP"' /tmp/bh_fd.open /tmp/bh_go'
    elif [ "$WORKLOAD" = "dir_lookup" ]; then
        # 0.84.13: one stat of an existing entry by path, with NOTHING
        # re-cached after H's revoke, so the lookup of the entry in the
        # target directory sends the request the fault meets.
        RCMD='exec python3 -c "import os,sys; st=os.stat(\"'"$F/$ENAME"'\"); sys.stdout.write(\"lookup_ino=%d\\n\" % st.st_ino)"'
    elif [ -n "$NSOP" ]; then
        # 0.84.11 (D-0958): one namespace operation on the target directory
        # — python's os.<op> is the syscall and nothing else.  The held fd
        # on the directory is taken before the fault so the parked process
        # has the same shape as the other workloads; the operation itself
        # goes through the path, not the fd.  The directory's PR and the
        # lookups the operation needs are re-cached just before the arm
        # (below), so the first request the operation sends is its own
        # PR-to-EX on the directory: inside xfs_create (create), inside
        # xfs_trans_alloc_dir's pair acquire (unlink, link), inside
        # xfs_lock_inodes (rename), inside xfs_symlink (symlink).
        case "$NSOP" in
        create)  RCMD='exec python3 -c "import os,sys; fd=os.open(\"'"$F/$WNAME"'\", os.O_CREAT|os.O_EXCL|os.O_WRONLY, 0o644); sys.stdout.write(\"create_fd=%d\\n\" % fd)"' ;;
        unlink)  RCMD='exec python3 -c "import os,sys; os.unlink(\"'"$F/$ENAME"'\"); sys.stdout.write(\"unlink_ok=1\\n\")"' ;;
        rename)  RCMD='exec python3 -c "import os,sys; os.rename(\"'"$F/$ENAME"'\", \"'"$F/$WNAME"'\"); sys.stdout.write(\"rename_ok=1\\n\")"' ;;
        link)    RCMD='exec python3 -c "import os,sys; os.link(\"'"$F/$ENAME"'\", \"'"$F/$WNAME"'\"); sys.stdout.write(\"link_ok=1\\n\")"' ;;
        symlink) RCMD='exec python3 -c "import os,sys; os.symlink(\"target_of_w\", \"'"$F/$WNAME"'\"); sys.stdout.write(\"symlink_ok=1\\n\")"' ;;
        esac
    elif [ "$ISDIR" = "1" ]; then
        # ONE call: a second would start a second 180 s wait on the same
        # fault and outlive a one-budget window (s589a).
        RCMD='exec python3 /src/mxfs/tests/getdents64.py 9 1'
    else
        RCMD='exec md5sum <&9'
    fi
    timeout 20 $SSH "$W" "rm -f /tmp/bh_read.out /tmp/bh_read.pid /tmp/bh_fd.open /tmp/bh_go" >/dev/null 2>&1
    if [ "$WORKLOAD" = "held_fd_dio_unaligned" ] || [ -n "$ATTROP" ]; then
        # The script opens, announces and parks by itself; exec keeps the
        # pid the shell wrote.
        timeout 25 $SSH "$W" "nohup sh -c 'echo \$\$ > /tmp/bh_read.pid; $RCMD' > /tmp/bh_read.out 2>&1 &" </dev/null >/dev/null 2>&1
    else
        timeout 25 $SSH "$W" "nohup sh -c '$FDOPEN; echo \$\$ > /tmp/bh_read.pid; : > /tmp/bh_fd.open; while [ ! -e /tmp/bh_go ]; do sleep 1; done; $RCMD' > /tmp/bh_read.out 2>&1 &" </dev/null >/dev/null 2>&1
    fi
    opened=0
    for i in 1 2 3 4 5 6 7 8 9 10; do
        o=$(timeout 15 $SSH "$W" "test -e /tmp/bh_fd.open && echo 1 || echo 0" </dev/null 2>/dev/null | filt | tr -dc '0-9')
        [ "${o:-0}" = "1" ] && { opened=1; break; }
        sleep 2
    done
    RPID=$(timeout 15 $SSH "$W" "cat /tmp/bh_read.pid" </dev/null 2>/dev/null | filt | tr -dc '0-9')
    echo "  INFO held_fd: W parked with the fd open pid=$RPID opened=$opened at +$(el)s"
    [ "$opened" = "1" ] && [ -n "$RPID" ] || { echo "ABORT: W could not park holding an open fd on the target"; disarm; exit 2; }
fi

# 2b. The candidate probe left W holding a grant on the target once it
#     recovered.  H rewrites the file, which revokes that grant, so the armed
#     read below must take a real acquire rather than a cached-grant fast path.
#     H is left holding an idle grant nothing is draining — the shape a request
#     lost in flight actually meets, since a request that never arrives
#     generates no blocking notification for H to answer.
if [ "$ISDIR" = "1" ]; then
    # A directory is "rewritten" by adding an entry: H's create takes EX on
    # the dir and revokes W's cached grant exactly as the file rewrite does.
    MD5_H=$(timeout 30 $SSH "$H" "
        : > '$F/.revoke_by_h' || exit 1
        sync; $(dig "$F")
      " 2>/dev/null | filt | grep -aoE '^[0-9a-f]{32}' | head -1)
elif [ "$WORKLOAD" = "held_fd_dio_unaligned" ]; then
# The rewrite must keep the unwritten region: only the first block, in place.
MD5_H=$(timeout 30 $SSH "$H" "
    dd if=/dev/urandom of='$F' bs=4096 count=1 conv=notrunc status=none || exit 1
    sync; md5sum '$F' | cut -d' ' -f1
  " 2>/dev/null | filt | grep -aoE '^[0-9a-f]{32}' | head -1)
else
value_now_into MD5_H "$H" 30 "$OUT/rv_MD5_H_setup.txt" '^[0-9a-f]{32}$' "H's rewrite of the target" "
    dd if=/dev/urandom of='$F' bs=4096 count=4 status=none || exit 1
    sync; md5sum '$F' | cut -d' ' -f1
  "
fi
[ -n "$MD5_H" ] || { echo "ABORT: H could not rewrite the target"; disarm; exit 2; }
echo "  INFO target rewritten by H, md5_H=$MD5_H at +$(el)s"
# The attribute workloads compare mode and block count before and after:
# the reference is H's view right after its rewrite, which is the state a
# refused operation must leave untouched on both nodes.
ATTR0=""
if [ -n "$ATTROP" ]; then
    value_now_into ATTR0 "$H" 20 "$OUT/rv_ATTR0_1.txt" '^[0-9]+_[0-9]+$' "ATTR0 on $H" "stat -c '%a_%s' '$F'"; ATTR0=$(printf '%s\n' "$ATTR0" | grep -aoE '^[0-9]+_[0-9]+')
    echo "  INFO $WORKLOAD: reference mode_size on H after the rewrite = ${ATTR0:-none} at +$(el)s"
    [ -n "$ATTR0" ] || { echo "ABORT: H could not stat the target"; disarm; exit 2; }
fi
if [ "$WORKLOAD" = "leaf_midlist" ]; then
    # W must START the armed listing holding a cached grant, so that its first
    # block is a fast path and only the acquire AFTER the pause is a real
    # request: list once now, with nothing armed, to cache the PR that H's
    # rewrite just revoked.  Then the pause knob and the watch that scopes it.
    relist=$(timeout 30 $SSH "$W" "ls -f '$F' | grep -c '^entry_'; echo $TARGET > $P/watch_ino; echo $LEAF_PAUSE_MS > $P/readdir_leaf_pause_ms; echo knobs=\$(cat $P/watch_ino),\$(cat $P/readdir_leaf_pause_ms)" 2>/dev/null | filt | tr '\n' ' ')
    echo "  INFO leaf_midlist: W re-listed the target to cache a grant and armed the between-block pause: $relist at +$(el)s"
    [[ "$relist" == *"knobs=$TARGET,$LEAF_PAUSE_MS"* ]] || { echo "ABORT: W has no readdir_leaf_pause_ms knob (build older than 0.84.4) or the watch did not arm ($relist)"; disarm; exit 2; }
fi

# 3. Arm the drop and start the read.  Nothing else is injected: H is untouched,
#    and every resource other than this inode still routes normally.
#    The candidate search already dropped requests for this inode; arming
#    resets the counter, so every count from here is the armed read's alone.
if [ "$WORKLOAD" != "open" ]; then
    if [ "$WORKLOAD" = "held_fd_dio_unaligned" ] || [ "$WORKLOAD" = "held_fd_mmap_write" ]; then
        # H's rewrite (2b) took W's PR on the file.  Re-cache it with a
        # plain read, so the armed pwrite's FIRST ride (shared) is a cached
        # fast path and its exclusive retry is the first request sent; for
        # the write fault the read also refills W's page cache, so the
        # fault's read half is served locally and page_mkwrite's acquires
        # are the first request.
        recache=$(timeout 30 $SSH "$W" "md5sum '$F' | cut -d' ' -f1" 2>/dev/null | filt | grep -aoE '^[0-9a-f]{32}' | head -1)
        echo "  INFO $WORKLOAD: W re-cached the file's PR (md5=${recache:-none}) at +$(el)s"
        [ "$recache" = "$MD5_H" ] || { echo "ABORT: W's re-cache read does not match H's rewrite"; disarm; exit 2; }
    fi
    if [ -n "$NSOP" ]; then
        # H's revoke (2b) took W's PR on the directory.  Re-cache it now, with
        # nothing armed: a listing takes the PR back, a stat of the name the
        # operation would write leaves the negative lookup under that PR,
        # and a stat of the entry it reads (unlink, rename, link) leaves the
        # positive one and the entry's own PR.  With those cached, the armed
        # operation sends no request before its own PR-to-EX upgrade on the
        # directory — which is the acquire under test.  Asserted: the new
        # name is absent and the existing entry present before the op.
        recache=$(timeout 30 $SSH "$W" "ls -f '$F' | grep -c '^entry_'; stat '$F/$WNAME' >/dev/null 2>&1 && echo present=1 || echo present=0; stat '$F/$ENAME' >/dev/null 2>&1 && echo entry=1 || echo entry=0" 2>/dev/null | filt | tr '\n' ' ')
        echo "  INFO $WORKLOAD: W re-cached the directory's PR, the negative lookup of $WNAME and the lookup of $ENAME: [$recache] at +$(el)s"
        [[ "$recache" == *"present=0"* ]] || { echo "ABORT: $WNAME already exists in the target (or W could not stat it): [$recache]"; disarm; exit 2; }
        [[ "$recache" == *"entry=1"* ]] || { echo "ABORT: $ENAME is missing from the target on W: [$recache]"; disarm; exit 2; }
    fi
    # The parked process already exists and already holds the fd; arming and
    # then releasing it is the whole launch.  Nothing is removed here — the
    # pid file was written before the fault existed.
    arm_fault "$TARGET"
    timeout 20 $SSH "$W" "rm -f /tmp/bh_go.child; : > /tmp/bh_go" </dev/null >/dev/null 2>&1
    sleep 3
    if [ -n "$FAULTOP" ]; then
        # The access runs in the driver's forked child; that is the task
        # whose stack and liveness the samples must read.
        cpid=$(timeout 15 $SSH "$W" "cat /tmp/bh_go.child 2>/dev/null" </dev/null 2>/dev/null | filt | tr -dc '0-9')
        echo "  INFO $WORKLOAD: driver parent pid=$RPID, faulting child pid=${cpid:-none} at +$(el)s"
        [ -n "$cpid" ] || { echo "ABORT: the driver forked no child for the fault"; disarm; exit 2; }
        RPID=$cpid
    fi
    echo "  INFO W held-fd read released pid=$RPID armed at +$(el)s"
    if [ "$WORKLOAD" = "leaf_midlist" ]; then
        # W is inside its first between-block pause (LEAF_PAUSE_MS, started
        # ~3 s ago).  H's create now takes EX on the dir and revokes W's
        # cached grant, so W's NEXT block acquire is a request — and it is
        # dropped.  The digest H reports afterwards is the reference for W's
        # recovered listing.
        measure "$H" 30 "$OUT/rv_MD5_H_1.txt" '^READ_RC=[0-9]+$' "MD5_H on $H" ": > '$F/.mid_by_h' || exit 1; sync; $(dig "$F"); printf '\nREAD_RC=%s\n' \$?"; MD5_H=$(grep -av '^READ_RC=' "$OUT/rv_MD5_H_1.txt" | grep -aoE '^[0-9a-f]{32}' | head -1)
        echo "  INFO leaf_midlist: H created an entry inside W's between-block pause, md5_H=$MD5_H at +$(el)s"
        [ -n "$MD5_H" ] || { echo "ABORT: H could not create the mid-listing entry"; disarm; exit 2; }
    fi
else
    arm_fault "$TARGET"
    timeout 20 $SSH "$W" "rm -f /tmp/bh_read.out /tmp/bh_read.pid" >/dev/null 2>&1
    timeout 20 $SSH "$W" "nohup sh -c 'echo \$\$ > /tmp/bh_read.pid; exec md5sum \"$F\"' > /tmp/bh_read.out 2>&1 &" >/dev/null 2>&1
    sleep 3
    RPID=$(timeout 15 $SSH "$W" "cat /tmp/bh_read.pid" 2>/dev/null | filt | tr -dc '0-9')
    echo "  INFO W read pid=$RPID armed at +$(el)s"
fi
[ -n "$RPID" ] || { echo "ABORT: could not capture W's read pid"; disarm; exit 2; }

# ─── 3b. OPT-IN: let the authority lease CLOSE UNDER a waiter already blocked ──
#
# WHY IT IS HERE AND NOT IN A HARNESS OF ITS OWN.  The hard half of producing a
# blocked acquire is finding an inode this node does not master and making its
# request vanish without harming anything else, and that is done by the ninety
# lines above.  What this stage adds is the ORDERING the lease work needs and
# no workload reaches: the request is outstanding FIRST, and only then does
# this node's authority over the shared LUN expire.
#
# The distinction matters because the lease's gate is at the point of use, so
# it catches an operation that is about to submit.  A task already parked
# inside a lock request submits nothing and asks nothing; whether it ever
# learns that its mount has lost the right to complete it is a different
# question, and this is the only place it gets asked.
#
# The ordering is enforced, not assumed: the waiter must be confirmed blocked
# AND the drop must have fired before the heartbeat is touched.  A lap that
# parks the heartbeat first would be measuring an acquire that never started.
#
# WHAT IS MEASURED is one interval: from the kernel's own P290-AUTH-CLOSED to
# the waiting task ceasing to exist.  Not whether it ends — it always ends
# eventually, at its own budget or when a shutdown tears the mount down
# underneath it — but whether the CLOSURE is what ended it.
LEASE_PARK_MS=${LEASE_PARK_MS:-0}
LEASE_WATCH_S=${LEASE_WATCH_S:-240}
LEASE_ABORT_BOUND_S=${LEASE_ABORT_BOUND_S:-10}
# Not anchored at ^: every line these read carries several fields, and an
# anchored reader hands back "" for all of them but the first.
leasefield(){ grep -aoE "(^| )$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }
lease_closed_s=""; lease_exit_s=""; lease_delta_s=""; lease_park_ok=0
if [ "$LEASE_PARK_MS" != 0 ]; then
    probe "$W" 25 "$OUT/w_preclose.txt" '^blocked=[01] ' "W is really blocked in the acquire before the lease is touched" "
        echo blocked=\$(test -d /proc/$RPID && echo 1 || echo 0) state=\$(awk '{print \$3}' /proc/$RPID/stat 2>/dev/null) drop=\$(cat $P/dl_drop_lockreq_n)
        echo --- stack ---; cat /proc/$RPID/stack 2>/dev/null | head -20"
    pre_blocked=$(leasefield "$OUT/w_preclose.txt" blocked); pre_drop=$(leasefield "$OUT/w_preclose.txt" drop)
    echo "  INFO before the close: blocked=$pre_blocked state=$(leasefield "$OUT/w_preclose.txt" state) drop_hits=$pre_drop at +$(el)s"
    if [ "${pre_blocked:-0}" != 1 ] || [ "${pre_drop:-0}" -lt 1 ]; then
        echo "  the waiter is not blocked in a dropped request, so closing the lease under it would measure nothing"
        echo "=== tcp_lockreq_blackhole $LABEL: VACUOUS stage=preclose blocked=$pre_blocked drop=$pre_drop out=$OUT ==="
        disarm; exit 3
    fi
    timeout 20 $SSH "$W" "echo $LEASE_PARK_MS > $P/dl_inject_hb_pause_ms" </dev/null >/dev/null 2>&1
    lease_park_ok=1
    lpt0=$(el)
    echo "  INFO parked W's heartbeat for ${LEASE_PARK_MS}ms at +${lpt0}s — the lease (30 s) closes under the blocked waiter"
    : > "$OUT/w_lease_watch.txt"
    lw=0
    while [ "$lw" -lt "$LEASE_WATCH_S" ]; do
        sleep 2; lw=$(( lw + 2 ))
        ls_=$(timeout 15 $SSH "$W" "echo alive=\$(test -d /proc/$RPID && echo 1 || echo 0) closed=\$($DM | grep -ac 'P290-AUTH-CLOSED') shut=\$($DM | grep -ac 'Shutting down filesystem')" </dev/null 2>/dev/null | filt | tr -d '\r')
        echo "+$(el)s $ls_" >> "$OUT/w_lease_watch.txt"
        a=$(printf '%s' "$ls_" | grep -aoE '(^| )alive=[0-9]+' | cut -d= -f2)
        c=$(printf '%s' "$ls_" | grep -aoE '(^| )closed=[0-9]+' | cut -d= -f2)
        [ -z "$lease_closed_s" ] && [ "${c:-0}" -ge 1 ] && { lease_closed_s=$(el); echo "  INFO the lease CLOSED at +${lease_closed_s}s"; }
        [ -z "$lease_exit_s" ] && [ "${a:-1}" = 0 ] && { lease_exit_s=$(el); echo "  INFO the blocked waiter EXITED at +${lease_exit_s}s"; }
        [ -n "$lease_closed_s" ] && [ -n "$lease_exit_s" ] && break
    done
    if [ -n "$lease_closed_s" ] && [ -n "$lease_exit_s" ]; then
        lease_delta_s=$(( lease_exit_s - lease_closed_s ))
    fi
    echo "  INFO lease watch: closed_at=+${lease_closed_s:-never}s waiter_exit=+${lease_exit_s:-never}s delta=${lease_delta_s:-n/a}s bound=${LEASE_ABORT_BOUND_S}s"
    timeout 20 $SSH "$W" "cat /tmp/bh_read.out 2>/dev/null | head -c 300; echo" </dev/null 2>/dev/null | filt > "$OUT/w_lease_readout.txt"
    echo "  INFO the waiter's own result: $(head -c 160 "$OUT/w_lease_readout.txt" | tr '\n' ' ')"
    timeout 20 $SSH "$W" "$DM | grep -a 'P290-AUTH-CLOSED\|P290-AUTH-REFUSED\|P290-AUTH-HB-STOP\|P292-ACQ-AUTH-CLOSED\|Shutting down filesystem' | tail -10" </dev/null 2>/dev/null | filt > "$OUT/w_lease_journal.txt"
    sed 's/.*mxfs: /    /' "$OUT/w_lease_journal.txt" | cut -c1-170 | head -4
    # Never leave the park armed: an injected heartbeat sleep that outlives its
    # lap stalls the NEXT prep's unmount, which waits on the sleeping thread.
    rem=$(( LEASE_PARK_MS / 1000 - ( $(el) - lpt0 ) ))
    [ "$rem" -gt 0 ] && { echo "  INFO waiting out the remaining ${rem}s of the heartbeat park"; sleep "$rem"; }
    timeout 20 $SSH "$W" "echo 0 > $P/dl_inject_hb_pause_ms" </dev/null >/dev/null 2>&1
fi

# 4. Sample the armed window.  Each sample answers three questions: is W's read
#    still blocked and where, is W still classifying the wait as live, and is H
#    still a healthy member that serves its own I/O promptly.
tsample=0
while [ "$tsample" -lt "$ARMED_S" ]; do
    sleep 60
    tsample=$(( tsample + 60 ))
    # each sample is validated on its own (the stack lines it carries are
    # what the verdict's call-site assertions count)
    probe "$W" 25 "$OUT/w_sample_$tsample.txt" '^alive=[01] state=' "the armed-window sample on $W at +${tsample}s" "
        alive=\$(test -d /proc/$RPID && echo 1 || echo 0)
        st=\$(awk '{print \$3}' /proc/$RPID/stat 2>/dev/null)
        echo alive=\$alive state=\$st
        echo lkwait=\$($DM | grep -ac 'P-LKWAIT-LIVE') retry=\$($DM | grep -ac 'P36-RETRY') drop=\$(cat $P/dl_drop_lockreq_n) unrec=\$($DM | grep -ac 'DLM inode lock unrecoverable') shut=\$($DM | grep -ac 'Shutting down filesystem') giveup=\$($DM | grep -ac 'P912-ACQ-UNRECEIPTED') qack=\$($DM | grep -ac 'P912-QACK-RX') deg=\$($DM | grep -ac 'P958-ACQ-DEGRADED ')
        echo out=\$(cat /tmp/bh_read.out 2>/dev/null | head -c 60)
        echo --- stack ---; cat /proc/$RPID/stack 2>/dev/null | head -20
        echo --- acquire_degraded ---; cat /sys/kernel/debug/mxfs/*/acquire_degraded 2>&1 | head -14
      "
    s=$(cat "$OUT/w_sample_$tsample.txt")
    echo "  SAMPLE +$(el)s $(echo "$s" | sed -n '1,3p' | tr '\n' ' ')"
    { echo "=== sample at +$(el)s ==="; echo "$s"; } >> "$OUT/w_samples.txt"
done

# 5. While W has been blocked past two budgets, prove H is not wedged: its own
#    I/O on the same filesystem, including on the very file W cannot reach,
#    must complete promptly.
# a hang here is the wedge under test: the status is the measurement, and
# only a missing h_mounted= line WITHOUT a timeout is a failed instrument
rsx 40 "$H" "
    s=\$(date +%s%N); $(dig "$F"); e=\$(date +%s%N); echo h_read_ms=\$(( (e-s)/1000000 ))
    s=\$(date +%s%N); dd if=/dev/urandom of='$MNT/.lockreqbh_${LABEL}_probe' bs=4096 count=4 status=none && sync; e=\$(date +%s%N); echo h_write_ms=\$(( (e-s)/1000000 ))
    echo h_mounted=\$(grep -c ' mxfs ' /proc/mounts)
  " > "$OUT/h_while_blocked.txt"; hsrc=$?
[ "$hsrc" = 124 ] || capture_require "$OUT/h_while_blocked.txt" '^h_mounted=[0-9]+$' "H's own I/O while W is blocked"
hs=$(grep -av "^$RS_STATUS_TAG " "$OUT/h_while_blocked.txt")
echo "  INFO H while W is blocked: $(echo "$hs" | tr '\n' ' ')"
md5_h_live=$(echo "$hs" | grep -aoE '^[0-9a-f]{32}' | head -1)
h_read_ms=$(echo "$hs" | sed -n 's/^h_read_ms=//p')
h_mounted=$(echo "$hs" | sed -n 's/^h_mounted=//p')

# 5b. drop_grant only: H writes THE TARGET FILE, which needs EX against W's
#     undelivered PR grant.  By now W's open has given up (the budget is
#     180 s and the window is longer).  With the cancel, the master retired
#     W's grant when W abandoned it and this write completes at once; without
#     it (control) the write blocks until W's phantom reconcile — triggered
#     by the repeated no-mirror blocking notifications this write causes —
#     releases the orphan (10 s measured, s585d).  Bounded at 40 s: a
#     blocked write past that is the answer, not a reason to wait.
h_wt_done_s=""
if [ "$FAULT" = "drop_grant" ]; then
    # Detached, with a done-marker, never under `timeout`: a dd blocked in
    # the acquire is not killable by the signal, and the question is WHEN it
    # completes, which a marker answers and a killed process cannot.
    timeout 20 $SSH "$H" "rm -f /tmp/bh_hw.done; nohup sh -c 'dd if=/dev/urandom of=\"$F\" bs=4096 count=4 conv=notrunc status=none; echo rc=\$? > /tmp/bh_hw.done; sync' >/dev/null 2>&1 &" </dev/null >/dev/null 2>&1
    hw_t0=$(date +%s)
    for i in $(seq 1 40); do
        d=$(timeout 15 $SSH "$H" "cat /tmp/bh_hw.done 2>/dev/null" </dev/null 2>/dev/null | filt | tr -d '\r')
        [ -n "$d" ] && { h_wt_done_s=$(( $(date +%s) - hw_t0 )); break; }
        sleep 1
    done
    echo "  INFO H's write of the TARGET after W gave up: $([ -n "$h_wt_done_s" ] && echo "completed in ${h_wt_done_s}s ($d)" || echo "STILL BLOCKED after 40s") at +$(el)s"
fi

# 6. Snapshot the armed-window totals, then disarm and see whether the read
#    recovers.  A read that returns correct data once the requests flow again
#    was waiting for a message, not wedged on its own state.
probe "$W" 25 "$OUT/w_armed_totals.txt" '^alive=[01]$' "the armed-window totals on $W" "
    echo alive=\$(test -d /proc/$RPID && echo 1 || echo 0)
    echo lkwait=\$($DM | grep -ac 'P-LKWAIT-LIVE') drop=\$(cat $P/dl_drop_lockreq_n) unrec=\$($DM | grep -ac 'DLM inode lock unrecoverable') shut=\$($DM | grep -ac 'Shutting down filesystem') giveup=\$($DM | grep -ac 'P912-ACQ-UNRECEIPTED') qack=\$($DM | grep -ac 'P912-QACK-RX') deg=\$($DM | grep -ac 'P958-ACQ-DEGRADED ') degtarget=\$($DM | grep -a 'P958-ACQ-DEGRADED ' | grep -ac 'ino=$TARGET ')
    echo beyond=\$($DM | grep -ao 'P-LKWAIT-LIVE ino=[0-9]* mode=[0-9]* rc=-[0-9]* laps=[0-9]* beyond_budget_s=[0-9]*' | tail -1)
    echo dropfirst_ts=\$($DM | grep -a 'P912-DROP-LOCKREQ n=1 ' | tail -1 | grep -ao '^\[ *[0-9]*' | tr -dc '0-9')
    echo deg_ts=\$($DM | grep -a 'P958-ACQ-DEGRADED ' | grep -a 'ino=$TARGET ' | head -1 | grep -ao '^\[ *[0-9]*' | tr -dc '0-9')
    echo degfile_lists_target=\$(grep -ac ' ino=$TARGET ' /sys/kernel/debug/mxfs/*/acquire_degraded 2>/dev/null | tail -1)
  "
armed=$(cat "$OUT/w_armed_totals.txt")
echo "  INFO armed-window totals: $(echo "$armed" | tr '\n' ' ')"
# The master's grant-drop counter, read while its knob is still armed.
h_grant_dropped=0
if [ "$FAULT" = "drop_grant" ]; then
    probe "$H" 20 "$OUT/h_grant_dropped.txt" '^[0-9]+$' "the grant-drop counter on $H" "cat $P/dl_drop_grant_n"
    h_grant_dropped=$(head -1 "$OUT/h_grant_dropped.txt" | tr -dc '0-9')
    h_grant_dropped=${h_grant_dropped:-0}
fi
# The DEGRADED report as it stood while the fault was armed, kept verbatim: it
# is the surface the operator would read, and the assertion below is about
# what it listed then, not after the fault cleared.
probe "$W" 20 "$OUT/w_degraded_armed.txt" '^DEGRADED_END$' "the DEGRADED report on $W while armed" "cat /sys/kernel/debug/mxfs/*/acquire_degraded 2>&1; echo DEGRADED_END"
# These fields share a line, so anchoring the match to the start of a line
# silently reads every one of them as empty — and an empty count compares
# equal to nothing, which would score the vacuity gate FAIL on a run that
# proved its point (s578b).  Match the field wherever it sits.
fld() { echo "$armed" | grep -ao "$1=[0-9]*" | head -1 | cut -d= -f2; }
a_alive=$(fld alive)
a_lkwait=$(fld lkwait)
a_drop=$(fld drop)
a_unrec=$(fld unrec)
a_shut=$(fld shut)
a_giveup=$(fld giveup)
a_qack=$(fld qack)
a_deg=$(fld deg)
a_degtarget=$(fld degtarget)
a_dropfirst_ts=$(fld dropfirst_ts)
a_deg_ts=$(fld deg_ts)
a_degfile=$(fld degfile_lists_target)

# What the armed operation itself said, captured BEFORE the knob is cleared —
# after the clear it is indistinguishable from a read that simply worked.
# The blocked operation may legitimately have said NOTHING yet, so an empty
# output is a result here: the sentinel is what proves the read happened.
probe "$W" 20 "$OUT/w_armed_out.txt" '^ARMED_OUT_END$' "the armed operation's output on $W" "cat /tmp/bh_read.out 2>/dev/null; echo ARMED_OUT_END"
echo "  INFO W armed-read output: [$(grep -av '^ARMED_OUT_END$' "$OUT/w_armed_out.txt" | head -c 140 | tr '\n' ' ')]"

echo "  INFO disarming at +$(el)s"
disarm
# The blocked process must be gone before the recovery read means anything.
gone=0
for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
    a=$(timeout 15 $SSH "$W" "test -d /proc/$RPID && echo 1 || echo 0" 2>/dev/null | filt | tr -dc '0-9')
    [ "${a:-1}" = "0" ] && { gone=$(( i * 5 )); break; }
    sleep 5
done
# A FRESH read, so the result is the same question in both modes: with the
# fault cleared, does this node read the file correctly again?  Reusing the
# armed read's output cannot answer it — in the bounded mode that output is
# the failure being asserted.
measure "$W" 90 "$OUT/rv_md5_w_2.txt" '^READ_RC=[0-9]+$' "md5_w on $W" "$(dig "$F") 2>&1; printf '\nREAD_RC=%s\n' \$?"; md5_w=$(grep -av '^READ_RC=' "$OUT/rv_md5_w_2.txt" | grep -aoE '^[0-9a-f]{32}' | head -1)
echo "  INFO after disarm: blocked pid gone_after=${gone}s, fresh read md5_W=${md5_w:-none} at +$(el)s"
# dir_create: did the name land anywhere?  Asked of BOTH nodes, each with a
# cold lookup (a cached negative dentry on W would answer "absent" for a name
# the master holds).  A refused create must have left it on neither.
name_on_h=""; name_on_w=""; entry_on_h=""; entry_on_w=""
if [ -n "$NSOP" ]; then
    # `test -e` follows symlinks; -L or -e together see a dangling one too.
    value_now_into name_on_h "$H" 30 "$OUT/rv_name_on_h_2.txt" '^(1|0)$' "name_on_h on $H" "echo 3 > /proc/sys/vm/drop_caches; { test -e '$F/$WNAME' || test -L '$F/$WNAME'; } && echo 1 || echo 0"; name_on_h=$(printf '%s\n' "$name_on_h" | tr -dc '0-9')
    value_now_into name_on_w "$W" 30 "$OUT/rv_name_on_w_3.txt" '^(1|0)$' "name_on_w on $W" "echo 3 > /proc/sys/vm/drop_caches; { test -e '$F/$WNAME' || test -L '$F/$WNAME'; } && echo 1 || echo 0"; name_on_w=$(printf '%s\n' "$name_on_w" | tr -dc '0-9')
    value_now_into entry_on_h "$H" 30 "$OUT/rv_entry_on_h_4.txt" '^(1|0)$' "entry_on_h on $H" "test -e '$F/$ENAME' && echo 1 || echo 0"; entry_on_h=$(printf '%s\n' "$entry_on_h" | tr -dc '0-9')
    value_now_into entry_on_w "$W" 30 "$OUT/rv_entry_on_w_5.txt" '^(1|0)$' "entry_on_w on $W" "test -e '$F/$ENAME' && echo 1 || echo 0"; entry_on_w=$(printf '%s\n' "$entry_on_w" | tr -dc '0-9')
    echo "  INFO $WORKLOAD: after the disarm $WNAME exists on H=${name_on_h:-?} W=${name_on_w:-?}; $ENAME exists on H=${entry_on_h:-?} W=${entry_on_w:-?} at +$(el)s"
fi
# held_fd_chmod / held_fd_fallocate: did the attribute change land anywhere?
# Both nodes cold (drop_caches, so the stat is a fresh acquire, not a cached
# image).  A refused operation must have left mode, blocks and size as H's
# rewrite set them.
attr_on_h=""; attr_on_w=""
if [ -n "$ATTROP" ]; then
    value_now_into attr_on_h "$H" 30 "$OUT/rv_attr_on_h_3.txt" '^[0-9]+_[0-9]+$' "attr_on_h on $H" "echo 3 > /proc/sys/vm/drop_caches; stat -c '%a_%s' '$F'"; attr_on_h=$(printf '%s\n' "$attr_on_h" | grep -aoE '^[0-9]+_[0-9]+')
    value_now_into attr_on_w "$W" 30 "$OUT/rv_attr_on_w_4.txt" '^[0-9]+_[0-9]+$' "attr_on_w on $W" "echo 3 > /proc/sys/vm/drop_caches; stat -c '%a_%s' '$F'"; attr_on_w=$(printf '%s\n' "$attr_on_w" | grep -aoE '^[0-9]+_[0-9]+')
    echo "  INFO $WORKLOAD: after the disarm mode_size on H=${attr_on_h:-?} W=${attr_on_w:-?} (reference $ATTR0) at +$(el)s"
    if [ "$ATTROP" = truncate ]; then
        # The kept wait completes once the requests flow: the file is now
        # 4096 bytes, so W's recovered read is compared against H's COLD
        # digest of the truncated file, not the setup digest.
        MD5_H_RECOVERED=$(timeout 30 $SSH "$H" "echo 3 > /proc/sys/vm/drop_caches; md5sum '$F' | cut -d' ' -f1" </dev/null 2>/dev/null | filt | grep -aoE '^[0-9a-f]{32}' | head -1)
        echo "  INFO held_fd_truncate: H's cold digest after the truncate landed = ${MD5_H_RECOVERED:-none} at +$(el)s"
    fi
fi
# held_fd_getxattr / held_fd_listxattr: the attribute the driver set before
# the fault must still be there, with its value, on both nodes cold — a
# refused READ changes nothing, and a lost set would be a different defect.
# getfattr is told the names are absolute, or it prints "Removing leading
# '/'" on stderr ahead of the value (s606b scored two rows FAIL on that
# warning); an absent attribute prints "No such attribute", captured too.
xattr_on_h=""; xattr_on_w=""
if [ -n "$XATTROP" ]; then
    measure "$H" 30 "$OUT/rv_xattr_on_h_5.txt" '^READ_RC=[0-9]+$' "xattr_on_h on $H" "echo 3 > /proc/sys/vm/drop_caches; getfattr --absolute-names -n user.d958 --only-values '$F' 2>&1; printf '\nREAD_RC=%s\n' \$?"; xattr_on_h=$(grep -av '^READ_RC=' "$OUT/rv_xattr_on_h_5.txt" | tr -d '\r\n' | head -c 80)
    measure "$W" 30 "$OUT/rv_xattr_on_w_6.txt" '^READ_RC=[0-9]+$' "xattr_on_w on $W" "echo 3 > /proc/sys/vm/drop_caches; getfattr --absolute-names -n user.d958 --only-values '$F' 2>&1; printf '\nREAD_RC=%s\n' \$?"; xattr_on_w=$(grep -av '^READ_RC=' "$OUT/rv_xattr_on_w_6.txt" | tr -d '\r\n' | head -c 80)
    echo "  INFO $WORKLOAD: after the disarm user.d958 cold on H=[${xattr_on_h:-?}] W=[${xattr_on_w:-?}] at +$(el)s"
fi
# drop_grant: H's write changed the bytes (or is about to, in the control,
# where W's fresh read above is what re-affirms and then releases the orphan
# grant and lets H's blocked dd through).  Wait for H's write to be done,
# then compare FRESH digests from both nodes; the setup digest is stale.
h_wt_recovered_s=""
if [ "$FAULT" = "drop_grant" ]; then
    if [ -z "$h_wt_done_s" ]; then
        rt0=$(date +%s)
        for i in $(seq 1 60); do
            d=$(timeout 15 $SSH "$H" "cat /tmp/bh_hw.done 2>/dev/null" </dev/null 2>/dev/null | filt | tr -d '\r')
            [ -n "$d" ] && { h_wt_recovered_s=$(( $(date +%s) - rt0 )); break; }
            sleep 1
        done
        echo "  INFO H's blocked write after the recovery read: $([ -n "$h_wt_recovered_s" ] && echo "completed ${h_wt_recovered_s}s after W's re-request ($d)" || echo "STILL BLOCKED after 60s more") at +$(el)s"
    fi
    md5_h_final=$(timeout 30 $SSH "$H" "md5sum '$F' 2>&1" 2>/dev/null | filt | grep -aoE '^[0-9a-f]{32}' | head -1)
    # the read IS the workload under test: its own failure (EIO, a hang past
    # the bound) is the finding the assertions below make, so the command
    # reports its status on a line of its own and the ssh's status is what
    # ABORTs; an empty digest here is W failing to read, never an ssh that
    # did not run
    measure "$W" 90 "$OUT/rv_md5_w_6.txt" '^MD5_RC=' "W's cold read of $F" "echo 3 > /proc/sys/vm/drop_caches; md5sum '$F' 2>&1; echo MD5_RC=\$?"; md5_w=$(grep -aoE '^[0-9a-f]{32}' "$OUT/rv_md5_w_6.txt" | head -1)
    # W's recovered read is compared against THIS digest; H's read taken
    # while W was blocked (step 5, before H's write of the target) stays
    # compared against the setup digest — s585c scored that check FAIL by
    # replacing the setup digest here and comparing a pre-write read to it.
    MD5_H_RECOVERED=$md5_h_final
    echo "  INFO final digests: H=${md5_h_final:-none} W=${md5_w:-none} at +$(el)s"
fi
MD5_H_RECOVERED=${MD5_H_RECOVERED:-$MD5_H}
# With the fault gone and the wait ended, the report must be empty again and
# the wait's own end must have been said.
probe "$W" 25 "$OUT/w_after_disarm.txt" '^degfile_lines=[0-9]+$' "the post-disarm report on $W" "
    echo degfile_lines=\$(cat /sys/kernel/debug/mxfs/*/acquire_degraded 2>/dev/null | grep -ac 'acq=')
    echo degend=\$($DM | grep -ac 'P958-ACQ-DEGRADED-END') reconf=\$($DM | grep -ac 'P958-ACQ-RECONFIRMED') rejected=\$($DM | grep -ac 'P958-ACQ-STATUS-REJECTED')
  "
after=$(cat "$OUT/w_after_disarm.txt")
echo "  INFO after disarm: $(echo "$after" | tr '\n' ' ')"
fldafter() { echo "$after" | grep -ao "$1=[0-9]*" | head -1 | cut -d= -f2; }
p_degfile_after=$(fldafter degfile_lines)
p_degend=$(fldafter degend)
p_reconf=$(fldafter reconf)
p_rejected=$(fldafter rejected)

sleep 3
hdcap "$W" "$OUT/dmesg_$W.txt"; hdcap "$H" "$OUT/dmesg_$H.txt"

# Abandonment evidence, from both ends, scoped to this run and the target.
w_cancel_sent=$(grep -a 'P958-ACQ-CANCEL-SENT' "$OUT/dmesg_$W.txt" | grep -ac "ino=$TARGET ")
w_cancel_supp=$(grep -a 'P958-ACQ-CANCEL-SUPPRESSED' "$OUT/dmesg_$W.txt" | grep -ac "ino=$TARGET ")
w_cancel_ack=$(grep -a 'P958-ACQ-CANCEL-ACK' "$OUT/dmesg_$W.txt" | grep -a "ino=$TARGET " | grep -ao 'outcome=[0-9]' | sort | uniq -c | tr '\n' ' ')
h_cancel_rx=$(grep -a 'P958-CANCEL-RX' "$OUT/dmesg_$H.txt" | grep -a "ino=$TARGET " | grep -ao 'outcome=[0-9]' | sort | uniq -c | tr '\n' ' ')
h_cancel_rx_n=$(grep -a 'P958-CANCEL-RX' "$OUT/dmesg_$H.txt" | grep -ac "ino=$TARGET ")
h_grant_retired=$(grep -a 'P958-CANCEL-GRANT-RETIRED\|P958-CANCEL-RX .* outcome=3' "$OUT/dmesg_$H.txt" | grep -ac "ino=$TARGET ")
# The other way an orphan grant gets retired: W's phantom reconcile, a
# mirror-bypassing release queued after repeated no-mirror notifications.
w_reconcile=$(grep -a 'P-PHANTOM-RECONCILE-SENT' "$OUT/dmesg_$W.txt" | grep -ac "ino=$TARGET ")
echo "  INFO abandonment: W cancel_sent=$w_cancel_sent suppressed=$w_cancel_supp acks=[${w_cancel_ack}] reconcile_sent=$w_reconcile; H cancel_rx=$h_cancel_rx_n outcomes=[${h_cancel_rx}] grant_retired=$h_grant_retired drop_grant_probe=$h_grant_dropped h_write_done_s=$([ "$FAULT" = "drop_grant" ] && echo "${h_wt_done_s:-blocked}" || echo n/a)"

echo "--- verdict ---"
if [ "$FAULT" = "drop_grant" ]; then
    ck "the grant-drop instrument fired on the master for the target" "$([ "$h_grant_dropped" -ge 1 ] && echo 1 || echo 0)" "1"
else
    ck "the drop instrument fired DURING the armed read (counter reset at the arm)" "$([ "${a_drop:-0}" -ge 1 ] && echo 1 || echo 0)" "1"
fi
ck "H stayed mounted while W was blocked" "${h_mounted:-0}" "1"
ck "H's own read of the same file completed promptly (< 15000 ms)" "$([ "${h_read_ms:-999999}" -lt 15000 ] && echo 1 || echo 0)" "1"
ck "H read the same bytes H wrote (the master is serving correctly)" "$([ "$md5_h_live" = "$MD5_H" ] && echo same || echo differ)" "same"
if [ "$LEASE_PARK_MS" = 0 ]; then
    ck "W read the file again once the requests flowed" "$([ -n "$md5_w" ] && echo 1 || echo 0)" "1"
    ck "W's recovered read returned the correct bytes" "$([ "$md5_w" = "$MD5_H_RECOVERED" ] && echo same || echo differ)" "same"
else
    # The lease arm withdraws W's mount on purpose, so "W reads it again"
    # cannot hold and must not be asserted.  What replaces it is the REASON:
    # the recovery is absent because the filesystem was shut down by the
    # closure, not because the disarm silently failed to take effect.  An
    # assertion removed without a replacement is an assertion relaxed.
    ck "W's filesystem was shut down by the closure, which is why it does not read again" \
       "$(grep -ac 'Shutting down filesystem' "$OUT/dmesg_$W.txt" 2>/dev/null | awk '{print ($1>=1)?1:0}')" "1"
    ck "W did not quietly recover and read stale bytes instead" \
       "$([ -z "$md5_w" ] || [ "$md5_w" = "$MD5_H_RECOVERED" ] && echo ok || echo stale)" "ok"
fi
ck "W's blocked process is gone after the disarm" "$([ "$gone" -gt 0 ] && echo 1 || echo 0)" "1"
if [ "$WORKLOAD" != "open" ]; then
    # The point of this workload is that the acquire under the fault belongs to
    # a caller that is NOT open().  If mxfs_dlm_open_protect appears in the
    # blocked task's stack the run measured the already-fixed site again and
    # its verdict means nothing, whichever way it went.
    # the samples were each validated as they were taken; their aggregate is
    # what the call-site assertions below read
    # WHICH CAPTURE HOLDS THE STACK depends on when the task was still there.
    # The armed-window sampler runs on a 60 s cadence; in the lease arm the
    # waiter is ended by the closure within seconds, long before the first
    # sample, so the only capture taken while it was genuinely blocked is the
    # pre-close probe.  Reading the empty one would fail a call site that was
    # measured, and reading it in the non-lease arms would lose the samples.
    if [ "$LEASE_PARK_MS" = 0 ]; then
        STACKSRC="$OUT/w_samples.txt"
        capture_require "$STACKSRC" '^alive=[01] state=' "the armed-window samples on $W"
    else
        STACKSRC="$OUT/w_preclose.txt"
        capture_require "$STACKSRC" '^blocked=[01] ' "the pre-close blocked-task capture on $W"
    fi
    st_openprot=$(grep -ac 'mxfs_dlm_open_protect' "$STACKSRC" 2>/dev/null)
    st_acq=$(grep -ac 'mxfs_dlm_ilock_begin' "$STACKSRC" 2>/dev/null)
    ck "the blocked task was in an inode acquire" "$([ "${st_acq:-0}" -ge 1 ] && echo 1 || echo 0)" "1"
    ck "the blocked acquire was NOT the open() call site" "${st_openprot:-1}" "0"
    # ...and it was the site this workload exists to measure.
    if [ "$WORKLOAD" = "held_fd_read" ]; then
        ck "the blocked acquire was the read path's (xfs_file_read_iter / read envelope in the stack)" "$(grep -aq 'xfs_file_read_iter\|mxfs_read_coherency_envelope\|ksys_read\|vfs_read' "$STACKSRC" && echo 1 || echo 0)" "1"
    elif [ "$WORKLOAD" = "held_fd_write" ]; then
        ck "the blocked acquire was the write path's (xfs_file_write_iter / buffered_write / vfs_write in the stack)" "$(grep -aq 'xfs_file_write_iter\|xfs_file_buffered_write\|ksys_write\|vfs_write' "$STACKSRC" && echo 1 || echo 0)" "1"
    elif [ "$WORKLOAD" = "held_fd_dio_unaligned" ]; then
        ck "the blocked acquire was the direct write's (xfs_file_dio_write_unaligned / xfs_file_write_iter / pwrite in the stack)" "$(grep -aq 'xfs_file_dio_write_unaligned\|xfs_file_write_iter\|xfs_file_dio_write\|ksys_pwrite\|vfs_write' "$STACKSRC" && echo 1 || echo 0)" "1"
    elif [ "$WORKLOAD" = "held_fd_chmod" ]; then
        ck "the blocked acquire was the attribute change's (xfs_setattr_nonsize / xfs_vn_setattr / notify_change / fchmod in the stack)" "$(grep -aq 'xfs_setattr_nonsize\|xfs_vn_setattr\|notify_change\|chmod_common\|sys_fchmod\|xfs_trans_alloc_ichange' "$STACKSRC" && echo 1 || echo 0)" "1"
    elif [ "$WORKLOAD" = "held_fd_fallocate" ]; then
        ck "the blocked acquire was fallocate's (xfs_file_fallocate / vfs_fallocate / sys_fallocate in the stack)" "$(grep -aq 'xfs_file_fallocate\|vfs_fallocate\|sys_fallocate\|ksys_fallocate' "$STACKSRC" && echo 1 || echo 0)" "1"
    elif [ "$WORKLOAD" = "held_fd_truncate" ]; then
        ck "the blocked acquire was the truncate's (xfs_setattr_size / xfs_vn_setattr / do_truncate / ftruncate in the stack)" "$(grep -aq 'xfs_setattr_size\|xfs_vn_setattr\|do_truncate\|sys_ftruncate\|notify_change' "$STACKSRC" && echo 1 || echo 0)" "1"
    elif [ -n "$FAULTOP" ]; then
        ck "the blocked acquire was the page fault's (xfs_filemap_fault / xfs_write_fault / do_page_mkwrite / handle_mm_fault / exc_page_fault in the stack)" "$(grep -aq 'xfs_filemap_fault\|xfs_write_fault\|xfs_filemap_page_mkwrite\|do_page_mkwrite\|do_shared_fault\|handle_mm_fault\|do_user_addr_fault\|exc_page_fault\|xfs_vn_update_time' "$STACKSRC" && echo 1 || echo 0)" "1"
    elif [ "$WORKLOAD" = "held_fd_setxattr" ] || [ "$WORKLOAD" = "held_fd_removexattr" ] || [ "$WORKLOAD" = "held_fd_setxattr_nofork" ]; then
        ck "the blocked acquire was the extended-attribute change's (xfs_attr_set / xfs_attr_add_fork / xfs_attr_change / setxattr / removexattr in the stack)" "$(grep -aq 'xfs_attr_set\|xfs_attr_add_fork\|xfs_attr_change\|xfs_xattr_set\|vfs_setxattr\|vfs_removexattr\|setxattr\|removexattr\|xfs_trans_alloc_inode' "$STACKSRC" && echo 1 || echo 0)" "1"
    elif [ -n "$XATTROP" ]; then
        ck "the blocked acquire was the extended-attribute read's (xfs_attr_get / xfs_attr_list / xfs_ilock_attr_map_shared / getxattr / listxattr in the stack)" "$(grep -aq 'xfs_attr_get\|xfs_attr_list\|xfs_ilock_attr_map_shared\|xfs_xattr_get\|xfs_vn_listxattr\|vfs_getxattr\|vfs_listxattr\|getxattr\|listxattr' "$STACKSRC" && echo 1 || echo 0)" "1"
    elif [ "$WORKLOAD" = "dir_lookup" ]; then
        ck "the blocked acquire was the lookup's (xfs_lookup / xfs_vn_lookup / lookup_slow / statx in the stack)" "$(grep -aq 'xfs_lookup\|xfs_vn_lookup\|lookup_slow\|__lookup_slow\|do_statx\|vfs_statx' "$STACKSRC" && echo 1 || echo 0)" "1"
    elif [ -n "$NSOP" ]; then
        case "$NSOP" in
        create)  nsframes='xfs_create\|xfs_generic_create\|lookup_open\|path_openat\|do_filp_open' ;;
        unlink)  nsframes='xfs_remove\|xfs_vn_unlink\|vfs_unlink\|do_unlinkat' ;;
        rename)  nsframes='xfs_rename\|xfs_vn_rename\|vfs_rename\|do_renameat2' ;;
        link)    nsframes='xfs_link\|xfs_vn_link\|vfs_link\|do_linkat' ;;
        symlink) nsframes='xfs_symlink\|xfs_vn_symlink\|vfs_symlink\|do_symlinkat' ;;
        esac
        ck "the blocked acquire was the $NSOP's ($nsframes in the stack)" "$(grep -aq "$nsframes" "$STACKSRC" && echo 1 || echo 0)" "1"
        # ...and not the lookup that precedes it: a stack in xfs_lookup means
        # a lookup was not cached and the wrong site met the fault.
        ck "the blocked acquire was NOT the lookup's (no xfs_lookup in the stack)" "$(grep -ac 'xfs_lookup' "$STACKSRC")" "0"
    elif [ "$ISDIR" = "1" ]; then
        ck "the blocked acquire was readdir's (xfs_file_readdir / iterate_dir / getdents64 in the stack)" "$(grep -aq 'xfs_file_readdir\|iterate_dir\|getdents64\|xfs_readdir\|xfs_dir2_leaf_getdents' "$STACKSRC" && echo 1 || echo 0)" "1"
    else
        ck "the blocked acquire was getattr's (vfs_fstat / mxfs_getattr_dlm_lock in the stack)" "$(grep -aq 'vfs_fstat\|mxfs_getattr_dlm_lock\|newfstat' "$STACKSRC" && echo 1 || echo 0)" "1"
    fi
    echo "  W blocked-task caller frames: $(grep -a 'xfs_file\|xfs_ilock\|mxfs_dlm\|read_iter\|readdir\|getdents\|sys_\|xfs_setattr\|xfs_vn_setattr\|xfs_trans_alloc\|fallocate' "$STACKSRC" 2>/dev/null | sed 's/^ *//' | sort -u | tr '\n' ' ' | cut -c1-400)"
fi
case "${EXPECT:-observe}" in
lease_abort)
    # The closure, not the budget, must be what ends the wait.
    #
    # Ending is not the assertion.  This wait always ends eventually — at its
    # own acquire budget, or when a shutdown tears the mount down underneath
    # it — and either of those would satisfy "it terminated" while leaving the
    # defect exactly where it was.  What is asserted is the INTERVAL between
    # the kernel's own P290-AUTH-CLOSED and the task ceasing to exist.
    ck "the lease actually closed under the blocked waiter" "$([ -n "$lease_closed_s" ] && echo 1 || echo 0)" "1"
    ck "the blocked waiter ended" "$([ -n "$lease_exit_s" ] && echo 1 || echo 0)" "1"
    if [ -n "$lease_delta_s" ]; then
        echo "  INFO closure-to-exit interval: ${lease_delta_s}s (bound ${LEASE_ABORT_BOUND_S}s)"
        ck "the CLOSURE is what ended the wait, not the acquire budget" \
           "$([ "$lease_delta_s" -le "$LEASE_ABORT_BOUND_S" ] && echo within || echo "over(${lease_delta_s}s)")" "within"
        # A negative interval would mean the wait ended BEFORE the lease
        # closed, which is some other mechanism and not this one.
        ck "the wait did not end before the lease closed" \
           "$([ "$lease_delta_s" -ge 0 ] && echo after || echo before)" "after"
    fi
    # The abort must reach the caller as an error, not as a silent success.
    ck "the aborted operation reported a failure to userspace" \
       "$(grep -aqi 'input/output error\|cannot open\|no such\|error' "$OUT/w_lease_readout.txt" 2>/dev/null && echo 1 || echo 0)" "1"
    ;;
bounded)
    # After a fix that bounds this wait: the operation must END inside the
    # armed window, and it must end without the requester shutting its own
    # filesystem down.  Both halves are required — a run that terminates by
    # taking the shutdown has not fixed anything, it has gone back.
    ck "W's blocked operation ended inside the armed window" "${a_alive:-1}" "0"
    ck "W did not take the unrecoverable-timeout shutdown" "${a_unrec:-0}" "0"
    ck "W did not shut its filesystem down" "${a_shut:-0}" "0"
    # It has to end for the RIGHT reason.  An operation that ends because the
    # drop stopped firing, or because it quietly succeeded, says nothing about
    # the bound being real.
    ck "W ended it by refusing the unreceipted acquire" "$([ "${a_giveup:-0}" -ge 1 ] && echo 1 || echo 0)" "1"
    ck "W's operation reported the failure to userspace" "$(grep -aqi 'input/output error\|cannot open\|sigbus\|bus error' "$OUT/w_armed_out.txt" 2>/dev/null && echo 1 || echo 0)" "1"
    # 0.84.2: the refusal is returned at the audited acquisition itself, and
    # each audited site says so by name.
    case "$WORKLOAD" in
    held_fd)      ck "the refusal was getattr's own (P958-GETATTR-REFUSED for the target)" "$([ "$(grep -a 'P958-GETATTR-REFUSED' "$OUT/dmesg_$W.txt" | grep -ac "ino=$TARGET ")" -ge 1 ] && echo 1 || echo 0)" "1" ;;
    held_fd_read) ck "the refusal was the read path's own (P958-READ-REFUSED for the target)" "$([ "$(grep -a 'P958-READ-REFUSED' "$OUT/dmesg_$W.txt" | grep -ac "ino=$TARGET ")" -ge 1 ] && echo 1 || echo 0)" "1" ;;
    held_fd_write)
        ck "the refusal was the write path's own (P958-WRITE-REFUSED for the target)" "$([ "$(grep -a 'P958-WRITE-REFUSED' "$OUT/dmesg_$W.txt" | grep -ac "ino=$TARGET ")" -ge 1 ] && echo 1 || echo 0)" "1"
        ck "the refused write moved no bytes (no write_bytes= from the driver)" "$(grep -ac 'write_bytes=' "$OUT/w_armed_out.txt")" "0"
        ck "no open or getattr refusal for the target (the driver reached the write)" "$(grep -a 'P912-OPEN-UNRECEIPTED\|P958-GETATTR-REFUSED' "$OUT/dmesg_$W.txt" | grep -ac "ino=$TARGET ")" "0" ;;
    held_fd_dio_unaligned)
        dio_stages=$(grep -a 'P958-WRITE-REFUSED' "$OUT/dmesg_$W.txt" | grep -a "ino=$TARGET " | grep -ao 'stage=[a-z-]*' | sort | uniq -c | tr -s ' ' | tr '\n' ';')
        echo "  INFO write refusals for the target by stage: [${dio_stages:-none}]"
        ck "the refusal was the write's own past its cached first ride (P958-WRITE-REFUSED stage=timestamp or stage=unaligned-excl-retry for the target)" "$([ "$(grep -a 'P958-WRITE-REFUSED' "$OUT/dmesg_$W.txt" | grep -a "ino=$TARGET " | grep -ac 'stage=timestamp\|stage=unaligned-excl-retry')" -ge 1 ] && echo 1 || echo 0)" "1"
        ck "the refusal was not the first ride's (the re-cached PR served it: no stage=first for the target)" "$(grep -a 'P958-WRITE-REFUSED' "$OUT/dmesg_$W.txt" | grep -a "ino=$TARGET " | grep -ac 'stage=first')" "0"
        ck "the first (shared) ride was not the one refused (no stage=first refusal for the target)" "$(grep -a 'P958-WRITE-REFUSED' "$OUT/dmesg_$W.txt" | grep -a "ino=$TARGET " | grep -ac 'stage=first')" "0"
        ck "the refused direct write moved no bytes (no dio_write_bytes= from the driver)" "$(grep -ac 'dio_write_bytes=' "$OUT/w_armed_out.txt")" "0"
        ck "no open or getattr refusal for the target (the driver reached the write)" "$(grep -a 'P912-OPEN-UNRECEIPTED\|P958-GETATTR-REFUSED' "$OUT/dmesg_$W.txt" | grep -ac "ino=$TARGET ")" "0" ;;
    held_fd_chmod)
        ck "the refusal was the attribute change's own (P958-SETATTR-REFUSED op=chmod for the target)" "$([ "$(grep -a 'P958-SETATTR-REFUSED' "$OUT/dmesg_$W.txt" | grep -a "ino=$TARGET " | grep -ac 'op=chmod ')" -ge 1 ] && echo 1 || echo 0)" "1"
        ck "the refused chmod reported no success to the driver (no chmod_ok= line)" "$(grep -ac 'chmod_ok=' "$OUT/w_armed_out.txt")" "0"
        ck "the refused chmod changed the mode on neither node (H cold == reference)" "$([ -n "$attr_on_h" ] && [ "$attr_on_h" = "$ATTR0" ] && echo same || echo differ)" "same"
        ck "the refused chmod changed the mode on neither node (W cold == reference)" "$([ -n "$attr_on_w" ] && [ "$attr_on_w" = "$ATTR0" ] && echo same || echo differ)" "same"
        ck "no open, getattr or write refusal for the target (the driver reached the chmod)" "$(grep -a 'P912-OPEN-UNRECEIPTED\|P958-GETATTR-REFUSED\|P958-WRITE-REFUSED' "$OUT/dmesg_$W.txt" | grep -ac "ino=$TARGET ")" "0"
        ck "no 'Corruption of in-memory data' (a dirty cancel) on W" "$(grep -ac 'Corruption of in-memory' "$OUT/dmesg_$W.txt")" "0" ;;
    held_fd_mmap_read|held_fd_mmap_write)
        fstages=$(grep -a 'P958-FAULT-REFUSED' "$OUT/dmesg_$W.txt" | grep -a "ino=$TARGET " | grep -ao 'stage=[a-z-]*' | sort | uniq -c | tr -s ' ' | tr '\n' ';')
        echo "  INFO fault refusals for the target by stage: [${fstages:-none}]"
        ck "the refusal was the page fault's own (P958-FAULT-REFUSED for the target)" "$([ -n "$fstages" ] && echo 1 || echo 0)" "1"
        if [ "$WORKLOAD" = "held_fd_mmap_read" ]; then
            ck "the refused acquire was the read fault's counted hold (stage=read-hold)" "$(echo "$fstages" | grep -aq 'stage=read-hold' && echo 1 || echo 0)" "1"
        else
            # The write fault's read half rides the cached PR only while
            # the inode's stale flag is clear, which a preceding read cannot
            # guarantee (ccmemory trap-a-cached-pr-is-not-a-fast-path-when-
            # the-inode-is-marked-stale); whichever registered acquire met
            # the discarded request is the fault's own boundary.
            ck "the refused acquire was one of the write fault's (stage=timestamp, write-hold, or the read half's read-hold)" "$(echo "$fstages" | grep -aq 'stage=timestamp\|stage=write-hold\|stage=read-hold' && echo 1 || echo 0)" "1"
            echo "  INFO held_fd_mmap_write: write-side stage reached: $(echo "$fstages" | grep -aq 'stage=timestamp\|stage=write-hold' && echo yes || echo 'no (the read half sent the request)')"
        fi
        ck "the driver's mapping was made before the fault (mmap_ok=1)" "$(grep -ac '^mmap_ok=1' "$OUT/w_armed_out.txt")" "1"
        ck "the faulting child was killed by SIGBUS (${FAULTOP}_rc=-7 SIGBUS reported by the parent)" "$(grep -ac "^${FAULTOP}_rc=-7 SIGBUS" "$OUT/w_armed_out.txt")" "1"
        ck "the refused $FAULTOP returned nothing to the driver (no ${FAULTOP}_ok= line)" "$(grep -ac "${FAULTOP}_ok=" "$OUT/w_armed_out.txt")" "0"
        if [ "$WORKLOAD" = "held_fd_mmap_write" ]; then
            measure "$H" 20 "$OUT/rv_rv7_7.txt" '^READ_RC=[0-9]+$' "rv7 on $H" "echo 3 > /proc/sys/vm/drop_caches; head -c 4 '$F'; printf '\nREAD_RC=%s\n' \$?"; rv7=$(grep -av '^READ_RC=' "$OUT/rv_rv7_7.txt" | tr -d '\n' | grep -ac '^mmw!$')
            ck "the refused store changed no byte on the master (H's first bytes are not mmw!)" "$rv7" "0"
        fi
        ck "the refused operation changed nothing: H cold mode_size == reference" "$([ -n "$attr_on_h" ] && [ "$attr_on_h" = "$ATTR0" ] && echo same || echo differ)" "same"
        ck "no open, getattr, read or write refusal for the target (the driver reached the fault)" "$(grep -a 'P912-OPEN-UNRECEIPTED\|P958-GETATTR-REFUSED\|P958-READ-REFUSED\|P958-WRITE-REFUSED' "$OUT/dmesg_$W.txt" | grep -ac "ino=$TARGET ")" "0"
        ck "no 'Corruption of in-memory data' (a dirty cancel) on W" "$(grep -ac 'Corruption of in-memory' "$OUT/dmesg_$W.txt")" "0"
        ck "no kernel splat on W (no 'BUG:' / 'WARNING:' / 'Oops')" "$(grep -ac 'BUG:\|WARNING:\|Oops' "$OUT/dmesg_$W.txt")" "0" ;;
    held_fd_getxattr|held_fd_listxattr|held_fd_setxattr|held_fd_removexattr|held_fd_setxattr_nofork)
        xrefusals=$(grep -a 'P958-XATTR-REFUSED\|P958-XATTRSET-REFUSED' "$OUT/dmesg_$W.txt" | grep -a "ino=$TARGET " | grep -ao 'P958-XATTR[A-Z]*-REFUSED.* \(op\|stage\)=[a-z]*' | sed 's/ino=[0-9]* //' | sort | uniq -c | tr -s ' ' | tr '\n' ';')
        echo "  INFO xattr refusals for the target: [${xrefusals:-none}]"
        if [ "$WORKLOAD" = "held_fd_setxattr" ] || [ "$WORKLOAD" = "held_fd_setxattr_nofork" ]; then
            echo "  INFO setxattr path seen by the kernel: [$(grep -a 'P958-XATTRSET-PATH' "$OUT/dmesg_$W.txt" | grep -a "ino=$TARGET " | tail -1 | sed 's/^\[[^]]*\] //' | cut -c1-200)]"
        fi
        ck "the refusal was the $ATTROP site's own ($XPROBE $XFIELD for the target)" "$([ "$(grep -a "$XPROBE" "$OUT/dmesg_$W.txt" | grep -a "ino=$TARGET " | grep -ac "$XFIELD")" -ge 1 ] && echo 1 || echo 0)" "1"
        case "$WORKLOAD" in
        held_fd_getxattr|held_fd_listxattr|held_fd_removexattr|held_fd_setxattr_nofork)
            ck "the driver's set landed before the fault (setxattr_ok=1)" "$(grep -ac '^setxattr_ok=1' "$OUT/w_armed_out.txt")" "1" ;;
        esac
        [ "$WORKLOAD" = "held_fd_setxattr_nofork" ] && ck "the driver removed the attribute (and the fork) before the fault (removexattr_ok=1)" "$(grep -ac 'removexattr_ok=1' "$OUT/w_armed_out.txt")" "1"
        ck "the refused ${ATTROP} returned nothing to the driver (no ${WORKLOAD#held_fd_}_ok= line)" "$(grep -ac "${WORKLOAD#held_fd_}_ok=" "$OUT/w_armed_out.txt")" "0"
        case "$WORKLOAD" in
        held_fd_getxattr|held_fd_listxattr|held_fd_removexattr)
            ck "the refused operation changed nothing: user.d958 still reads v958 on the master, cold" "${xattr_on_h:-none}" "v958"
            ck "the refused operation changed nothing: user.d958 still reads v958 on the requester, cold" "${xattr_on_w:-none}" "v958" ;;
        held_fd_setxattr|held_fd_setxattr_nofork)
            ck "the refused set wrote nothing: user.d958 absent on the master, cold" "$(echo "${xattr_on_h:-}" | grep -aci 'no such attribute')" "1"
            ck "the refused set wrote nothing: user.d958 absent on the requester, cold" "$(echo "${xattr_on_w:-}" | grep -aci 'no such attribute')" "1" ;;
        esac
        ck "the refused operation changed nothing: H cold mode_size == reference" "$([ -n "$attr_on_h" ] && [ "$attr_on_h" = "$ATTR0" ] && echo same || echo differ)" "same"
        ck "no open, getattr or write refusal for the target (the driver reached the operation)" "$(grep -a 'P912-OPEN-UNRECEIPTED\|P958-GETATTR-REFUSED\|P958-WRITE-REFUSED' "$OUT/dmesg_$W.txt" | grep -ac "ino=$TARGET ")" "0"
        ck "no 'Corruption of in-memory data' (a dirty cancel) on W" "$(grep -ac 'Corruption of in-memory' "$OUT/dmesg_$W.txt")" "0" ;;
    held_fd_fallocate)
        ck "the refusal was fallocate's own (P958-FALLOCATE-REFUSED for the target)" "$([ "$(grep -a 'P958-FALLOCATE-REFUSED' "$OUT/dmesg_$W.txt" | grep -ac "ino=$TARGET ")" -ge 1 ] && echo 1 || echo 0)" "1"
        ck "the refused fallocate reported no success to the driver (no fallocate_ok= line)" "$(grep -ac 'fallocate_ok=' "$OUT/w_armed_out.txt")" "0"
        ck "the refused fallocate allocated nothing (H cold mode_size == reference)" "$([ -n "$attr_on_h" ] && [ "$attr_on_h" = "$ATTR0" ] && echo same || echo differ)" "same"
        ck "the refused fallocate allocated nothing (W cold mode_size == reference)" "$([ -n "$attr_on_w" ] && [ "$attr_on_w" = "$ATTR0" ] && echo same || echo differ)" "same"
        ck "no open, getattr or write refusal for the target (the driver reached the fallocate)" "$(grep -a 'P912-OPEN-UNRECEIPTED\|P958-GETATTR-REFUSED\|P958-WRITE-REFUSED' "$OUT/dmesg_$W.txt" | grep -ac "ino=$TARGET ")" "0"
        ck "no 'Corruption of in-memory data' (a dirty cancel) on W" "$(grep -ac 'Corruption of in-memory' "$OUT/dmesg_$W.txt")" "0" ;;
    dir_lookup)
        lk_stages=$(grep -a 'P958-LOOKUP-REFUSED' "$OUT/dmesg_$W.txt" | grep -a "ino=$TARGET " | grep -ao 'stage=[a-z-]*' | sort | uniq -c | tr '\n' ' ')
        echo "  INFO lookup refusals for the target by stage: [${lk_stages:-none}]"
        ck "the refusal was the lookup's own (P958-LOOKUP-REFUSED for the target directory)" "$([ -n "$lk_stages" ] && echo 1 || echo 0)" "1"
        ck "the refused lookup returned no inode (no lookup_ino= from the driver)" "$(grep -ac 'lookup_ino=' "$OUT/w_armed_out.txt")" "0"
        ck "no open, getattr or readdir refusal for the target (the driver reached the lookup)" "$(grep -a 'P912-OPEN-UNRECEIPTED\|P958-GETATTR-REFUSED\|P958-READDIR-REFUSED' "$OUT/dmesg_$W.txt" | grep -ac "ino=$TARGET ")" "0" ;;
    dir_*)
        # The kernel names the operation by its XFS entry: unlink is "remove".
        kop=$NSOP; [ "$NSOP" = unlink ] && kop=remove
        ck "the refusal was the $NSOP's own (P958-NAMESPACE-REFUSED op=$kop for the target directory)" "$([ "$(grep -a "P958-NAMESPACE-REFUSED op=$kop " "$OUT/dmesg_$W.txt" | grep -ac "ino=$TARGET ")" -ge 1 ] && echo 1 || echo 0)" "1"
        ck "the refused $NSOP reported no success to the driver (no ${NSOP}_fd=/_ok= line)" "$(grep -ac "${NSOP}_fd=\|${NSOP}_ok=" "$OUT/w_armed_out.txt")" "0"
        if [ "$NSOP" = create ]; then
            # The cancel must have been of a CLEAN transaction: the create's
            # own cancel probe names the directory and prints the dirty bit.
            cr3=$(grep -a "P-CR3-CANCEL error=-5 dp_ino=$TARGET " "$OUT/dmesg_$W.txt" | head -1)
            echo "  INFO dir_create cancel line: [${cr3:-none}]"
            ck "the create cancelled its transaction CLEAN (P-CR3-CANCEL trans_dirty=0 for the target)" "$(echo "$cr3" | grep -ac 'trans_dirty=0')" "1"
            ck "the cancel allocated no inode (dialloc_ino=0 new_ino=0)" "$(echo "$cr3" | grep -ac 'dialloc_ino=0 new_ino=0')" "1"
        fi
        ck "no open, getattr or readdir refusal for the target (the driver reached the $NSOP)" "$(grep -a 'P912-OPEN-UNRECEIPTED\|P958-GETATTR-REFUSED\|P958-READDIR-REFUSED' "$OUT/dmesg_$W.txt" | grep -ac "ino=$TARGET ")" "0"
        case "$NSOP" in
        create|rename|link|symlink)
            ck "the refused $NSOP wrote no new name on the master (H does not see $WNAME)" "${name_on_h:-1}" "0"
            ck "the refused $NSOP wrote no new name on the requester (W does not see $WNAME, cold)" "${name_on_w:-1}" "0" ;;
        esac
        case "$NSOP" in
        unlink|rename|link)
            ck "the refused $NSOP left the existing entry on the master (H still sees $ENAME)" "${entry_on_h:-0}" "1"
            ck "the refused $NSOP left the existing entry on the requester (W still sees $ENAME)" "${entry_on_w:-0}" "1" ;;
        esac
        ck "no 'Corruption of in-memory data' (a dirty cancel) on W" "$(grep -ac 'Corruption of in-memory' "$OUT/dmesg_$W.txt")" "0"
        ck "no dirty rename cancel on W (P217-RENAME-DIRTYCANCEL)" "$(grep -ac 'P217-RENAME-DIRTYCANCEL' "$OUT/dmesg_$W.txt")" "0" ;;
    held_dir_readdir|leaf_midlist)
        rd_stages=$(grep -a 'P958-READDIR-REFUSED' "$OUT/dmesg_$W.txt" | grep -a "ino=$TARGET " | grep -ao 'stage=[a-z-]*' | sort | uniq -c | tr '\n' ' ')
        echo "  INFO readdir refusals for the target by stage: [${rd_stages:-none}]"
        ck "the refusal was readdir's own (P958-READDIR-REFUSED for the target)" "$([ -n "$rd_stages" ] && echo 1 || echo 0)" "1"
        # The refusal must not have been taken by an already-audited site
        # the driver was written to avoid: no open and no getattr refusal
        # for the target on this lap.
        ck "no open or getattr refusal for the target (the driver reached readdir)" "$(grep -a 'P912-OPEN-UNRECEIPTED\|P958-GETATTR-REFUSED' "$OUT/dmesg_$W.txt" | grep -ac "ino=$TARGET ")" "0"
        if [ "$WORKLOAD" = "leaf_midlist" ]; then
            # The site under test is the per-block re-acquire, reached only
            # after entries from earlier blocks were handed to userspace:
            # the first getdents64 call returned names, the refusal names
            # stage=leaf, and the second call got the error.
            first_names=$(grep -ao 'names=[0-9]*' "$OUT/w_armed_out.txt" | head -1 | cut -d= -f2)
            ck "the first getdents64 returned the entries emitted before the pause (names > 0)" "$([ "${first_names:-0}" -ge 1 ] && echo 1 || echo 0)" "1"
            ck "the refusal was the leaf per-block re-acquire (stage=leaf)" "$(echo "$rd_stages" | grep -aq 'stage=leaf' && echo 1 || echo 0)" "1"
            ck "the following getdents64 call returned the error (getdents_rc=-1)" "$(grep -aq 'getdents_rc=-1' "$OUT/w_armed_out.txt" && echo 1 || echo 0)" "1"
        else
            ck "the driver's getdents64 returned the error (getdents_rc=-1)" "$(grep -aq 'getdents_rc=-1' "$OUT/w_armed_out.txt" && echo 1 || echo 0)" "1"
        fi
        ;;
    esac
    # EXACT abandonment (0.84.1): the master is told by name and answers with
    # what it held.  drop_req: it never saw the request, so ABSENT (1) and a
    # tombstone; drop_grant: it held W's grant, so GRANT RETIRED (3) — and
    # H's own write of the file, queued behind that grant, completes.
    if [ "$CONTROL_NO_CANCEL" = "1" ]; then
        ck "control: W abandoned WITHOUT telling the master (cancel suppressed)" "$([ "$w_cancel_supp" -ge 1 ] && echo 1 || echo 0)" "1"
        ck "control: the master received no cancel for the target" "$h_cancel_rx_n" "0"
        # Without the cancel the orphan grant is retired only by W's phantom
        # reconcile, which needs H's write to have blocked long enough to
        # send two no-mirror notifications inside 15 s.  The write's wall is
        # the measurement (10 s on s585d); what is asserted is the mechanism.
        ck "control: W's phantom reconcile released the orphan grant (P-PHANTOM-RECONCILE-SENT for the target)" "$([ "$w_reconcile" -ge 1 ] && echo 1 || echo 0)" "1"
        ck "control: H's write of the target was blocked until that release (> 1 s)" "$([ -n "$h_wt_done_s" ] && [ "$h_wt_done_s" -gt 1 ] && echo 1 || echo 0)" "1"
        ck "control: H's write did complete once the reconcile released the orphan" "$([ -n "$h_wt_done_s" ] || [ -n "$h_wt_recovered_s" ] && echo 1 || echo 0)" "1"
    else
        ck "W told the master it abandoned the wait (LOCK_CANCEL sent for the target)" "$([ "$w_cancel_sent" -ge 1 ] && echo 1 || echo 0)" "1"
        if [ "$FAULT" = "drop_grant" ]; then
            ck "the master retired W's undelivered grant on the cancel (outcome 3)" "$([ "$h_grant_retired" -ge 1 ] && echo 1 || echo 0)" "1"
            ck "W received the cancel ack naming the retired grant (outcome=3)" "$(echo "$w_cancel_ack" | grep -aq 'outcome=3' && echo 1 || echo 0)" "1"
            ck "H's write of the target completed promptly after W gave up (< 15 s)" "$([ -n "$h_wt_done_s" ] && [ "$h_wt_done_s" -lt 15 ] && echo 1 || echo 0)" "1"
            # ...and because of the cancel, not because the reconcile happened
            # to fire first: a lap where both retire the grant proves nothing
            # about which one the write waited on.
            ck "the orphan was retired by the cancel, not by W's phantom reconcile (no P-PHANTOM-RECONCILE-SENT for the target)" "$w_reconcile" "0"
        else
            ck "the master answered the cancel ABSENT (it never had the request) (outcome 1)" "$(echo "$h_cancel_rx" | grep -aq 'outcome=1' && echo 1 || echo 0)" "1"
            ck "W received the cancel ack (outcome=1)" "$(echo "$w_cancel_ack" | grep -aq 'outcome=1' && echo 1 || echo 0)" "1"
        fi
    fi
    ;;
hang)
    # Asserting the defect as it stands, for a build that is expected to
    # still have it.
    ck "W's operation was still blocked at the end of the armed window" "${a_alive:-0}" "1"
    ck "W never reached the fail-fast arm" "${a_unrec:-1}" "0"
    ;;
degraded)
    # BOUNDED DETECTION of a wait that cannot be failed.  The caller stays
    # blocked (that is the shape being measured, not a defect in the
    # detector), takes no shutdown, and the wait is reported DEGRADED inside
    # its bound from the first dropped request, listed in the mount's debugfs
    # while the fault stands, and delisted with its end said once the fault
    # clears.  DEGRADE_BOUND_S is the bound the build derives (acq_degrade_ms,
    # default 45 s); the slack is the 1 s re-send granularity plus the
    # classifier's 5 s backoff between restarts.
    DEGRADE_BOUND_S=${DEGRADE_BOUND_S:-45}
    ck "W's operation was still blocked at the end of the armed window (non-fallible caller)" "${a_alive:-0}" "1"
    ck "W did not take the unrecoverable-timeout shutdown" "${a_unrec:-0}" "0"
    ck "W did not shut its filesystem down" "${a_shut:-0}" "0"
    ck "W reported the target's wait DEGRADED (P958-ACQ-DEGRADED naming ino=$TARGET)" "$([ "${a_degtarget:-0}" -ge 1 ] && echo 1 || echo 0)" "1"
    # The detection latency is read from the DEGRADED line's OWN fields, not
    # from the drop probe's timestamps: that probe prints only its first 8
    # hits and every 64th, so "the first armed drop" is usually a line that
    # was never printed and the grep lands on a later one (s581b scored -8 s).
    # unanswered_ms is how long the wait had gone without an accepted
    # confirmation when the detector fired; age_ms equals it when the master
    # never confirmed at all, which is this fault's shape.
    degline=$(grep -a 'P958-ACQ-DEGRADED ' "$OUT/dmesg_$W.txt" | grep -a "ino=$TARGET " | head -1)
    unans_ms=$(echo "$degline" | grep -ao 'unanswered_ms=[0-9]*' | cut -d= -f2)
    age_ms=$(echo "$degline" | grep -ao ' age_ms=[0-9]*' | cut -d= -f2)
    bound_ms=$(echo "$degline" | grep -ao 'bound_ms=[0-9]*' | cut -d= -f2)
    if [ -n "$unans_ms" ] && [ -n "$bound_ms" ]; then
        echo "  INFO detection latency: unanswered_ms=$unans_ms age_ms=${age_ms:-?} bound_ms=$bound_ms (slack 6000 ms: the 1 s re-send granularity plus the classifier's 5 s backoff)"
        ck "the build's bound is the derived one (${DEGRADE_BOUND_S}s)" "$bound_ms" "$(( DEGRADE_BOUND_S * 1000 ))"
        ck "DEGRADED was reported no earlier than the bound" "$([ "$unans_ms" -ge "$bound_ms" ] && echo 1 || echo 0)" "1"
        ck "DEGRADED was reported inside the bound plus slack" "$([ "$unans_ms" -le $(( bound_ms + 6000 )) ] && echo 1 || echo 0)" "1"
        ck "the master never confirmed this wait (age == unanswered)" "$([ "${age_ms:-x}" = "$unans_ms" ] && echo 1 || echo 0)" "1"
    else
        ck "the DEGRADED line carried its unanswered_ms and bound_ms fields" "0" "1"
    fi
    ck "acquire_degraded listed the target while the fault was armed" "$([ "${a_degfile:-0}" -ge 1 ] && echo 1 || echo 0)" "1"
    ck "acquire_degraded is empty again after the fault cleared" "${p_degfile_after:-1}" "0"
    ck "the degraded wait's end was said (P958-ACQ-DEGRADED-END or RECONFIRMED)" "$([ $(( ${p_degend:-0} + ${p_reconf:-0} )) -ge 1 ] && echo 1 || echo 0)" "1"
    echo "  INFO status receipts rejected as stale/mismatched during the lap: ${p_rejected:-?}"
    if [ "$ATTROP" = truncate ]; then
        # The honest completion of a kept wait: once the requests flow the
        # operation lands, correctly, on both nodes, and reports success.
        value_now_into rv7 "$W" 20 "$OUT/rv_rv7_7.txt" '^[0-9]+$' "rv7 on $W" "grep -ac 'truncate_ok=1' /tmp/bh_read.out || [ \$? = 1 ]"
        ck "the kept truncate reported success once the requests flowed (truncate_ok=1 from the driver)" "$rv7" "1"
        ck "the truncate landed on the master (H cold size 4096, mode unchanged)" "${attr_on_h:-none}" "$(echo "$ATTR0" | cut -d_ -f1)_4096"
        ck "the truncate landed on the requester (W cold size 4096, mode unchanged)" "${attr_on_w:-none}" "$(echo "$ATTR0" | cut -d_ -f1)_4096"
        ck "no refusal of any kind for the target (the wait was kept, not failed)" "$(grep -a 'P912-ACQ-UNRECEIPTED\|P958-SETATTR-REFUSED\|P958-FALLOCATE-REFUSED\|P958-WRITE-REFUSED\|P912-OPEN-UNRECEIPTED\|P958-GETATTR-REFUSED' "$OUT/dmesg_$W.txt" | grep -ac "ino=$TARGET ")" "0"
        ck "no 'Corruption of in-memory data' on W" "$(grep -ac 'Corruption of in-memory' "$OUT/dmesg_$W.txt")" "0"
    fi
    ;;
esac
echo "--- what W did during the armed window (the measurement) ---"
echo "  W read still blocked at the end of the armed window: alive=${a_alive:-?} (1 = still blocked)"
echo "  W P-LKWAIT-LIVE lines=${a_lkwait:-?}  requests dropped during the armed read=${a_drop:-?}"
echo "  W 'DLM inode lock unrecoverable' lines=${a_unrec:-?}  'Shutting down filesystem' lines=${a_shut:-?}"
echo "  W last classifier line: $(echo "$armed" | sed -n 's/^beyond=//p')"
if [ "$ISDIR" = "1" ]; then
    # Bound: 8 x DIR_ENTRIES unlinks at ~14 ms each, plus the rmdirs.
    timeout $(( 8 * DIR_ENTRIES / 50 + 40 )) $SSH "$H" "rm -f '$MNT/.lockreqbh_${LABEL}_probe'; rm -rf '$MNT'/.lockreqbh_${LABEL}_1 '$MNT'/.lockreqbh_${LABEL}_2 '$MNT'/.lockreqbh_${LABEL}_3 '$MNT'/.lockreqbh_${LABEL}_4 '$MNT'/.lockreqbh_${LABEL}_5 '$MNT'/.lockreqbh_${LABEL}_6 '$MNT'/.lockreqbh_${LABEL}_7 '$MNT'/.lockreqbh_${LABEL}_8" >/dev/null 2>&1
else
timeout 15 $SSH "$H" "rm -f '$F' '$MNT/.lockreqbh_${LABEL}_probe' '$MNT'/.lockreqbh_${LABEL}_1 '$MNT'/.lockreqbh_${LABEL}_2 '$MNT'/.lockreqbh_${LABEL}_3 '$MNT'/.lockreqbh_${LABEL}_4 '$MNT'/.lockreqbh_${LABEL}_5 '$MNT'/.lockreqbh_${LABEL}_6 '$MNT'/.lockreqbh_${LABEL}_7 '$MNT'/.lockreqbh_${LABEL}_8" >/dev/null 2>&1
fi
echo "=== tcp_lockreq_blackhole $LABEL: fails=$fails wall=$(el)s out=$OUT $(date -u +%FT%TZ) ==="
[ "$fails" -eq 0 ]
