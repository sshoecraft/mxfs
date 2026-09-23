#!/bin/bash
# crash_consistency — committed-data durability + cross-node consistency after
# cache loss (the invariant crash recovery depends on).
#
# Each node writes N files with O_SYNC/fsync (so they are journaled + on the
# shared LUN), records their checksums, and barriers.  Then EVERY node drops
# its page/inode/dentry caches (cold state, as after a crash+remount) and
# re-reads EVERY node's files from the shared device, asserting every checksum
# and the global file count survived.  A committed write that vanishes or
# differs after a cold reload would be lost on a real crash → FAIL.
#
# NOTE: a true node-KILL + survivor foreign-log-replay needs host-side
# orchestration the in-guest run_coord harness doesn't have; this validates the
# durability/consistency guarantee crash recovery rests on, guest-side + safe.
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"

R="$RANK"; T="$NODES"
# sess489: CC_TAG=<word> puts this run's files in a directory of their own
# (.crash_consistency_<word>) so a second run on the SAME mount creates its
# files instead of overwriting the previous run's.  Chain 139's armed rows
# re-ran on the mount their failed rows had left behind, so their 23-29 s
# "passes" were 3200 O_TRUNC overwrites of existing files and measured no
# create at all (the create-cost probe fired 102 times on 9 nodes instead of
# 3200 on 32).  Pass it through MXFS_TEST_ENV="CC_TAG=fresh2".
D="$MNT/.crash_consistency${CC_TAG:+_$CC_TAG}"
# sess464 (D-32NODE-SHARED-DIR-CREATE-PACE stage 2 evidence): CC_SHARDED=N
# makes the ONE shared directory a SHARDED directory with N containers
# (MXFS_IOC_DIRSHARD_MKDIR via tests/dirshard_ioctl.py, rank 1 creates it,
# every rank waits on the ready barrier before touching it).  Same workload,
# same checks, same 90 s budget; the pre-stage-3 evidence list in
# docs/dir-sharding.md compares N=16/32/64 against the unsharded and the
# CC_PRIVATE=1 baselines.  Pass it through MXFS_TEST_ENV="CC_SHARDED=32".
# A node without the feature (EOPNOTSUPP) fails the run: the variant asserts
# the feature, it does not fall back.  The feature needs a filesystem made
# with mkfs.mxfs -D (prep with MXFS_MKFS_OPTS=-D) and the module parameter
# dirshard_mkdir_enable, which the creating rank turns on here.
if [ -n "${CC_SHARDED:-}" ]; then
    if [ "$R" = 1 ]; then
        if [ ! -d "$D" ]; then
            echo 1 > /sys/module/mxfs/parameters/dirshard_mkdir_enable
            out=$(python3 /src/mxfs/tests/dirshard_ioctl.py mkdir "$MNT" ".crash_consistency" "$CC_SHARDED" 2>&1)
            ckeq "cc sharded mkdir N=$CC_SHARDED" "OK" "$(echo "$out" | tail -1)"
        fi
        st=$(python3 /src/mxfs/tests/dirshard_ioctl.py info "$D" 2>/dev/null | sed -n 's/^state=\([A-Z]*\) nshards=\([0-9]*\).*/\1 \2/p')
        ckeq "cc sharded dir state" "PUBLISHED $CC_SHARDED" "$st"
    fi
else
    mkdir -p "$D" 2>/dev/null
fi

# ccloop c7ee71c6 sess6: arm the kernel dir-block probe family (P-DIRWR incl.
# the new danode arm, P10-RDBLK, ...) on THIS run's shared dir.  The 181124Z
# torn da3-node CRC (5-node shutdown cascade) had ZERO write-side traces
# because only dir_reuse armed watch_ino.  Same pattern/knob as dir_reuse.
if [ "${MXFS_WATCH_ARM:-1}" = 1 ]; then
    cc_watch=$(stat -c '%i' "$D" 2>/dev/null)
    [ -n "$cc_watch" ] && echo "$cc_watch" > /sys/module/mxfs/parameters/watch_ino 2>/dev/null || true
fi

NFILES="${CC_NFILES:-50}"

# sess10 (ccloop 72513a13) N-INVARIANT reader set — see the verify loop below
# for why each node reads its own files plus the next cc_k peers rather than
# every node's.  Computed here because the assertion plan depends on it.
cc_k=$(( 96 / T )); [ "$cc_k" -lt 3 ] && cc_k=3
[ "$cc_k" -gt $(( T - 1 )) ] && cc_k=$(( T - 1 ))

# sess481: declare the assertion count BEFORE any work, so a run that dies on
# its budget reports how much it never reached.  At 32 nodes this run intends
# 204 assertions and 200 of them are the cross-node durable verify; the
# 20260904T000831Z board spent all 90 s in the write phase and reached the
# verify on ZERO nodes, yet reported "checks=1 passed=1 failed=0" — which was
# read as a clean run.  planned=/notrun= is what makes that unmistakable.
cc_plan=3                                        # ready + written + done barriers
cc_plan=$(( cc_plan + (cc_k + 1) * NFILES ))     # own + cc_k peers, durable verify
[ "$R" = 1 ] && cc_plan=$(( cc_plan + 1 ))       # total durable file count
# sharded variant: rank 1 asserts the published dir state, peers its visibility
# (rank 1's mkdir check is conditional on the dir not already existing, so it is
# deliberately not counted — under-declaring is safe, over-declaring is not).
[ -n "${CC_SHARDED:-}" ] && cc_plan=$(( cc_plan + 1 ))
suite_plan "$cc_plan"

# sess436 (D-32NODE-SHARED-DIR-CREATE-PACE, design-consult ruling measurement 5):
# CC_PRIVATE=1 = the HEADROOM variant — every node writes into its OWN
# subdirectory of $D instead of the one shared directory, so the only
# shared resource is the parent (mkdir once) and the workload measures
# what the fleet can do when no directory lock rotates.  Pass it through
# MXFS_TEST_ENV="CC_PRIVATE=1".  Never a board condition: the board row
# stays the shared-directory workload.
ccdir() { if [ "${CC_PRIVATE:-0}" = 1 ]; then echo "$D/n$1"; else echo "$D"; fi; }
ccglob() { if [ "${CC_PRIVATE:-0}" = 1 ]; then ls "$D"/n*/node*_f[0-9]* 2>/dev/null; else ls "$D"/node*_f[0-9]* 2>/dev/null; fi; }
# CC_PRIVATE needs the per-node subdirectory; a SHARDED parent refuses child
# directories (Model A), so the two variants are mutually exclusive.
if [ -z "${CC_SHARDED:-}" ]; then
    mkdir -p "$(ccdir "$R")" 2>/dev/null
fi

echo "mxfs-CCph rank=$R PHASE=start" > /dev/kmsg 2>/dev/null || true
ck "cc barrier ready" coord_barrier "cc_ready"
if [ -n "${CC_SHARDED:-}" ] && [ "$R" != 1 ]; then
    # rank 1 published the sharded directory before the barrier
    ckeq "cc sharded dir visible" "1" "$([ -d "$D" ] && echo 1 || echo 0)"
fi

echo "mxfs-CCph rank=$R PHASE=barrier-ready-done" > /dev/kmsg 2>/dev/null || true
# Durable writes (each file synced before recording its checksum).
for i in $(seq 1 "$NFILES"); do
    f="$(ccdir "$R")/node${R}_f${i}"
    dd if=/dev/urandom of="$f" bs=4096 count=$(( (i % 8) + 1 )) oflag=sync 2>/dev/null
done
sync
echo "mxfs-CCph rank=$R PHASE=datawrite-done" > /dev/kmsg 2>/dev/null || true
for i in $(seq 1 "$NFILES"); do
    md5sum "$(ccdir "$R")/node${R}_f${i}" 2>/dev/null | awk '{print $1}' > "$(ccdir "$R")/node${R}_f${i}.md5"
done
sync

echo "mxfs-CCph rank=$R PHASE=md5write-done" > /dev/kmsg 2>/dev/null || true
ck "cc barrier written" coord_barrier "cc_written"

echo "mxfs-CCph rank=$R PHASE=barrier-written-done" > /dev/kmsg 2>/dev/null || true
# Cold reload: drop caches so the next reads come from the shared LUN.
sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null
sleep 1

# Cross-node durable verify.  sess10 (ccloop 72513a13): N-INVARIANT reader
# set — "every node reads EVERY node" was O(N^2) cold reads (32 nodes:
# 3200 files+sidecars per node = 102400 cluster-wide; verify dominated the
# 109s wall vs the 90s budget).  Each node now verifies its OWN files plus
# the next K peers (rotating), K = max(3, 96/T) capped at T-1 — every
# file is still cold-read by >=K distinct REMOTE readers, which is the
# cross-node durability assertion; only the redundancy factor shrinks at
# high N (32: own+3 peers; 16: own+6; 8: own+12; <=4: full mesh as before).
echo "mxfs-CCph rank=$R PHASE=dropcaches-done" > /dev/kmsg 2>/dev/null || true
FORENSIC="$D/.cc_forensic_r${R}"
cc_targets="$R"
for cc_j in $(seq 1 "$cc_k"); do
    cc_targets="$cc_targets $(( ((R - 1 + cc_j) % T) + 1 ))"
done
for n in $cc_targets; do
    for i in $(seq 1 "$NFILES"); do
        exp=$(cat "$(ccdir "$n")/node${n}_f${i}.md5" 2>/dev/null)
        act=$(md5sum "$(ccdir "$n")/node${n}_f${i}" 2>/dev/null | awk '{print $1}')
        if [ "$exp" != "$act" ]; then
            # forensics (failure only): which file, inodes, sizes, re-read
            md5f="$(ccdir "$n")/node${n}_f${i}.md5"; dataf="$(ccdir "$n")/node${n}_f${i}"
            {
              echo "FAIL node${n}_f${i} reader=r${R}"
              echo "  md5file ino=$(stat -c%i "$md5f" 2>/dev/null) size=$(stat -c%s "$md5f" 2>/dev/null) content=[$(cat "$md5f" 2>/dev/null)]"
              echo "  datafile ino=$(stat -c%i "$dataf" 2>/dev/null) size=$(stat -c%s "$dataf" 2>/dev/null) blocks=$(stat -c%b "$dataf" 2>/dev/null)"
              # sess33 (D-CRASH-COLDREAD-STALE-SPLIT): arm the kernel probe
              # family on the DATA inode before the heal tests so the re-read
              # path traces (FUA read, reload, adopt decisions) land in dmesg.
              stat -c%i "$dataf" 2>/dev/null > /sys/module/mxfs/parameters/watch_ino 2>/dev/null || true
              # second read after another drop to test persistence of staleness
              echo 3 > /proc/sys/vm/drop_caches 2>/dev/null; sleep 0.3
              echo "  md5file reread size=$(stat -c%s "$md5f" 2>/dev/null) content=[$(cat "$md5f" 2>/dev/null)]"
              # sess33: the 20260731T131837Z incident rereread only the
              # sidecar — the DATA file's heal behavior is the discriminator
              # (stale extent map/dinode heals only via reload; a lagging
              # PLATTER heals when the writer's flush finally lands).  Reread
              # data now and again after 2s.
              echo "  datafile reread1 size=$(stat -c%s "$dataf" 2>/dev/null) blocks=$(stat -c%b "$dataf" 2>/dev/null) md5=$(md5sum "$dataf" 2>/dev/null | awk '{print $1}')"
              sleep 2; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null; sleep 0.3
              echo "  datafile reread2 size=$(stat -c%s "$dataf" 2>/dev/null) blocks=$(stat -c%b "$dataf" 2>/dev/null) md5=$(md5sum "$dataf" 2>/dev/null | awk '{print $1}')"
              echo "  dmesg-tail-for-ino:"
              dmesg 2>/dev/null | grep "ino=$(stat -c%i "$dataf" 2>/dev/null)" | tail -6 | sed 's/^/    /'
            } >> "$FORENSIC" 2>/dev/null
            # kernel marker so it interleaves with mxfs P-traces
            echo "mxfs-cc-FAIL node${n}_f${i} md5ino=$(stat -c%i "$md5f" 2>/dev/null)" > /dev/kmsg 2>/dev/null
        fi
        ckeq "cc r${R} durable node${n}_f${i}" "$exp" "$act"
    done
done

echo "mxfs-CCph rank=$R PHASE=verify-done" > /dev/kmsg 2>/dev/null || true
if [ "$R" = 1 ]; then
    total=$(ccglob | grep -vc '\.md5$')
    # sess493: this assertion failed 203/204 on rank 1 (run 20260904T095615Z)
    # with no other marker anywhere — the count is the only check that does
    # not name what it missed.  Record the number and the names on both
    # sides so a miss is attributable: absent = expected entries readdir did
    # not return (a lost or unlanded dirent), extra = names readdir returned
    # that no node created (a stale or duplicated block image).
    if [ "$total" != "$((T * NFILES))" ]; then
        cc_seen=$(ccglob | grep -v '\.md5$' | sed 's|.*/||' | sort)
        cc_want=$(for n in $(seq 1 "$T"); do for i in $(seq 1 "$NFILES"); do echo "node${n}_f${i}"; done; done | sort)
        cc_absent=$(comm -23 <(echo "$cc_want") <(echo "$cc_seen") | tr '\n' ',' | cut -c1-400)
        cc_extra=$(comm -13 <(echo "$cc_want") <(echo "$cc_seen") | tr '\n' ',' | cut -c1-400)
        echo "mxfs-cc-COUNT reader=r${R} exp=$((T * NFILES)) act=$total absent=[$cc_absent] extra=[$cc_extra]" > /dev/kmsg 2>/dev/null
        echo "COUNT exp=$((T * NFILES)) act=$total absent=[$cc_absent] extra=[$cc_extra]" >> "$FORENSIC" 2>/dev/null
    fi
    ckeq "cc total durable file count" "$((T * NFILES))" "$total"
fi

# sess14 CASE-A/B discriminator (runs inline on the reliable full-suite repro,
# while both nodes still hold their cluster state).  Fires only on this node's
# failure.  Identifies a missing peer file, then:
#   PROBE-pureLUN : drop_caches + re-stat (coherent LUN re-read, no writer BAST)
#   PROBE-direx   : touch a file in $D (forces THIS node dir-EX acquire -> BASTs
#                   the writer -> writer drains to final location) + re-stat
# pureLUN restores  => CASE A (reader cache stale; gen-inval didn't fire).
# only direx restores => CASE B (entry not at final on-disk location until the
#                       writer is BASTed into flushing it).
if [ "$FAIL_N" -gt 0 ]; then
    # count ALL expected entries (data + md5) for every node = 2*T*NFILES
    expall=$(( 2 * T * NFILES ))
    cnt0=$(ccglob | wc -l | tr -d ' ')
    # readdir re-read after a pure cache drop (coherent LUN re-read, no writer BAST)
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null; sleep 0.6
    cntLUN=$(ccglob | wc -l | tr -d ' ')
    # force THIS node to acquire dir-EX (touch) -> BASTs the writer -> writer drains
    touch "$D/.probe_r${R}" 2>/dev/null; sync
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null; sleep 0.6
    cntDIREX=$(ccglob | wc -l | tr -d ' ')
    {
      echo "=== sess14 A/B discriminator reader=r${R} exp=$expall cnt0=$cnt0 pureLUN=$cntLUN direx=$cntDIREX ==="
    } >> "$FORENSIC" 2>/dev/null
    echo "mxfs-cc-DISCRIM reader=r${R} exp=$expall cnt0=$cnt0 pureLUN=$cntLUN direx=$cntDIREX" > /dev/kmsg 2>/dev/null
    echo "mxfs-cc-DISCRIM reader=r${R} miss=$miss" > /dev/kmsg 2>/dev/null
fi

echo "mxfs-CCph rank=$R PHASE=count-done" > /dev/kmsg 2>/dev/null || true
ck "cc barrier done" coord_barrier "cc_done"
echo "mxfs-CCph rank=$R PHASE=barrier-done-done" > /dev/kmsg 2>/dev/null || true
coord_done "$([ "$FAIL_N" -eq 0 ] && echo PASS || echo FAIL)"
finish
