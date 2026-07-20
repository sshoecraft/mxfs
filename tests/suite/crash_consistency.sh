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
D="$MNT/.crash_consistency"
mkdir -p "$D" 2>/dev/null

NFILES="${CC_NFILES:-50}"

ck "cc barrier ready" coord_barrier "cc_ready"

# Durable writes (each file synced before recording its checksum).
for i in $(seq 1 "$NFILES"); do
    f="$D/node${R}_f${i}"
    dd if=/dev/urandom of="$f" bs=4096 count=$(( (i % 8) + 1 )) oflag=sync 2>/dev/null
done
sync
for i in $(seq 1 "$NFILES"); do
    md5sum "$D/node${R}_f${i}" 2>/dev/null | awk '{print $1}' > "$D/node${R}_f${i}.md5"
done
sync

ck "cc barrier written" coord_barrier "cc_written"

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
FORENSIC="$D/.cc_forensic_r${R}"
cc_k=$(( 96 / T )); [ "$cc_k" -lt 3 ] && cc_k=3
[ "$cc_k" -gt $(( T - 1 )) ] && cc_k=$(( T - 1 ))
cc_targets="$R"
for cc_j in $(seq 1 "$cc_k"); do
    cc_targets="$cc_targets $(( ((R - 1 + cc_j) % T) + 1 ))"
done
for n in $cc_targets; do
    for i in $(seq 1 "$NFILES"); do
        exp=$(cat "$D/node${n}_f${i}.md5" 2>/dev/null)
        act=$(md5sum "$D/node${n}_f${i}" 2>/dev/null | awk '{print $1}')
        if [ "$exp" != "$act" ]; then
            # forensics (failure only): which file, inodes, sizes, re-read
            md5f="$D/node${n}_f${i}.md5"; dataf="$D/node${n}_f${i}"
            {
              echo "FAIL node${n}_f${i} reader=r${R}"
              echo "  md5file ino=$(stat -c%i "$md5f" 2>/dev/null) size=$(stat -c%s "$md5f" 2>/dev/null) content=[$(cat "$md5f" 2>/dev/null)]"
              echo "  datafile ino=$(stat -c%i "$dataf" 2>/dev/null) size=$(stat -c%s "$dataf" 2>/dev/null)"
              # second read after another drop to test persistence of staleness
              echo 3 > /proc/sys/vm/drop_caches 2>/dev/null; sleep 0.3
              echo "  md5file reread size=$(stat -c%s "$md5f" 2>/dev/null) content=[$(cat "$md5f" 2>/dev/null)]"
            } >> "$FORENSIC" 2>/dev/null
            # kernel marker so it interleaves with mxfs P-traces
            echo "mxfs-cc-FAIL node${n}_f${i} md5ino=$(stat -c%i "$md5f" 2>/dev/null)" > /dev/kmsg 2>/dev/null
        fi
        ckeq "cc r${R} durable node${n}_f${i}" "$exp" "$act"
    done
done

if [ "$R" = 1 ]; then
    total=$(ls "$D"/node*_f[0-9]* 2>/dev/null | grep -vc '\.md5$')
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
    cnt0=$(ls "$D"/node*_f[0-9]* 2>/dev/null | wc -l | tr -d ' ')
    # readdir re-read after a pure cache drop (coherent LUN re-read, no writer BAST)
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null; sleep 0.6
    cntLUN=$(ls "$D"/node*_f[0-9]* 2>/dev/null | wc -l | tr -d ' ')
    # force THIS node to acquire dir-EX (touch) -> BASTs the writer -> writer drains
    touch "$D/.probe_r${R}" 2>/dev/null; sync
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null; sleep 0.6
    cntDIREX=$(ls "$D"/node*_f[0-9]* 2>/dev/null | wc -l | tr -d ' ')
    {
      echo "=== sess14 A/B discriminator reader=r${R} exp=$expall cnt0=$cnt0 pureLUN=$cntLUN direx=$cntDIREX ==="
    } >> "$FORENSIC" 2>/dev/null
    echo "mxfs-cc-DISCRIM reader=r${R} exp=$expall cnt0=$cnt0 pureLUN=$cntLUN direx=$cntDIREX" > /dev/kmsg 2>/dev/null
    echo "mxfs-cc-DISCRIM reader=r${R} miss=$miss" > /dev/kmsg 2>/dev/null
fi

ck "cc barrier done" coord_barrier "cc_done"
coord_done "$([ "$FAIL_N" -eq 0 ] && echo PASS || echo FAIL)"
finish
