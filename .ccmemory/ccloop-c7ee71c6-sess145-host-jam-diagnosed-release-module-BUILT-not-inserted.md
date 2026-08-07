---
name: ccloop-c7ee71c6-sess145-host-jam-diagnosed-release-module-BUILT-not-inserted
description: sess145: clyde-wide D-pileup (load 521) fully diagnosed to the sess141 leaked i_dio_count; inode_dio_release.ko BUILT + GPT GO; NOT YET INSERTED.
metadata:
  type: project
tags: [fence, host-jam, i_dio_count, inode_dio_release, D-PR-FENCE-PREEMPT-WITHOUT-ABORT, sess145, rule5]
---

# sess145 — the leaked i_dio_count now jams the whole host; fix built, not yet run

## What was found (all measured via /proc stacks; ps/pgrep THEMSELVES WEDGE — never run them bare, use the awk /proc sweep in the transcript)

Cascade, each link proven by a stack read:
1. Parked loop worker kworker/u113:15+loop0 pid 1758538 in ext4_dio_write_checks+0x127 → inode_dio_wait on fio-backing.img (leaked i_dio_count=1, re-measured =1 this session; ino 62527935 dev 259:2 size 2147483648).
2. loop0 busy_iter: exactly 2 in-flight — rq[0] dd's 4KiB write (bvec on dd's live vmap stack; loop_unwedge's BAD flag is a FALSE POSITIVE for vmap stacks), rq[1] bio-less flush_rq tag 31.
3. mount pid 1833866 in jbd2_write_superblock → __wait_on_buffer: its PREFLUSH sb write is parked in the blk-mq flush FSM pending list behind the stuck flush_rq (invisible to busy_iter). mount 1834825 queued on super_lock behind it. Both started Aug 4 19:27/19:29.
4. NEW COLLATERAL: ffmpeg pid 1867972 (started Aug 4 20:10 by user's mmprocess daemon) in THP fault → direct compaction → buffer_migrate_folio_norefs → __lock_buffer on the locked jbd2 buffer — D forever HOLDING ITS mmap_lock (read).
5. khugepaged pid 365 in collapse_huge_page → mmap_write_lock(ffmpeg mm) — queued writer; THP collapse stalled host-wide.
6. rwsem writer-fairness ⇒ every /proc/1867972/cmdline reader queues: 266 pgrep + 246 ps in D. User's `*/10 * * * * mmrun` cron (crontab steve) dead since Aug 5 03:10 (~44h). Load 521. THIS is why sess143/144 died: their ps/pgrep probes hung the session.

## The fix (GPT RULE-5: CONDITIONAL GO, sess145 transcript has the 9 mandatory items)

`scripts/inode_dio_release/` — BUILT ok vermagic 6.8.0-101-generic. Performs the dead task's missing inode_dio_end: atomic_cmpxchg(&i_dio_count,1,0) ONE attempt (count==1 at swap ⇒ provably the leaked token; live DIO would make it ≥2) + wake_up_var. Identity interlocks in-module: ino+dev 259:2+EXT4 magic+S_ISREG+size. Userspace pre-checks PASSED: /sys/block/loop0/loop/backing_file == /var/lib/mxfs-fence/fio-backing.img, ino/size match.

Late-legit-inode_dio_end underflow ruled out structurally: token returns only via iomap_dio_complete at dio->ref==0; the GPF-killed task never dropped the submitter's initial ref (dies mid-__iomap_dio_rw), so ref can never hit 0; nvme inflight 0 0 (no bio left to complete). GPT wanted this CHECKED AGAINST SOURCE — ~/src/linux/fs/iomap/direct-io.c NOT FOUND at that path; locate the file (find ~/src/linux -name direct-io.c) and confirm the dio->ref init-to-1 + tail-drop pattern before acting.

## EXECUTION CHECKLIST for next session (in order)

1. Verify iomap dio->ref pattern in source (above).
2. Pause the producer: `crontab -l | sed 's|^\*/10 \* \* \* \* /home/steve/.local/bin/mmrun|#PAUSED-mxfs-sess145 &|' | crontab -` (RESTORE AFTER — do not forget; user infra).
3. `cd /src/mxfs/scripts/inode_dio_release && sudo insmod inode_dio_release.ko path=/var/lib/mxfs-fence/fio-backing.img expect_ino=62527935 expect_major=259 expect_minor=2 expect_size=2147483648` (act=0 probe) → dmesg → rmmod.
4. Same with act=1 → expect "RELEASED the leaked token (1 -> 0)". rmmod.
5. Watch drain ≤30s (RULE 0 budget: worker+dd+flush ms, jbd2 via 50ms dm-delay ~100ms, mounts <5s, reader herd seconds): kworker 1758538 stack changes/exits; /proc/1833866,1834825,1845104,1867972 exit or leave D; khugepaged 365 back to S; awk sweep shows pgrep/ps D-count → 0; loadavg falls.
6. If a gen-0 mount SUCCEEDED (check /proc/mounts for fiomnt/mxfsfencef): umount it. Recovered fs is TAINTED — never serve it (GPT #8).
7. Restore crontab line (remove #PAUSED-mxfs-sess145 marker).
8. loop_unwedge act=0 on /dev/loop0 → expect 0 in-flight. Leave loop0+dm+image ATTACHED and quarantined (GPT #4/#9: no teardown during/after drain; do not delete/modify the backing file while attached).
9. Write outcome memory; THEN resume the actual queue: fence stage-(ii) gen-1 (`sudo MXFS_FENCE_MODE=fileio bash tests/fence_inflight/stack.sh up`, ruled order 0x04→0x05→0x04 ARM_SEQ=1,2,3, verdict.py) — sess142 memory has details. Also verify SCST bvec-UAF patch deployment (target version 3.11.0-pre+caw-abort-reclaim.2) before generating fileio traffic.

## Standing cautions
- NEVER bare ps/pgrep/top until the jam is confirmed drained; timeout everything; the awk-over-/proc sweep is the safe census.
- stack.sh quarantine hung sess143/145 probes — assume it shells a /proc walker; only use it post-drain (and check why later).
- RULE 2: no clyde reboot, ever. All of this exists to avoid one.
