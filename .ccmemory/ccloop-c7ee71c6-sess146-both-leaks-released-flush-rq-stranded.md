---
name: ccloop-c7ee71c6-sess146-both-leaks-released-flush-rq-stranded
description: sess146: BOTH sess141 leaks fixed (i_dio_count + i_rwsem reader via up_read_non_owner, GPT GO). Kworker+dd freed. REMAINING: flush_rq tag31 stranded,…
metadata:
  type: project
tags: [host-jam, i_dio_count, i_rwsem, flush-rq, loop0, sess146, rule5, cron-paused]
---

# sess146 — dead task's TWO leaks released; one stranded flush_rq remains

## Done this session (all on clyde, module scripts/inode_dio_release/)
1. GPT item: iomap dio->ref init-1/tail-drop CONFIRMED in /src/linux (7.1-rc7) fs/iomap/direct-io.c:709,803,142,868. NOTE: kernel source is at /src/linux NOT ~/src/linux.
2. **Cron PAUSED**: steve's crontab mmrun line commented with `#PAUSED-mxfs-sess145` — **MUST RESTORE after drain** (`sed 's|^#PAUSED-mxfs-sess145 ||'`).
3. act=1 released i_dio_count 1→0 (cmpxchg ok). FIRST WAKE WAS WRONG KEY: 6.8 inode_dio_end = wake_up_bit(&i_state, __I_DIO_WAKEUP=9) (inline in fs.h:3160), NOT wake_up_var(&i_dio_count) (that's ≥6.10ish + 7.1). act=2 (added) issued both wakes. Nothing woke — because:
4. **sess145 misdiagnosis corrected**: kworker 1758538 was NOT in inode_dio_wait (no such frame in /proc/stack; /proc filters .sched.text so rwsem sleeps hide the top frame). It was in the ext4_dio_write_checks shared→exclusive UPGRADE inode_lock() (dd write targets unwritten/fallocated block ⇒ *unwritten forces upgrade). The dead task leaked BOTH the dio token AND its SHARED i_rwsem hold.
5. Probe (act=0) now prints raw rwsem: count=0x102 (1 reader bias + WAITERS), owner=kworker|0x3. owner word is BEST-EFFORT for readers (stamped by every down_read, never cleared w/o DEBUG_RWSEMS) — pointed at the LIVE waiter itself; NOT a validity guard.
6. GPT RULE-5 consult #2: CONDITIONAL GO on ONE up_read_non_owner (maps to up_read on this CONFIG_DEBUG_LOCK_ALLOC=n kernel; symbol itself not exported). Guards: exact count==0x102 re-read immediately before, READER_OWNED flag, dio==0, one attempt, NEVER a second decrement or supplementary wake.
7. act=3 FIRED: count 0x102→0x2. **kworker 1758538 FREED (idle), dd 1845104 COMPLETED+EXITED.**

## REMAINING JAM (next session start here)
- **flush_rq tag=31 (op=FLUSH, PREFLUSH, FLUSH_SEQ) still state=in_flight** in /sys/kernel/debug/block/loop0/hctx0/busy. NOTE /sys/block/loop0/inflight shows 0 0 — flush-seq rqs are NOT counted there (accounting skip); do not trust it.
- Behind it: jbd2 sb write (PREFLUSH|FUA from jbd2_mark_journal_empty) of mount 1833866 parked in loop0's flush FSM pending; mount 1834825 on super_lock; dm-0 (mxfsfencef = dm-delay 0ms over loop0, 252:0) shows 1 write inflight; both mounts = `mount /dev/mapper/mxfsfencef /var/lib/mxfs-fence/fiomnt`.
- ffmpeg 1867972 still D holding mmap_lock (locked jbd2 buffer via THP compaction migrate), khugepaged 365 D behind it, ps/pgrep herd behind that. Load still ~522 (avg decays slowly; instantaneous D-count already collapsed).
- **Kworker sweep: NO kworker anywhere has loop frames** ⇒ the flush loop_cmd sits on some loop cmd_list with NO work scheduled. THEORY (unproven): the GPF-dead worker's `struct worker` stays in pool busy_hash forever marked executing its work item; later queue_work of THAT work item appends to the dead worker's ->scheduled list = swallowed forever. Which work item (per-blkcg loop_worker vs rootcg_work) unresolved — flush_rq is bio-less ⇒ cmd->blkcg_css=NULL ⇒ rootcg list (7.1 loop.c:1875; 6.8 similar) BUT then 1758538 should have drained it after dd. CONTRADICTION UNRESOLVED — measure, don't guess.
- Candidate probes: (a) module to walk lo->rootcg_cmd_list/workers (private 6.8 struct loop layout — risky, no 6.8 source per RULE 1); (b) cheap functional test: submit one small O_DIRECT read to /dev/loop0 from root cgroup → forces queue_work(rootcg_work); if it completes, list got drained (flush too); if it hangs D, work item is swallowed ⇒ that read leaks one D task (weigh first, maybe GPT). (c) blk_mq debugfs deeper: hctx0/sched_tags, flush state not directly visible.
- loop_unwedge module (scripts/loop_unwedge) has busy_iter dump (act=0) + BAD-flag false positive for vmap stacks.
- Post-drain checklist unchanged: umount any late gen-0 fiomnt mounts (TAINTED, never serve), keep loop0+dm+backing attached/quarantined, RESTORE CRON, then fence stage-(ii) gen-1 + SCST bvec-UAF patch deploy check (target 3.11.0-pre+caw-abort-reclaim.2).
- Standing: no bare ps/pgrep until herd drains; timeout everything; never read /proc/1867972/cmdline (its mmap_lock has queued writer).
