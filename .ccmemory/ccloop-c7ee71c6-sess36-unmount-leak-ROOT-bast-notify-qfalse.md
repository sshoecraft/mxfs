---
name: ccloop-c7ee71c6-sess36-unmount-leak-ROOT-bast-notify-qfalse
description: sess36: D-UNMOUNT-BUSY-INODES ROOT = bast_notify queue_work-false paths kept the iget ref (4 sites); fixed 307, injector-proven 308; kprobe trace met…
metadata:
  type: project
---

# sess36: unmount inode leak ROOT FOUND + FIXED (0.11.307/308)

## Root (ended a 5-session hunt)
`mxfs_dlm_bast_notify` starts with xfs_iget. Its FOUR dispatch sites (immediate/src5, none-held-idle/src3, orphan-release/src4, phantom-reconcile) transferred the ref on queue_work() success but on queue_work()==FALSE (work already pending) printed P76-QW-FALSE and returned WITHOUT xfs_irele — the pending instance owns only the FIRST donor's ref, so each collision leaked exactly one inode ref. The ilock-end arm (xfs_mxfs_dlm.c ~28535) always had the correct pattern (irele on false).

Why every prior instrument failed: the arms ARE balanced (audits were right); P203-LEVEL was last-writer noise; P205 couldn't see VFS puts. The winning instrument: **tracefs kprobes on igrab/ihold/__iget/iput** (real T symbols on 6.8.0-101-generic; BTF offsets i_sb=+56 i_ino=+80 i_count=+344 via bpftool) logging ptr+ino+entry-cnt — per-inode running-count reconstruction had ZERO anomalies and pinned the surviving grab to a 70ms window, correlated to dmesg (clock offset trace-local vs printk ≈ constant): failed EX acquire rc=-EDEADLK → P35-ACQBAST-HONOR honors deferred BAST synchronously in the mkdir task → bast_notify iget → queue collides with already-queued work (P70-BP ENTRY 10us later) → P76 site=immediate → ref stranded.

## Tools (RULE 3, reusable)
- tests/refleak_trace.sh — arm/disarm/fetch kprobe ref traces per node (offsets are 6.8.0-101-specific; re-derive via bpftool on kernel change).
- tests/refleak_analyze.py — per-inode timeline + per-task net balance (LIFO-free).
- tests/census_p.sh — parallel dmesg census without job-control spam.
- mxfs.bast_qfalse_inject (TEST-ONLY, 308): bast_work self-requeues with own donated ref → PENDING stays set → every notify dispatch hits queue-false deterministically. 126 forced collisions, 0 leaks on the fix.

## Verification
8 clean reproducer cycles on 307/308 (pre-fix ~0.45 catch/cycle over 11 cycles → P≈0.8%) + 126-collision injector cycle. GPT design review passed (ownership model; keep-and-park rejected). Ledger: FIXED AND VERIFIED with honest residual note (3 of 4 sites' trigger scenarios never observed; code-identical fix).

## Split findings (new OPEN entries)
- D-DWORK-TEARDOWN-LASTREF-LEAK (medium): dwork fires post-pag-teardown holding the LAST ref (circular: evict can't run so P204 cancel never engages); P142-DWORK-STALE pag=NULL → P142-DWORK-LASTREF intentional leak. Observed once on an infra-aborted cycle. Fix direction: flush bast wq before pag teardown, or teach ident-fail path to distinguish inserted-teardown inodes from pre-insert placeholders.
- D-DIRVIEW-NONCONVERGE-SESS25 (high): split from SILENT-MKDIR-LOSS closure.

## Gotchas learned
- unmount_leak_check.sh CLEARS dmesg at start — run event censuses BEFORE it.
- pkill -f 'pattern' via ssh kills its own shell if the pattern matches the ssh command line.
- A killed run.sh leaves nodes with fs shut down: mountpoint -q fails while mount table lists it; sweep-remount via census_p.
- refleak_trace should set trace_clock=global for cross-CPU rigor (local clocks skewed ~758s vs printk; per-inode analysis was still exact via entry-cnt validation).

## Ledger position after sess36 so far
10 OPEN: FOREIGN-REPLAY, RELEASE-BARRIER (umbrella), MOUNT-DEGRADES, MATRIX-UNMEASURED, DIR-REUSE-FLAKY (pace), SHARED-DIR-CREATE-PACE, INODE-CLUSTER-PUBLISH, READDIR-PEER-PACE, DIRVIEW-NONCONVERGE, DWORK-TEARDOWN-LASTREF. Closed today: COLDREAD-STALE-SPLIT, SILENT-MKDIR-LOSS, CAW-YIELD-STARVATION, UNMOUNT-BUSY-INODES (4 closures, 2 honest splits). Builds 305-308. Board 306 was 20/21 (dir_reuse pace only). Criteria: NOT production ready.
