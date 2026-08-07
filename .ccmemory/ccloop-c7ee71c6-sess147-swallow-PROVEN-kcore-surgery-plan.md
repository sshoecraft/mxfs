---
name: ccloop-c7ee71c6-sess147-swallow-PROVEN-kcore-surgery-plan
description: sess147: busy_hash swallow PROVEN by kcore+BTF (dead worker, rootcg_work on its scheduled). rootcg list head corrupt. Surgery plan: unswallow FIRST,…
metadata:
  type: project
---

# sess147 — swallow theory PROVEN by direct memory read; full surgery plan

## Toolchain built this session (all in scripts/loop_unwedge/, RULE 3)
- drgn 0.2.0 exists but NO DWARF → useless here. Instead: **pahole (apt dwarves) reads /sys/kernel/btf/vmlinux → exact 6.8 layouts** (pahole_layouts.txt); **bpftrace kprobe lo_ioctl + `losetup /dev/loop0` → live pointers** (lo_capture.bt); **kcore_walk.py = Python /proc/kcore reader** (ELF LOAD segs + pread, kallsyms symbolization) — full read-only walker, output kcore_walk.out. loop is BUILTIN (no module BTF needed). Lockdown=[none].
- Key pointers (STABLE, re-verify at act time): lo=0xffff8a25803c3200 q=0xffff8a258d6a9590 wq(loop0)=0xffff8a2debc31a00 hctx0=0xffff8a258543b600 fq=0xffff8a2586393e80.

## MEASURED STATE (two reads minutes apart, identical)
1. **Dead worker in pool 113 busy_hash: worker@0xffff8a2584f89e00** id=0 flags=0x80 cur_work=&lo->rootcg_work(0xffff8a25803c3288) cur_func=loop_rootcg_workfn cur_pwq=0xffff8a25d93fea00; its task@0xffff8a25bef2a8c0 is FREED (pid=0 comm='' state=0). Still on pool->workers list; nr_workers=5 counts it (4 live idle: ids 15(=pid 1758538),3,5,1).
2. **rootcg_work SWALLOWED**: data=0xffff8a25d93fea05 (PENDING|PWQ, pwq=0xffff8a25d93fea00, pool_id=113, color 0); work.entry next=prev=0xffff8a2584f89e40 = dead_worker+0x40 = **sole entry on dead worker's ->scheduled** (assign_work collision path). Pool 113 worklist empty, pools 112/114 clean.
3. **rootcg_cmd_list HEAD CORRUPT** (@lo+168): head->next=0xffff8a258df20d10 = stale COMPLETED cmd (tag8 rq@0xffff8a258df20c00 state=IDLE ref=0, RAHEAD read, ret=86016, css=0xffff8a258e1a1000) whose own list_entry.next=LIST_POISON1. Cause: Aug04 force-completion churn recycled tags while cmds sat linked. head->prev NOT yet read — read before surgery.
4. **flush_rq tag31**: rq@0xffff8a2580207c00 state=IN_FLIGHT ref=1 end_io=flush_end_io; its pdu loop_cmd@0xffff8a2580207d10 is **self-linked (on NO list)**, use_aio=0 css=0 → unreachable by any worker even after unswallow → must be completed from blk layer.
5. **jbd2 data rq@0xffff8a258df22e80** tag=31(borrowed) on fq->flush_queue[0], flush.seq=3 (PREFLUSH+DATA done) state=COMPLETE, end_io=mq_flush_data_end_io → **waiting only for POSTFLUSH** = the stranded flush_rq. fq: pending_idx=1 running_idx=0 queue[1] empty data_in_flight=0.
6. **journalctl: loop_unwedge act=1 ran 5× on Aug 04** (18:38 4rq; 19:18 2rq; 19:23/19:24/19:25 1rq each with 0 bios = FLUSH_RQs!). Force-completing the flush without fixing the swallow re-strands on the next flush cycle — proven empirically 3×.

## SURGERY PLAN (order matters; RULE-5 GPT consult REQUIRED before acting — not yet done)
- **ACT A (new module act, extend loop_unwedge or new wq_unswallow.ko): un-swallow.** Under pool113->lock (raw_spinlock@pool+0, pahole-verified): interlock-verify EVERY measured value above (worker addr hashed, cur_work, cur_func==loop_rootcg_workfn kallsyms param, task ptr + freed markers, scheduled sole-entry ptrs); then list_del rootcg_work from dead->scheduled; hash_del(dead->hentry); (GPT: also detach pool->workers + nr_workers--?). Unlock. Under lo->lo_work_lock(@lo+124): verify head->next==0xffff8a258df20d10 then INIT_LIST_HEAD(&rootcg_cmd_list). Set rootcg_work.data = WORK_STRUCT_NO_POOL (public linux/workqueue.h macro). Accepted leaks: dead worker struct 168B; old pwq nr_active+1 & pwq ref (wq never destroyed).
- **ACT B verify:** small O_DIRECT read of /dev/loop0 from root cgroup → must complete (rootcg path revived).
- **ACT C:** loop_unwedge act=1 expect=1 → blk_mq_end_request(flush_rq, IOERR) (honest status: fsync never ran; fs is TAINTED gen-0 quarantine). flush_end_io advances seq → jbd2 sb write completes EIO → jbd2 abort (contained) → BH unlock → ffmpeg 1867972 mmap_lock frees → khugepaged 365 + ps herd drain → load collapses. blk_mq_end_request on flush_rq is the NORMAL driver completion path (end_io returns RQ_END_IO_NONE, not freed). Module quiesces queue around pass 2 already.
- **Then:** umount both fiomnt mounts (1833866, 1834825; expect errors=ok, journal aborted), keep loop0+dm-0 attached/quarantined, **RESTORE CRON** (`crontab -l | sed 's|^#PAUSED-mxfs-sess145 ||' | crontab -`), verify tag31 gone + load drop, then back to RULE-6 ledger (fence stage-(ii) gen-1 + SCST bvec-UAF patch deploy, target 3.11.0-pre+caw-abort-reclaim.2).

## Offsets cheat-sheet (6.8.0-101, pahole from live BTF)
worker: hentry@0 cur_work@16 cur_func@24 cur_pwq@32 scheduled@64 task@80 pool@88 node(list)@96 flags@120 id@124. worker_pool: lock@0 id@12 worklist@40 nr_workers@56 nr_idle@60 idle_list@64 busy_hash@192(64×8) workers@712 dying@728. loop_device: backing@96 state@120 work_lock@124 wq@128 rootcg_work@136 rootcg_cmd_list@168 idle_workers@184 tree@200 lo_queue@256. loop_cmd=rq+272 (list_entry@0 use_aio@16 ret@24 css@88). request sz=272: q@0 mq_hctx@16 cmd_flags@24 rq_flags@28 tag@32 queuelist@72 state@148 ref@152 flush.seq@232 end_io@256. fq: bits@4(b0=pend,b1=run) pending_since@8 queue[2]@16 data_cnt@48 flush_rq@56. task: __state@24 flags@44 exit_state@2384 pid@2488 comm@3032. work.data flags: PENDING=b0 PWQ=b2, pwq=data&~0xff, offq pool=data>>5.

## Standing
- Cron STILL PAUSED (#PAUSED-mxfs-sess145). No bare ps/pgrep until herd drains. Never read /proc/1867972/cmdline. Timeout everything. git BANNED (user global rule — a `git tag` attempt got denied this session; use no git, period). Load 522, ffmpeg D, khugepaged D — unchanged all session (jam stable).
