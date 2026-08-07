---
name: ccloop-c7ee71c6-sess171-pw-selftest-LANDED-0.11.462-built
description: sess171: PW selftest IMPLEMENTED + 0.11.462 BUILT (srcversion F185ED4495CCC5DCEED0914), NOT deployed. Next: tests/caw_pw_selftest.sh harness, deploy,…
metadata:
  type: project
---

# sess171 — PW selftest landed, 0.11.462 built, harness NOT yet written

## LANDED THIS SESSION (all built clean; rig still on 0.11.460)
1. **`dlm/v5_mount.c`** — `mxfs_v5_dlm_caw_pw_selftest(struct mxfs_v5_dlm *ctx, uint64_t ino)` inserted after `mxfs_v5_dlm_inode_unlock_open`, before the ICLUSTER block (~4546). Exact sess170-ruled sequence: arm1 lock-PW(T1 proving)→convert-EX(==T1)→convert-PW(defensive)→reconvert-EX(==T1)→unlock→relock-EX(T3!=T1)→unlock; arm2 lock-PW(T4!=T3,!=0)→acquire-EX-while-held(==T4)→unlock. Best-effort unlock on every fail; verdict `mxfs: P274-PWTEST <PASS|FAIL> run=%u ino=%llu t1= t3= t4= step=%s rc=%d` (WARN on pass, ERR on fail; START line too). Returns 0 PASS, -EREMOTEIO assertion-fail, other -errno infra (infra rc preserved through fail path). Decl + contract comment in `dlm/v5_mount.h` after `mxfs_v5_dlm_inode_unlock`.
2. **`xfs/xfs_mount.h`** — `struct dentry *m_mxfs_pwtest_dentry` right after `m_mxfs_dlm` (comment explains early-removal requirement).
3. **`xfs/xfs_mxfs_dlm.c`** — `mxfs_caw_pw_selftest_write` handler + fops + `static atomic_t mxfs_caw_pwtest_busy` gate above `mxfs_dlm_cache_init`; file `caw_pw_selftest` (0200, private=mp) created in cache_init's `if (mp->m_debugfs)` block alongside recovery_blocked/inode_authority. Handler: snapshot m_mxfs_dlm (-ENODEV), xfs_is_shutdown (-ESHUTDOWN), kstrtoull_from_user (0=auto key `(agcount+1+node_slot)<<(agblklog+inopblog)|1`), atomic_cmpxchg busy gate (-EBUSY), synchronous run, count-on-PASS/rc-on-fail.
4. **`pal/linux/xfs_super.c`** — `debugfs_remove(mp->m_mxfs_pwtest_dentry)` + NULL in `xfs_fs_put_super`, right BEFORE `mp->m_mxfs_dlm = NULL` (~1556 now), inside the `if (mp->m_mxfs_dlm)` block. debugfs proxy waits out in-flight handler → closes the ctx use-after-free race per ruling condition C.
5. **VERSION 0.11.462**; `make modules` rc=0 srcversion **F185ED4495CCC5DCEED0914**; `make -C tools` rc=0.

## HARNESS FACTS DERIVED THIS SESSION (write tests/caw_pw_selftest.sh from these)
- **Expected probes per PASS run with key K**: P274-GEP-PRESERVE rk=K exactly **3** (a1-convert-ex, a1-reconvert-ex upgrades via convert path @9921 site, a2-acquire-ex via compat-add @7868). The EX→PW **downgrade takes `caw_slot_clearing("convert-downgrade")` and does NOT call caw_grant_epoch_update** — no probe; token survival is proven by the reconvert==T1 round-trip. P109-CLR-UPGRADE id=K old_mode=4 new_mode=5 exactly **1** (acquire path only, ~7844) and it is **instr-gated** — set `/sys/module/mxfs/parameters/instr=1` first (module_param at xfs_mxfs_dlm.c:36268). GEP-PRESERVE/INJECT/CONT-ZERO are ALWAYS-ON (not instr-gated). Preserve counts can exceed on CAS -EAGAIN retries → assert >=3, ==1 may be >=1.
- **Debugfs path on node**: `/sys/kernel/debug/mxfs/<s_id>/caw_pw_selftest` — glob `/sys/kernel/debug/mxfs/*/caw_pw_selftest` (top dir "mxfs" @xfs_super.c:4148, per-mount dir = s_id = device basename).
- **Wrap case**: echo 1 > /sys/module/mxfs/parameters/caw_inject_gep_wrap (consumable), re-run selftest on idle node → first mint (a1-lock-pw) consumes it → P274-GEPWRAP-INJECT rk=K prev=..., T1==1 on the PASS line; knob self-clears. Race: any other fresh PW/EX mint on that node can consume it first — assert rk==K, re-run if raced.
- **Tombstone carries ex_grant_epoch** (caw_tombstone_slot ~1280, sess108 REQUIRED) → T3=T1+1, T4=T3+1 expected; harness asserts inequality only (ruling A1), may REPORT values.
- **SSH idiom**: `tools/mxfs_sshpass.sh <node> [passfile] <cmd>` (passfile optional, auto-materialized); nodes test1..test32; kmsg marker scoping (`echo MARK > /dev/kmsg`, then `dmesg | awk '/MARK/{f=1} f'`) — never bare dmesg grep. Kill/rejoin idiom: `virsh -c qemu:///system destroy/start testN` + wait_up pattern from scripts/ccloop_reset.sh.
- **Deploy**: run.sh prep_cluster (~529) pushes REPO/mxfs.ko by md5 + srcversion check — `./run.sh 32 caw [test...]` deploys and runs; no prep-only mode found. Plan: deploy+board via run.sh, then run harness on mounted cluster (board leaves cluster mounted), or run harness after a 1-test run.sh invocation.
- **Kill-while-held case (ruling condition B)**: selftest hold window is ms — run selftest in a tight loop on victim, virsh destroy mid-loop, verify survivor purge + victim rejoin + selftest re-PASS on victim (purge/reacquisition). Epoch continuity across purge is a #15-ledger question, NOT asserted by this case.

## NEXT QUEUE (order)
1. Write tests/caw_pw_selftest.sh (basic + wrap + kill modes per facts above).
2. Deploy 462 + run harness on test1 + wrap case + kill-while-held; then full board 32/caw.
3. Ledger #15 rewrite (sess108 steps DONE, vehicle ruling, selftest evidence, 2^64 wrap math doc duty Q4) + #1 historical-record-lifetime blocker + Q6 cross-ref.
4. COMPACTION DUE (183 unfolded) — run compile-memories when context allows.
Rig: all 32 on 0.11.460 (460F52B...), untouched this session.
