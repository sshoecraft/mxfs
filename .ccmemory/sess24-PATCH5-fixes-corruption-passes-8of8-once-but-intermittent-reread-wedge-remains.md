---
name: sess24-PATCH5-fixes-corruption-passes-8of8-once-but-intermittent-reread-wedge-remains
description: sess24 DECISIVE: ALL dir-DATA-block re-read variants (bulk leaf_only=0; targeted postread Patch5; targeted pre-read TRYLOCK grant_stale) intermittent…
metadata:
  type: project
---

## sess24 DECISIVE — dir-data re-read is a DEAD END (all variants wedge)

### Tree restored: build 8A437A7104B8812D30D8050 = keeper EF6000F0 + ONE cleanup
Only surviving change: P103-RELOAD-REUSE-ADOPT (xfs_mxfs_dlm.c:9129) is now `pr_warn_ratelimited` instead of unratelimited `mxfs_pal_log(ERR)` — it floods 3727/run under inode-reuse churn (harmless to ring, but BLOCKS a 115200 serial console). Functionally == keeper. All Patch5 / grant_stale / DLM-fairness experiments REVERTED.

### What was tried and REFUTED this session (all fix the corruption, all WEDGE)
The 8/tcp dir_reuse corruption (use_free stale-RMW-base + DABUF-HOLE) is fixed by making the dir DATA block a coherent RMW base. THREE distinct re-read implementations were built+tested; EVERY one intermittently HARD-WEDGES nodes (network-dark, requires reboot) at 4 AND 8 nodes under contention:
1. **Bulk**: `dir_postread_leaf_only=0` (postread hook re-reads every stale data block). uf=0/hole=0; wedges 4 & 8.
2. **Targeted postread (Patch5)**: per-inode `i_dlm_dir_rmw_reread` flag scopes the postread re-read to addname's one block. PASSED 8/8 ONCE, then wedged 0/8; wedges 4 too.
3. **Targeted pre-read grant_stale**: moved the grant-gen staleness invalidation into the WEDGE-FREE pre-read path (TRYLOCK on the incore buffer, never relse a trans-joined buffer). STILL wedged 0/8 run 1.
=> The wedge is NOT the relse-of-trans-buffer ABBA I hypothesized (the TRYLOCK pre-read has neither relse nor blocking lock, yet wedges). The wedge is intrinsic to SERVING THE PEER'S FRESH DIR IMAGE under 8-node reuse churn — re-reading the coherent block exposes the peer's REUSED inode numbers, and processing them (iget/reload/inactivate ghost incarnations) storms. At DEFAULT (serve stale own block) there's no fresh peer-inode exposure -> no storm -> no wedge (but corruption). NOTE: P103 storm itself is NOT the cause (3727 P103 at DEFAULT 4/tcp which PASSES) — it's a CORRELATE of the reuse churn; the wedge is some hard hang the fresh-image processing triggers.

### THE WEDGE IS THE CORE BLOCKER — must be captured before more re-read attempts
It is a HARD hang (CPU stuck / IRQs-off; hung_task & NMI-watchdog did NOT print a stack to serial; node goes fully network-dark). Serial capture infra exists (console=ttyS0 + libvirt `<log file>` on test2-4; the grub edit floods unless P103 is ratelimited — now it is). Last attempt: serial caught only BOOT, no runtime/hung stack -> hard hang. NEXT-SESSION REQUIRED SETUP to get the stack:
1. guest cmdline: add `ignore_loglevel` (so all printk reaches serial) + keep `nmi_watchdog=1`; `echo 8 > /proc/sys/kernel/printk`.
2. If still nothing: enable kdump (crashkernel=) on a guest, `echo 1 >/proc/sys/kernel/hardlockup_panic` + `panic_on_warn`, so a panic+kdump captures the stuck stack.
3. OR: bisect the wedge — does re-reading ONLY block-format (4-node) dirs wedge, or only node-format? Add a probe right before the FUA re-read logging comm/pid/daddr, then after a wedge, `virsh qemu-monitor-command testN --hmp 'info registers'`/gdb-to-vmlinux to map RIP.

### Alternative coherency approaches (avoid dir-data re-read entirely)
- **Acquire-time eviction done right**: at dir EX (re)acquire after a handoff, evict ALL stale dir DATA blocks (the existing mxfs_dir_drain_evict_data_blocks / dir_force_evict) so the next read is naturally COLD/fresh — no mid-operation re-read. It currently LOCKED-SKIPs transiently-locked blocks (leaving the stale base = the corruption). If the eviction (which runs at acquire, no live trans) can be made to reliably evict without wedging, that's the GFS2 pattern and sidesteps the re-read-wedge. BUT sess23 found eager evict-on-BAST harmful (leaf corruption) — must scope to DATA blocks + same-incarnation.
- **Serialize the create storm** (GPT Patch d): delegate the hot dir to one node / bounded EX batching, so far fewer cross-node handoffs -> fewer stale bases -> less re-read need. Big change.

### Keeper status: EF6000F0 behavior (8A437A71 build). 1/2/4 tcp PASS; 8/tcp dir_reuse = lone blocker, ~50% flaky via corruption. NOT regressed. See [[sess24-leafonly0-wedge-correlates-p103-reload-storm-serial-setup-done]] [[sess24-CONFIRMED-leafonly0-wedges-pristine-keeper-need-serial-console]] [[sess24-gpt5.5-dlm-fairness-and-demand-reread-design]].
</body>
