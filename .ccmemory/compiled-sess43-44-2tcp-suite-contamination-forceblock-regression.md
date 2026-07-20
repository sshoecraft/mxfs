---
name: compiled-sess43-44-2tcp-suite-contamination-forceblock-regression
description: sess43-44: 2/tcp criterion is FULL run.sh suite; most fails = contamination; dir_force_block=1 is a net regression, =0 fixes cache_coherency+dlm_fair…
metadata:
  type: project
tags: [compiled, 2tcp-suite, contamination, dir_force_block, cache_coherency, dlm_fairness, regression]
---

## sess43-44 — 2/tcp criterion reframed to the full suite; contamination map; dir_force_block=1 is a net regression

Central finding across these two sessions: the ship criterion "2 node dlm=tcp test 100% successful" is the FULL `./run.sh 2 tcp` suite (17 tests) at 100% — NOT just `dir_reuse_coherency`. Most suite failures are cross-test CONTAMINATION, and the `mxfs_dir_force_block=1` default introduced by the sess43 dir_reuse fix is itself a NET REGRESSION that shuts down `cache_coherency` and `dlm_fairness`.

### sess43 — criterion correction + contamination map (build 422E6DC6, force_block=1 default)

**Criterion retracted and corrected** [[sess43-CORRECTION-criterion-is-FULL-2tcp-suite-not-just-dir-reuse]]: a premature "criteria-met YES" was challenged when the user showed `showstat.sh 2 tcp` = 2 PASS / 11 FAIL / 4 PENDING. The criterion had been over-narrowed to `dir_reuse_coherency` (all prior sessions in this lineage worked on that). Marker set back to NO. The `dir_reuse_coherency` fix (force_block=1 default + P43/P43B) is real and KEPT regardless.

**Suite mechanism**: `run.sh` preps ONCE and runs all 17 tests back-to-back with NO reset/reboot between them. An early test that shuts down the FS (prime suspect: `cache_coherency`, the sess79-92 lineage blocker) contaminates every test after it. So "2/17" is largely a harness artifact, not 11 separate bugs [[sess43-suite-failures-are-largely-contamination-not-real]].

**Standalone (fresh prep, clean reboot) results, build 422E6DC6** [[sess43-STATUS-real-vs-contamination-map-and-plan]]:
- PASS standalone / suite-fail was CONTAMINATION (11 confirmed-good): posix_multi (suite 0/2), strong_consistency (suite 1/2), zero_silent_loss (suite 0/2), mmap_coherency, rsync_paired, scaling_curve, dlm_scaling, crash_consistency (2/2), dlm_membership (2/2), plus precond_readiness and dir_reuse_coherency.
- REAL fail standalone (3): `cache_coherency` (1/2, sess79-92 blocker, does not obviously wedge); `dlm_fairness` (1/2, WEDGES cluster — leaks in-kernel DLM state, module refcnt=1 won't rmmod, next prep mkfs fails); `tcp_dlm_scaling` (1/2, same wedge).
- UNTESTED (prep blocked by the wedge): fence_during_write, fault_netpartition, soak.

**Key sess43 hypotheses**: the two DLM-stress tests (dlm_fairness, tcp_dlm_scaling) leak in-kernel DLM state (kthread/connection/workqueue not torn down) → module ref held → cascade. Same leaked state likely degrades the shared FS for later in-suite tests. At this point force_block=1 was believed NOT to regress (all 9 contamination tests passed with it on) — this was later DISPROVEN in sess44. Do NOT paper over a real FS-shutdown bug with harness resets; distinguish real vs contamination via standalone results + dmesg (force_shutdown / EFSCORRUPTED). Operational: never kill a running test mid-flight (leaks refcnt → forces virsh reboot).

### sess44 — BREAKTHROUGH: dir_force_block=1 is the regression

**Proven under RULE 4 with clean reboots between runs** [[sess44-BREAKTHROUGH-force-block-1-is-the-regression]], build 422E6DC6:
- `dlm_fairness`: FAIL 1/2 with default (force_block=1), test2 FS shuts down mid-test. With `MXFS_EXTRA_MODARGS='dir_force_block=0'` → PASS 2/2, zero shutdown/corruption/P43/P133.
- `cache_coherency` (the 90-session blocker): with `dir_force_block=0` → PASS 2/2.

**Shutdown chain (dlm_fairness, test2, fresh prep — NOT contamination)**: shared dir `.dlm_fairness` ino=2097280 is BLOCK in-core (fmt=2, size=4096) but SHORTFORM on disk (fmt=1, size=6) with SAME di_gen (peer node1 drained+converted it). Sequence: `P133-DINO-READSTALE "reload served stale cached cluster"` → `P34D-RELOAD-FRESHSRC` correctly adopts the coherent on-disk shortform dinode → BUT `P43B-DIR-FMTREVERT-SNAP-SKIP` (the dir_reuse lineage guard) OVERRIDES it and keeps the stale in-core BLOCK → node2 renames on a stale block base → frees a dir block already freed on disk → `xfs_alloc.c:2254 ltbno+ltlen>bno` BNOBT double-free → `xfs_defer_finish_noroll` Corruption → SHUTTING DOWN.

**Root insight**: P34D ("adopt coherent on-disk dinode") and P43/P43B ("keep in-core BLOCK; disk shortform is a stale self-revert") are DIRECTLY CONFLICTING guards from different sessions; the dir_reuse P43B wins → corruption. `force_block=1` forces the dir BLOCK in-core while the churning peer legitimately converts it to SHORTFORM on disk → permanent format divergence the reload cannot reconcile. force_block=1 fixed dir_reuse_coherency's sf→block divergence but BROKE the block→sf direction for dlm_fairness/cache_coherency (same family).

**Fix landed**: `int mxfs_dir_force_block = 0;` (was 1) at `xfs/xfs_mxfs_dlm.c:2789`, rebuilt to build **9A10A0773B7002BA33D2EAD**.

**Full `./run.sh 2 tcp` in-suite sweep, build 9A10A077 (force_block=0 default), partial** [[sess44-force-block-0-suite-sweep]]:
- PASS in-suite: precond_readiness, cache_coherency 2/2 (90-session blocker, GREEN in-suite), strong_consistency, mmap_coherency, zero_silent_loss, dlm_fairness 2/2 (was FAIL), scaling_curve, dlm_scaling.
- FAIL in-suite: `posix_multi` 1/2 (test2 one check `pm r2 sees node1 renamed content exp=posix_1 got=` — empty-content read of a peer's renamed hardlink, sess39/45 empty-content family; test1 PASS 211/211); `dlm_membership` 1/2 (coord=fault); `rsync_paired` 0/2 (both nodes; 400-file rsync into own subdir, 90s window — timing-under-load or contamination from preceding fault test).
- Still running at note time: crash_consistency, dir_reuse_coherency, fence_during_write, fault_netpartition, soak, tcp_dlm_scaling.

**Pattern after the fix**: pure cross-node coherency tests now PASS in-suite. Residuals cluster on (a) heavier/metadata workloads (rsync_paired), (b) fault tests (dlm_membership + pending fence/netpartition/crash), (c) one transient empty-content read (posix_multi). Dominant residual cause hypothesized = contamination/cumulative degradation (suite never re-preps; a fault test that doesn't cleanly recover degrades downstream) PLUS the posix_multi empty-content coherency gap.

### Open direction (user: FIX ROOT — no workaround, no flag-flip-to-pass, no git, no restore)
1. Confirm `dir_reuse_coherency` @ force_block=0. If PASS → default force_block=0 stands as a forward, evidence-based fix (NOT a history-restore, which the user forbade). If FAIL → genuine conflict; proper fix is reliable cross-node dir-EX reload adoption: make release fully checkpoint+drain the dir so the next acquire's reload gets fresh disk state, and let P34D's adoption stand (don't let P43/P43B override a genuine peer-state reload) — do NOT force a single format.
2. Get the COMPLETE 17-test result.
3. Re-run each FAIL STANDALONE to split REAL-bug vs contamination (dlm_fairness/cache_coherency/dir_reuse already PASS standalone+in-suite).
4. For genuine contamination the fix is the fault tests' clean node-rejoin recovery, NOT mkfs-between-tests (that masks real wedge bugs). A real clustered FS must survive back-to-back workloads.
5. posix_multi empty-content: same family as cache_coherency cross_write_read (now passing); likely a hardlink+rename content-visibility residual.

### Methodology reminders (recurring, expensive lessons)
- After ANY FS shutdown, `umount -f` in prep does NOT fully release the stale mount → next mkfs triggers `P131-SELF-FENCE device reformatted under live mount (fs_uuid mismatch)`, confounding the next test. MUST `virsh destroy/start` BOTH nodes between shutdown-runs.
- `dmesg -C` on both nodes BEFORE each run; prep rmmod/insmod does NOT clear dmesg, and un-filtered dmesg shows STALE shutdowns from prior runs (burned multiple diagnostics on this).
- Foreground runs auto-background past ~90s — await task-notification, don't poll.
- Never kill a running test mid-flight (leaks module refcnt → forces virsh reboot).
