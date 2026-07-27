---
name: ccloop4dd7-sess1-dialloc-corruption-campaign-state
description: ccloop-4dd7 sess1: VM-rig repro of pve dialloc corruption; dead-shell FIX built (defer+sanitize); 4 more evidenced defects (recycle-gate stale adopt,…
metadata:
  type: project
---

# ccloop-4dd7 sess1 — stale-inode dialloc corruption campaign (VM rig)

## Rig pivot
pve1/pve2 physical nodes are POWERED OFF / unreachable (no OOB; cannot restart remotely).
Pivoted to VM rig: test1/test2 (Ubuntu 24.04, kernel 6.8.0-101-generic = clyde's kernel,
so local `make modules` serves VMs via NFS /src). LIO tcm_loop stack was torn down by a
clyde reboot — rebuilt with `sudo scripts/lio_tcm_setup.sh setup` (idempotent; /dev/mxfs-shared
symlink; VM XML references it, `<shareable/>`). Cluster: `MXFS_FORCE_PREP=1 ./run.sh 2 tcp
prep_cluster` (defaults: test1/test2, /dev/sda, /tmp/.mxfs_pass auto from secrets).
After run.sh auto-recovers (reboots) VMs, wait for `systemctl is-system-running` != starting
(pam_nologin banner pollutes SSH output and breaks run.sh parsing until boot completes).
**The churn repro reproduces the pve corruption family in 45-180s EVERY run**:
`N1=test1 N2=test2 MXFS_PASS=/tmp/.mxfs_pass scripts/agi_wedge_repro.sh 180 24`.

## THREE corruption flavors reproduced (each with full dmesg autopsy)
Logs: tests/logs/vmrig_dialloc_20260724_*Z/ (live_test1.log/live_test2.log pairs).

### Flavor 2 — dead-shell CREATE (THE pve handoff signature) — FIX BUILT
Chain PROVEN (ino 139 autopsy, all same second, same ip pointer):
P19-B3DEC coh_nlink=0 will_skip=1 b4_noauth=1 → INACT-SKIP-STALE (peer freed the ino;
local node RIGHTLY skips destructive inactivation but the shell's in-core mode/forks are
NEVER reset like local xfs_inode_uninit would) → IRECLAIMABLE dead shell (mode=0100644,
nlink=0, i_dlm_stale=1) → local dialloc reuses the ino → iget cache-hit →
P-CR63-DEADSHELL → upstream xfs_iget_check_free_state (runs BEFORE recycle) sees mode!=0
→ false "Corruption detected! Free inode not marked free" → -117 → dirty trans_cancel →
cluster-wide shutdown.
**FIX (xfs/xfs_icache.c, build C61E575C, v0.11.41)**:
1. xfs_iget_cache_hit: new `bool cr63_defer_deadshell` — in the P-CR63 block's IRECLAIMABLE
   branch, if nlink==0 → P-CR63-DEADSHELL-DEFER + skip xfs_iget_check_free_state.
2. xfs_iget_recycle gained param `bool deadshell_create` (sole caller updated): stale-block
   gate extended to `(i_dlm_stale || deadshell_create)`; inside the disk-read: if
   deadshell_create && disk mode!=0 → P-CR63-DEFER-DISKLIVE + error=-EFSCORRUPTED (flows
   into existing re-add-to-reclaim recovery — create fails loudly, no clobber); else if
   deadshell_create && disk mode==0 && in-core mode!=0 → **P-RECYCLE-SANITIZE**: emulate the
   missed local uninit (xfs_idestroy_fork df/af/cow, df=EXTENTS empty, mode=0, nblocks=0,
   disk_size=0, forkoff=0, diflags=0, diflags2=new_diflags2, ADOPT disk di_gen).
**NOT YET EXERCISED** (DEFER=0 SANITIZE=0 in all runs so far — condition is probabilistic).
Deterministic recipe attempt (scripts/deadshell_repro.sh) instead produced the VFS-LIVE
shell variant which the EXISTING mxfs_dlm_reset_inode_for_create rescue handles (P-CR63-SHELL
reclaimable=0 → P9-NLEDGE reset4create → EAGAIN → success). The IRECLAIMABLE variant needs
the node to learn nlink=0 (coh ledger) BEFORE eviction — timing not yet captured determin-
istically. Verification plan: churn rounds until DEFER fires ≥1 with zero corruption.

### Flavor 1 — inobt record double-free (run 1)
test2: P-DIFREE-DBL agno=4 agino=145 ir_free=0xfffffffff0122000 freecount=39 (bit ALREADY
set) → guard is WARN-ONLY, proceeded → freecount 40 vs mask popcount 39 → xfs_inobt_check_irec
EFSCORRUPTED on BOTH nodes → shutdowns. Upstream cause: test2's create of s2 (ino 8388753)
was in-core-only (P116-RELOAD-SELFCLOBBER-SKIP incore=0100644 disk=0 held=1 — unpublished
create, KEEP was arguably correct); the shared inobt said FREE at test2's own difree ⇒ the
DIALLOC's bit-clear never reached/was lost from the shared record. **P150 record-level probes
now armed** (see instrumentation) — next firing gives the full RMW interleave.

### Flavor 3 — rmdir droplink nlink=0 (-117) + zombie extent double-free (run 3)
ino 1862 autopsy:
- test1 rm s-file → frees ino 1862 properly (P82-REM + "P9-INSTR ifree DONE flushed"), disk
  gen 3097500574→575.
- test2 (~1s LATER) `printf x > s2` resolved the STALE name→1862 (dcache/stale dir) →
  ilock EX (fresh acquire on freed ino succeeds — DLM is by number) → reload ran but
  **P-RELOAD-IDENTICAL saw the OLD ALLOCATED image (gen 574, nx=1) == in-core → kept**:
  the cluster-buffer read was served STALE (cached buffer NOT FUA-refreshed on fresh
  EX acquire) despite test1's flushed free — **the "inode-cluster invalidate-on-acquire"
  hole the original pve handoff hypothesized, now EVIDENCED** → O_TRUNC freed the stale
  map's block agbno=226 (P3-EFREE-Q) which test1's side also freed = **cross-node double
  block free** → then INACT-SKIP-STALE (guard caught the ifree, too late for extents).
- test1 mkdir d1_N reused 1862: **P-RECYCLE-GATE adopt=1 of disk_gen=3097500574 OVER
  incore_gen=3097500575 — ORDERING-BLIND ADOPT of an OLDER image** (adopt condition is
  `gen differs`, no direction). icreate init then overwrote most fields BUT i_nblocks is
  only ASSERTed (never reset) by xfs_inode_init → latent accounting skew.
- test1 rmdir d1_N: MX-INSTR remove dp=131 ip=1862 nlink=0 xfs_droplink rc=-117 → dirty
  cancel → shutdown. nlink zeroing suspected from P63-FASTEX-HANDOFF disk-superset dir
  reload adopting the freed platter image over the UNPUBLISHED mkdir (P63 fired on 1862
  at :39 right before) — NOT yet pinned; needs gen prints at the P63/superset adopt.

## Evidenced fix queue (in order)
1. **Recycle-gate ordering guard** (one-liner, direct evidence): adopt only when disk gen
   NEWER: `(s32)(be32_to_cpu(dip->di_gen) - VFS_I(ip)->i_generation) > 0`, else keep.
   (xfs_icache.c P-RECYCLE-GATE branch.)
2. **reset4create generation converge**: mxfs_dlm_reset_inode_for_create (xfs_mxfs_dlm.c
   ~20020) never touches i_generation → destage REGRESSES gen vs the peer's freed image
   (evidence: P-CR62 disk_di_gen=incore+1; 1862 same). Add VFS_I(ip)->i_generation++
   (peer's uninit did exactly +1; converges; keeps every gen-based guard sound). My
   P-RECYCLE-SANITIZE already adopts disk gen (equivalent).
3. **P116 zombie arm** (after 1+2 make gens trustworthy): P116 currently keeps in-core
   whenever dirty||grant-held; add: if disk-free && disk_gen == incore_gen+1 && !dirty →
   ZOMBIE: fall through to adopt the freed image (truncate becomes no-op on empty map —
   kills the zombie-O_TRUNC double-free). Fresh-ino unpublished-create window is protected
   by dirty; reused-ino window becomes gen-EQUAL after fix 2. Print gens in P116 always.
4. **Cluster-buffer FUA refresh on fresh inode-DLM acquire** (flavor 3 root): reload served
   a stale cached cluster image under a FRESH EX. Instrument read provenance first
   (was the read cache-hit? _XBF_FUA_FRESH state) — then fix invalidate-on-acquire.
5. **Flavor 1 lost-alloc**: wait for P150/P144-inobt firing; autopsy the record interleave.

## Instrumentation added this session (build C61E575C)
- **P150-{ALLOC-IBT,ALLOC-UI,ALLOC-FIN,FREE-IBT,FREE-FIN}** (xfs/libxfs/xfs_ialloc.c,
  helper mxfs_p150_inorec after xfs_dialloc_check_ino, #ifdef __KERNEL__): every inobt/
  finobt record RMW in multinode logs agno/startino/off/pre-mask/pre-fc/post/tenure=
  ag_dlm_tenure_id/mgen=pag_dlm_meta_gen/btenure=b_tenure_id/bgen=b_mxfs_ag_gen/daddr/
  lsn/comm/realns. Cap 20000.
- **P144 extended to inobt/finobt** (pal/linux/xfs_buf.c): mxfs_p144_ops() covers 4 AG
  btrees; RD at cold-read completion, WR at write submission, crc32c content fingerprint.
- scripts/deadshell_repro.sh (RULE 3): deterministic 4-step recipe (currently produces the
  live-shell variant; keep for regression of that path).

## Key code map (for continuation)
- xfs_iget_cache_hit / P-CR63 block: xfs/xfs_icache.c ~1090-1160 (defer flag ~999).
- xfs_iget_recycle + stale-block + SANITIZE: xfs_icache.c 449-~700.
- check_free_state call (deferred): ~1360.
- INACT guard (B1-B5 decision, runs BEFORE truncate — good): xfs/xfs_inode.c 3340-3700
  (P19-B3DEC print 3691). DLM EX acquired before disk read, held across truncate+ifree.
- P116-RELOAD-SELFCLOBBER-SKIP: xfs_mxfs_dlm.c ~18080 (inside mxfs_dlm_reload_inode).
- mxfs_dlm_reset_inode_for_create: xfs_mxfs_dlm.c ~20020.
- P-RECYCLE-GATE adopt: xfs_icache.c ~640 (inside recycle stale-block).
- P63/handoff/P51 dir refresh machinery: xfs_mxfs_dlm.c 21520-21660; dir_gg_refresh
  default 1 arms refresh on every grant_gen change (P51-HANDOFFUNDERFIRE is detector-only).
- P-DIFREE-DBL: xfs/libxfs/xfs_ialloc.c ~2650 (warn-only, proceeds).
- xfs_inode_uninit (local ifree in-core reset to EMULATE): xfs/libxfs/xfs_inode_util.c 842-890.
- xfs_inode_init does NOT reset i_nblocks (ASSERT only): xfs_inode_util.c 308.

## Env/ops notes
- VERSION bumped 0.11.40 → 0.11.41 (dead-shell fix). Builds: 01AC24CC (pre-instr) →
  B8B30A9D (P150/P144) → C61E575C (dead-shell fix).
- Live capture pattern: `nohup tools/mxfs_sshpass.sh testN /tmp/.mxfs_pass "dmesg -T -w" >
  $LOGD/live_testN.log &` then churn; grep P-probes. LOGD pointer file:
  /tmp/claude-1000/-src-mxfs/*/scratchpad/logdir.txt.
- prep_cluster occasionally reports ABORT while nodes actually mounted OK (parse noise);
  verify with `mount | grep shared` + srcversion before concluding.
- My own harness bug to avoid: ssh helper piped through grep swallows remote exit status —
  use output-based checks (echo MOUNTED) not rc.
- Task list: #1 dialloc corruption (in_progress), #2 AGI Phase-B, #3 pve2 flush_workqueue
  wedge, #4 dir_reuse create-visibility (P12/P13 livelock ON DISPLAY in run-1 log — reader
  loop on unpublished create, ties to flavor-1's unpublished window).
- RULE 6: NOTHING is closed yet. Dead-shell fix = built, UNVERIFIED (needs DEFER+SANITIZE
  observed + zero corruption). Other flavors OPEN with evidence trails.
