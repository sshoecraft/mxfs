---
name: sess44-BREAKTHROUGH-force-block-1-is-the-regression
description: sess44 BREAKTHROUGH: dir_force_block=1 (sess43 dir_reuse default) CAUSES dlm_fairness + cache_coherency shutdowns. force_block=0 → both PASS 2/2 clea…
metadata:
  type: project
---

## sess44 (ccloop 8ddb16a2) BREAKTHROUGH — `dir_force_block=1` is a NET REGRESSION

### Criterion = FULL `./run.sh 2 tcp` (17 tests) 100%. Build 422E6DC670C1DE34EE6598C.

### PROVEN (RULE 4, clean reboots between):
- **dlm_fairness**: FAIL 1/2 with default (force_block=1) — test2 FS **shuts down** mid-test.
  With `MXFS_EXTRA_MODARGS='dir_force_block=0'` → **PASS 2/2, zero shutdown/corruption/P43/P133**.
- **cache_coherency** (the 90-session blocker): with `dir_force_block=0` → **PASS 2/2**.
- (dir_reuse_coherency force_block=0 test was RUNNING at handoff — see newer memory.)

### The shutdown chain (dlm_fairness, test2, fresh prep — NOT contamination):
shared dir `.dlm_fairness` ino=2097280 is **BLOCK in-core (fmt=2,size=4096) but SHORTFORM on disk
(fmt=1,size=6), SAME di_gen** (peer node1 drained+converted it). Then:
`P133-DINO-READSTALE "reload served stale cached cluster"` → `P34D-RELOAD-FRESHSRC` correctly
adopts the coherent on-disk (shortform) dinode → **but `P43B-DIR-FMTREVERT-SNAP-SKIP` (my
dir_reuse lineage) OVERRIDES it and keeps the stale in-core BLOCK** → node2 renames on a stale
block base → frees a dir block disk already freed → `xfs_alloc.c:2254 ltbno+ltlen>bno` BNOBT
**double-free** → `xfs_defer_finish_noroll` Corruption → SHUTTING DOWN.

### ROOT INSIGHT: P34D ("adopt coherent on-disk dinode") and P43B/P43 ("keep in-core BLOCK,
disk shortform is a stale self-revert") are **DIRECTLY CONFLICTING guards from different
sessions**, and my dir_reuse P43B wins → corruption. force_block=1 forces the dir BLOCK in-core
while the churning peer legitimately converts it to SHORTFORM on disk → permanent format
divergence the reload can't reconcile. `force_block=1` fixed dir_reuse_coherency's sf→block
divergence but BROKE the block->sf direction for dlm_fairness/cache_coherency (same family).

### METHODOLOGY (critical): after ANY FS shutdown, `umount -f` in prep does NOT fully release
the stale mount → next mkfs triggers `P131-SELF-FENCE device reformatted under live mount
(fs_uuid mismatch)` → confounds the next test. **MUST virsh destroy/start both nodes between
shutdown-runs.** Also `dmesg -C` on both nodes BEFORE each run (prep rmmod/insmod does NOT clear
dmesg; un-filtered dmesg shows STALE shutdowns from prior runs — burned 2 diagnostics on this).

### NEXT: confirm dir_reuse_coherency result @ force_block=0. If it PASSES → default force_block=0
(forward fix, evidence-based, NOT a history-restore — user FORBADE restore-from-history). If it
FAILS → genuine conflict; the proper fix is reliable cross-node dir-EX reload adoption (make
release fully checkpoint+drain the dir so the next acquire's reload gets fresh disk state, and
let P34D's adoption stand — i.e. don't let P43/P43B override a genuine peer-state reload), NOT
forcing a single format. User directive: FIX root cause, no flag-flip-to-pass, no git, no restore.
[[sess44-force-block-0-suite-sweep]]</body>
