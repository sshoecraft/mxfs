---
name: sess59-zsl-bmbt-stale-child-root-and-residual
description: sess59 BIG PROGRESS: zsl 1600→105. concurrent-EX REFUTED (ex_pop=1). Root = stale-cached bmbt CHILD blocks on reload. Residual = di_nextents vs bmbt-…
metadata:
  type: project
---

## sess59 (ccloop 14d31183) — zero_silent_loss: 1600 → 105 silent, RULE-4 chain

Build progression: 420F8D79 (diag) → FEDFFD74 (P58 ex_pop probe) → 63FD06FF
(FASTEX reload fix) → **75C0C6AE (bmbt-child evict, CURRENT)**.

### PROVEN #1 — concurrent-EX REFUTED at the clobber site
Added inode-EX popcount to the P58-SELFSKIP-STALE-DIR probe (build FEDFFD74).
Every fire: `ino=131 post_release=0 dir_gen=388 loaded_gen=332 pin=1
self_created=0 ex_pop=1 ex_nslots=1 held=1`. ex_pop=1/held=1 everywhere ⇒
NOT a mutual-exclusion violation. The node alone holds the dir EX. So the
durable dirent loss is a **single-holder STALE-BASE clobber-after-commit**
(hypothesis B), on the FASTEX (post_release=0) re-acquire that sess58's
post_release exemption did not cover.

### Fix attempt A (63FD06FF) — DISPROVEN-as-clean, but exposed the real root
Extended the reload self-skip disk-superset bypass to
`peer_modified_since_load = S_ISDIR && !self_created && dir_gen>loaded_gen`
(in mxfs_dlm_reload_inode, ~line 3847). This made the FASTEX path reload
from disk. Result: creates failed with "Structure needs cleaning"
(EFSCORRUPTED) + FS shutdown: `corrupt dinode 131 (btree extents)` at
**xfs_iread_bmbt_block**, caller xfs_create. The forced cold-read of the
bmbt EXPOSED a corruption the stale-cache self-skip had been MASKING.
Buffer dump: magic BMA3, owner 0x83=131, uuid all VALID — a real but
tree-inconsistent (stale) cached child.

### PROVEN #2 + Fix B (75C0C6AE) — stale cached bmbt CHILD blocks
On a BTREE-format dir, the extent MAP lives in separate bmbt blocks in the
AGs. mxfs_dlm_reload_inode invalidates the inode CLUSTER buffer (dinode =
bmbt root in if_broot) but NOT the cached bmbt CHILD blocks, and
mxfs_dir_drain_evict_data_blocks only evicts DATA-fork blocks (and bails
for a just-reloaded BTREE fork, extents-not-read). So after adopting a
peer's fresh root, xfs_iread_extents walked into a STALE cached child →
shutdown. FIX: new `mxfs_dir_evict_bmbt_blocks(ip)` (AG-walk for
xfs_bmbt_buf_ops bufs owned by ip, clear XBF_DONE on clean ones — same
idiom as data-block evict, never xfs_buf_stale, skip pinned/undestaged).
Called at top of mxfs_dir_drain_evict_data_blocks before the BTREE bail.
**Result: silent 1600 → 105, 1495/1600 dirs persist through drop_caches,
no hang, verify completes. Only test10/test15 still shut down.**

### RESIDUAL (next) — di_nextents vs bmbt-leaf disk inconsistency
New signature on the 2 failing nodes: `Internal error ir.loaded !=
ifp->if_nextents at xfs_bmap.c:1271, Caller xfs_iread_extents`. The
dinode's di_nextents disagrees with the count of records found walking the
(now cold-read) bmbt leaves. ⇒ the dinode (di_nextents) and the bmbt child
blocks are MUTUALLY INCONSISTENT ON DISK — a writer-side RELEASE
flush-ordering gap: the releasing node does not flush the inode cluster
buffer (di_nextents) and ALL bmbt children as one consistent set before
handing EX to a peer. Investigate the bast release drain + mxfs_dir_bmbt_scan
flush vs inode-cluster flush ordering. Possible causes: bmbt_scan skips a
pinned/in-AIL child; MXFS_BMBT_SCAN/EVICT_MAX=64 cap; or dinode flushed
without its children (or vice-versa).

### Verify-phase fix (KEEP) — scripts/sess88_workload_a_modeN_baseline.sh
node0 `find | wc -l` merged find stderr (via run's 2>&1) so error-msg digits
corrupted the count, and a hang→empty→fake 1600. Rewrote to `echo
COUNT=$(find ... 2>/dev/null | wc -l)` + sed-extract + 3× retry; empty now
flagged "VERIFY HANG (STRUCTURAL)" not silent loss.

### INFRA
Storm leaves FS-shutdown nodes with umount hung in D-state. Probe each node
`umount /mnt/shared` (rc=0 vs HANG); virsh -c qemu:///system destroy+start
the HANG ones, rmmod the clean ones, before each re-run. P59-BMBT-EVICT /
P58-SELFSKIP probes are gated behind mxfs_dirwr/instr (counts read 0 with
them off) but the eviction/skip LOGIC runs regardless. Other open criteria:
fence_during_write, rsync_paired, posix_semantics_multi16.
</body>
