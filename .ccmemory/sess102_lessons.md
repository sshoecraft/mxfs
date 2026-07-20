---
name: sess102_lessons
description: sess102 — cache_coherency 3/4. in_ail-discard fix (B3C15760, KEEP) killed bnobt/dialloc double-alloc; remaining blocker = inode-REUSE iunlink/inactiv…
metadata:
  type: project
---

# sess102 (2026-06-06, ccloop run 29df431e)

cache_coherency = **3/4** on clean cluster (build BF1DF7A1): cross_visibility,
rename_visibility, unlink_visibility all PASS; **cross_write_read FAILS**.
Marker NOT written. Current head build = **B3C15760** (in_ail fix, deployed all 4).

## DECISIVE NEW FRAMING (the big one): fua_disable=1 broke the AG-meta gen model
sess94 made `fua_disable=1` the DEFAULT — reads go plain-bio through the COHERENT
SCST shared write-back cache; FUA-platter reads are STALE (behind the cache).
**All of sess80/90/92's GPT/Gemini consults analyzed `mxfs_buf_read_fua` (mechanism F
TOCTOU, bounce-buffer) — that path is now DEAD (fua_disable gates it off).** The bnobt
double-free PERSISTS with FUA off ⇒ root is the plain-bio/SCST coherency path, NOT FUA.

## THREE shutdown signatures, all the SAME lost-update family
1. bnobt double-free: `ltbno+ltlen>bno` xfs_alloc.c:2244 (cross_write_read). free path.
2. dialloc EFSCORRUPTED i!=1 → xfs_create → trans_cancel. create path.
3. xfs_remove/xfs_iunlink_remove_inode AGI-unlinked-garbage → inactive_ifree. unlink path.
Repro: loop `run_tests.sh --phase cluster --test test_unlink_visibility` (keeps cluster
mounted; cache_coherency.sh TEARS DOWN after each run so can't loop it). unlink_visibility
shuts down ~1/3 runs. cross_write_read alone barely churns inodes — won't repro the bnobt.

## FIX #1 LANDED (B3C15760, KEEP — net progress): drop `!in_ail` AG-meta protection
`mxfs_ag_meta_invalidate_stale` (xfs_mxfs_dlm.c ~4210) PROTECTED `in_ail` buffers. Under
fua_disable=1 a buffer clean by tx-flags (!dirty BLI && !pin && !delwri && !XBF_WRITE) has
its content already on the coherent SCST cache, so discarding+plain-reread is SAFE even
if in_ail (XFS keeps a buffer in_ail long AFTER clean writeback until log-tail push). The
`!in_ail` exclusion served node A its OWN stale PRIOR-HOLD snapshot of AGI/inobt/bnobt/cntbt
after a release→peer-modifies-AG→reacquire cycle → double-alloc/free. `!dirty` still fully
protects current-hold uncommitted work. **sess43's "discard-in_ail lost-update→shutdown"
was a FUA-platter-behind-SCST false positive — does NOT apply under fua_disable=1.**
RESULT: P102-INVAL-INAIL-DISCARD fires; the bnobt/dialloc double-alloc class (sig 1/2)
is ELIMINATED. Failure MOVED to sig 3 (iunlink/inode-cluster), a PRE-EXISTING mode
(documented sess39/92), not a regression. Gemini RULE-5 consult #2 endorsed this exact fix
and predicted the residual = inode-cluster (Gap c).

## REMAINING BLOCKER = inode-number REUSE coherency (the 13-session core, now isolated)
Built detector **P-IRESURRECT** in xfs_iflush (xfs_inode.c ~3325, after dip=xfs_buf_offset):
logs every multi-node iflush where on-disk dinode disagrees with in-core (mode/gen/nlink).
PROVES: `comm=xfsaild` flushes in-core inodes that disk says are a DIFFERENT/older
incarnation. Patterns: (a) `incore_gen == disk_gen+1` = this node REALLOCATED the ino number
while disk/peer still has gen G LIVE; (b) at the iunlink shutdown: P71-INSTR
`ino=6291584 disk_dimode=040755 disk_dnlink=2 agi_disk_differs=1` = this node is FREEING an
inode the on-disk image shows as a LIVE DIRECTORY owned by a peer. So a node holds a STALE
in-core inode (nlink=0, inactivating) whose number a peer reused live → inactivation
corrupts AGI/iunlink/bnobt.

### Gemini REFUTED my xfs_iflush gen-mismatch ABORT guard — DO NOT BUILD IT
gen mismatch at flush is NORMAL during rapid reuse (disk cluster has old gen G, in-core has
new G+1); aborting would trap legit reallocated inodes. P-IRESURRECT is detector-ONLY (no
behavior change) — keep it or remove, harmless.

### Existing inactivation guard INACT-SKIP-STALE (xfs_inode.c ~2217) is INSUFFICIENT
Skips inactivation only when B1 disk-free (di_mode==0) OR B2 (gen-mismatch AND i_dlm_mode==NL).
The failing case: disk shows LIVE (mode 040755) + **gen MATCHES** + i_dlm_mode=**EX**(5) +
disk_nlink>0 while in-core nlink=0. Neither B1 nor B2 catches it. HARD part: when gen matches,
"legit inactivation w/ disk lagging nlink" vs "peer reused same-gen, must skip" is ambiguous
by inode content alone. NEXT SESSION: this is the crux — likely need the per-inode DLM/evict
state (XFS_ISTALE_CAW, dlm_stale, evict-ring P-EVICT-DISPATCH/EVICT-RING-DIRMOD) to know a
peer took the inode, OR prevent the stale in-core inode from existing (invalidate on peer
free). Consider Gemini consult #3 (or GPT per escalation) framed on: inode-cluster +
di_next_unlinked coherency under fua_disable=1, deadlock-safe (no ILOCK across CAW poll, no
blocking SCSI in writeback). inode-cluster bufs are NOT in mxfs_buf_is_ag_metadata (only
AGF/AGI/AGFL/bnobt/cntbt/inobt/finobt/rmap/refcount) — that's Gap (c).

## INFRA (verified sess102)
- Builds: srcversion NOT stable cross-session; verify probe via `strings mxfs.ko | grep`.
- Repro loop kept mounted: reset4.sh 4 → run_tests.sh --phase cluster --test <name> in a loop,
  grep each node dmesg for 'Shutting down filesystem'. MXFS_NODE_OFFSET=16 MXFS_TESTS_DIR=/src/mxfs/tests.
- Clock sync (drifts ~1s/node, breaks P-trace merge): per node `date -u -s "$(date -u +...)"`.
- cache_coherency.sh auto-backgrounds >10min AND unmounts at end. Deploy: reset4.sh 4
  (LIBVIRT_DEFAULT_URI=qemu:///system). All 4 nodes mount /mnt/shared dev /dev/sda; slots t1=0 t2=3 t3=1 t4=2.
- P-IRESURRECT detector + P102-INVAL-INAIL-DISCARD are in current build B3C15760.
</body>
