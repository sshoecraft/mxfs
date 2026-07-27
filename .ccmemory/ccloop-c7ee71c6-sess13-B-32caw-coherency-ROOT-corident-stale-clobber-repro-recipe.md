---
name: ccloop-c7ee71c6-sess13-B-32caw-coherency-ROOT-corident-stale-clobber-repro-recipe
description: sess13: 32/caw cache_coherency ROOT EVIDENCE: co-resident stale cluster-buf clobber after ino-reuse churn; platter proof + tight repro recipe (storm+…
metadata:
  type: project
tags: [32-node, coherency, data-loss, cluster-buf, co-resident, rule4, open, repro]
---

# sess13-B: 32/caw coherency defect — physical evidence + repro recipe (sess12-C family ROOT)

## The failure (lap 6 of sess13 hunt, 13:24-13:31Z, v0.11.115 fresh prep + prior wedge_load storm)
cache_coherency rv phase: test1's `mv node1_before_1 → node1_after_1` (ino 170, AG-0, cluster
daddr=160 slot boff=5120) FAILED 3 checks on ALL 32 NODES IDENTICALLY: old-gone FAIL (before_1
still resolvable at verify), new-exists FAIL + content FAIL (iget of after_1 → -117).
P26-IGET-FAIL dp=8388739 name="node1_after_1" inum=170 err=-117 ftype=1 ×6 on test1 itself.
ONE HOUR LATER (live artifact): BOTH names exist as dirents, BOTH -117 unresolvable; dir has 129
entries (128 expected + resurrected before_1). Content content_1_1 (12B) = DURABLE DATA LOSS.

## Physical platter proof (dd + decode, test1, envelope offset 196688 sectors)
Cluster block daddr=160 (16 slots, inos 160-175):
- slots 160-169 (except 162): mode=100644 files — correct current incarnations (destage WORKED)
- slot 170: **OLD DIRECTORY incarnation** — magic=IN mode=040755 v3 fmt=2 di_ino=170
  di_gen=2664539562 crc=0x7c115af5 changecount=131 lsn=0x10000ca35 nlink=2 size=4096.
  This is the REMOVED `.wedgeload` dir's dinode (my storm's tree; something removed it between
  laps freeing ino 170 for reuse).
- slots 171-175: mode=0 (FREED — those free-writes LANDED on the platter!)

⇒ mode=0 for 171-175 proves a node flushed this cluster AFTER the frees, and THAT WRITE carried
a STALE slot-170 (old dir image): neither ino-170's free-write (mode=0) nor test1's new FILE
incarnation survived on disk. Classic cross-node co-resident stale overwrite: a node writing the
8K cluster for ITS slots durably reverts OTHER nodes' slots from its stale in-core copy.
-117 mechanics: dirent ftype=1 (REG) vs platter dir-mode dinode → EUCLEAN at iget on every node;
test1's in-core "authoritative" object (RELOAD-VERIFY-BAIL fa=xfs_dinode_verify+0x750 tries=9,
kept in-core) eventually evicted → loss became total. Companion loop prints on test1 comm=mv:
P12-IGETMISS-RELOAD → P11-ACQSTALE-SELFBAST src=7 → P142-BWORK-STALE (rcu_cur=NULL — bast work on
non-current object) → RELOAD-VERIFY-BAIL → P13-SLOTPATCH (disk_mode=040755 patched into logged
cluster buf!) every ~25ms. P13-SLOTPATCH pulling the STALE DIR bytes into the logged buf is
itself suspect (propagates the clobber?).
Dir-block level: same family — rename_visibility dir (ino 8388739, 8192B block dir, written by
all 32 nodes) ended with BOTH before_1 AND after_1 dirents = stale dir-block overwrite/merge.

## REPRO RECIPE (much tighter than "aged state")
1. Fresh 32/caw prep.  2. tests/wedge_load.sh start N (create/unlink churn cycling inos across
all 32 nodes in shared dirs — builds the reused-ino minefield; the tree then gets removed).
3. Run cache_coherency (its creates land on churned inos; renames + 32-node verify).
Hit on lap 6 of session (first lap AFTER the storm aged ino-reuse state). Historical
"aged-state" 32/caw coherency FAILs (sess12-C, loop2) = same recipe occurring naturally.

## NEXT (RULE 4)
Instrument cluster-buf WRITE provenance: per-write print (node, daddr, comm, per-slot di_ino/mode
summary or slot-170 bytes) filtered to hot daddrs, on all nodes; re-run recipe; identify the
clobber write's node + path (xfsaild delwri? drain_alloc_buflist? icd destage? P13-SLOTPATCH?).
Then fix at the proven path. Existing guards that SHOULD have prevented it: P119 non-EX discard,
FUA-fresh reread (_XBF_FUA_FRESH), per-slot patch machinery, FIRST_FLUSH resurrection guard —
one of them has a hole under fast free/reuse churn. LIVE ARTIFACT preserved on cluster (do not
re-prep until harvested): broken slot-170 + 129-entry dir.
Matrix: 32/caw cache_coherency recorded FAIL (13:25:57Z) — criteria.json.
