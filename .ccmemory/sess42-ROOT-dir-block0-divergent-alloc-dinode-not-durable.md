---
name: sess42-ROOT-dir-block0-divergent-alloc-dinode-not-durable
description: sess42 dir_reuse 2/tcp data-loss: SERIAL-STALE cross-node block0 divergence at shortform->block conversion. NOT double-grant (P-DOUBLEGRANT=0), NOT r…
metadata:
  type: project
---

## sess42 dir_reuse_coherency 2/tcp DATA-LOSS — refined diagnosis (2 hypotheses REFUTED)

### SYMPTOM (deterministic): cold verify, BOTH nodes agree readdir=186-187/200, lookup_fail=0, missing = node1_f1..f14 (node1's FIRST files = logical block0 of test dir ino=131). ALWAYS node1's, NEVER node2's. node1=rank1=dir owner (does mkdir/rm-rf, writes first each round).

### MECHANISM (P-DIRIFLUSH detector, xfs_inode.c ~4868): node1 flushes dir block0 ALWAYS at canonical fsb (fsb=15 AG0). node2 flushes block0 at canonical fsb=15 (majority) BUT ALSO at DIVERGENT fsb=14 (AG0) and **fsb=262153 (=AG1, node2's preferred AG = slot1%agcount)**. node2 builds its OWN logical-block0 in its own AG from a stale/empty base. The home dinode's logical-0 ends up pointing at node2's rival block0 → node1's block0 (with f1..f14) orphaned → lost. lookup_fail=0 because the leaf hash still resolves names to logical-0 (now the rival block). Happens at the SHORTFORM->BLOCK conversion: node2 converts from a stale shortform base missing node1's dirents.

### REFUTED HYPOTHESIS A — DLM double-grant / concurrent EX: **P-DOUBLEGRANT=0 and P-STALEMASTER-GRANT=0** (always-on master-side shadow-table detector, dlm/dlm.c:2288 dg_grant_ex). NO two nodes hold EX on ino=131 concurrently; NO split-brain mastership. ⇒ DLM mutual exclusion is SOUND. The divergence is SERIAL-STALE (node2 acquires EX serially after node1 releases, but reloads a stale base), NOT a concurrency race.

### REFUTED HYPOTHESIS B — dir DINODE not platter-durable at release (block/leaf): build C5BD4E04 extended mxfs_dlm_dir_inode_durable (xfs_mxfs_dlm.c ~1814) to force the inode cluster durable for ALL dir formats (not just shortform). TEST: still FAILED (rounds 20,23), node2 STILL allocated divergent fsb=14/262153. Only inflated dir iflushes ~30x (perf). ⇒ release-durability is NOT the gap. **REVERTED** (tree back to E8C6B4B6 = held-check-only).

### TREE STATE: E8C6B4B6 = baseline + the VERIFIED held-check stall fix ([[sess42-FIX-held-check-mode-blind-false-negative-PR]]). NO data-loss fix yet. dir_reuse 2/tcp still ~50% FAIL (data loss), but NO 65s stalls and runs ~293s.

### NEXT (RULE 4) — the divergence is SERIAL-STALE, so the question is WHY node2's serial EX-acquire reload reads a stale base (doesn't see node1's committed block0). Non-perturbing detector needed: at node2's dir EX-acquire reload (mxfs_dlm_reload_inode, xfs_mxfs_dlm.c ~6007 / slow-path ~9175), log the block0 fsb+fmt+size it READS FROM DISK vs node1's last committed (P-DIRIFLUSH). If node2 reads stale shortform/empty while node1 committed block-format → the reload reads a pre-conversion image (cached buffer not FUA? or node1's conversion not yet durable at node2's acquire?). Candidate fixes: (1) GPT inode-flush FENCE in xfs_iflush_cluster ([[sess-tcp-FENCE-correct-location-iflush-cluster-not-iflush]]) — skip node2's divergent-block0 flush; (2) force node2's reload to FUA-read the dir DATA block0 not just the dinode; (3) make shortform->block conversion of a SHARED dir verify on-disk format first. Detector P-DIRIFLUSH already in tree (always-on capped). See also [[sess-tcp-FIX-DESIGN-fence-stale-dir-inode-fork-flush]].
</body>
