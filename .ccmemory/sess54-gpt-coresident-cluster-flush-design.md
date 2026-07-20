---
name: sess54-gpt-coresident-cluster-flush-design
description: sess54 GPT-5.5 ranked design for the cluster-flush vs per-inode-EX mismatch (co-resident dirent resurrection). The architecturally-correct fix.
metadata:
  type: project
---

## sess54 GPT-5.5 consult (RULE 5; complete proven diagnosis) — design for the co-resident cluster-flush resurrection. See root [[sess54-ROOT-coresident-cluster-flush-stale-buffer-resurrection]].

GPT verdict: the bug is **DLM write authority is per-inode, but the physical write is the whole 4KB inode cluster**. On a shared LUN with non-coherent buffer caches, any full-cluster write can write stale bytes for co-resident inodes. Ranked fix:

1. **CORRECT (big): inode-cluster DLM lock + fresh RMW.** Add a DLM resource `ICLUSTER:<uuid>:<agno>:<cluster_start_agino>`. For ANY full inode-cluster write: acquire ICLUSTER EX → READ FRESH 4KB from disk (do NOT reuse cached buffer as base) → overlay ONLY inodes this node is authoritative for (holds EX / RELFLUSH current-tenure) → write 4KB → release. Eliminates co-resident clobber AND discard.
2. **Target-only durable flush:** `mxfs_inode_cluster_durable(dp)` must NOT co-flush arbitrary co-resident inodes. Flush only dp via the fresh-RMW path. (My sess54 localized FUA-refresh-of-b_addr is a lightweight approximation of #1 WITHOUT the ICLUSTER lock — relies on per-inode EX for the overlay; small race window remains vs a peer's concurrent co-resident write, but strictly better than the stale cached buffer.)
3. **Systematic EX dirty-pin (source fix):** introduce `dirty_holders` (NOT tied to ILOCK lifetime). A node must not release/downgrade inode EX until all changes committed under that EX are durable. BAST release waits ex_holders==0 && pr_holders==0 && dirty_holders==0. Apply to EVERY dir-modifying path (create/remove/rename/mkdir/rmdir/link/symlink) and ALL affected dirs/inodes. (sess54 did remove+rename via ex_holders pin — works for target; make it generic + add create.)
4. **P119 classified handling, NOT silent discard:** ghost (di_mode==0 OR di_gen != i_generation OR S_IFMT differs) → abort/clean (avoid AIL wedge). LIVE same-incarnation non-EX dirty → must NOT mark-clean (loses committed change) and must NOT leave-dirty-forever (AIL wedge — PROVEN sess54 P113-DRAIN-WEDGE) → queue a repair worker that re-acquires EX + flushes (with epoch validation), or fail hard. NEVER `error=0;goto flush_out` for a live inode.
5. **DLM epoch (not di_gen) for ownership/ordering:** stamp `i_mxfs.dirty_epoch = dlm_current_epoch(ip)` when dirtied under EX; on repair, flush only if `dlm_current_epoch(ip)==dirty_epoch` else journal-recover/shutdown. di_gen EQUALITY is a same-incarnation test only, NOT an ownership/ordering proof.

GPT "immediate minimal fix likely to drive leftovers→0": (a) extend EX dirty-pin to ALL dir-mod paths + all affected dirs; (b) stop mxfs_inode_cluster_durable from co-flushing arbitrary co-resident inodes (target-only / fresh-RMW). sess54 implemented (b) as the localized FUA-refresh (build 99A4E4905, untested). If that's insufficient, escalate to the full ICLUSTER-lock RMW (#1).
