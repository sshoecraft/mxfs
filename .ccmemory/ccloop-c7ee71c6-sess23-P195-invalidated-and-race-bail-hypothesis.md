---
name: ccloop-c7ee71c6-sess23-P195-invalidated-and-race-bail-hypothesis
description: sess23: P195 is neither necessary nor sufficient for the silent loss (measured both ways); new lead = P34J-RELOAD-RACE-BAIL, the untouched twin of th…
metadata:
  type: project
tags: [ccloop-c7ee71c6, sess23, D-SILENT-MKDIR-LOSS, P195, P34J, hypothesis]
---

# sess23 — P195 invalidated as the predicate; the race-bail is the new lead

## 1. P195 is NEITHER NECESSARY NOR SUFFICIENT for the silent loss

Two measurements on 0.11.193 @16/caw, both correctly window-scoped:

**Not necessary** — a FAILING run:

    dirent_durability         FAIL  durable_loss=3 mkdir_err=0   (4/16 nodes)
    dirent_publish_integrity  PASS  stale_base_mutations=0        (16/16)

**Not sufficient** — a PASSING run's per-node census (tests/dd_loss_capture.sh,
scoped to the last MXFS_DIRENT_WINDOW, the same scoping the criterion uses):

    test3   P195=1  P65-EPOCH-CONVGATE=1
    test13  P195=1  P65-EPOCH-CONVGATE=1
    (durable_loss=0 on that run)

Window mis-scoping is RULED OUT: `dirent_durability` stamps
`MXFS_DIRENT_WINDOW` to /dev/kmsg at the START of its run, before the workload
(tests/suite/dirent_durability.sh:65), and the criterion scans from the LAST
marker.

**Consequence:** `dirent_publish_integrity`'s stated justification —
"asks the DETERMINISTIC question ... fires reliably ... must stay red until the
freshness gate at EX acquire is implemented" (state.md sess21) — is
**measurably wrong**. Driving P195 to zero would NOT demonstrate the loss is
fixed. Do not use it as the acceptance signal, and do not use it as an A/B arm.
Keep the criterion (P195 is still an invariant violation worth counting) but
STOP treating it as the predicate for D-SILENT-MKDIR-LOSS.

## 2. sess22's reload_demote_wait fix IS working — validated incidentally

Per-node, scoped, on a passing run:

    P34J-RELOAD-DEMOTE-BAIL      = 0   (was 641-936/run pre-sess22)
    P198-RELOAD-DEMOTE-WAITED    = 4-16 per node
    P34J-RELOAD-RACE-BAIL        = 8-15 per node, on EVERY node

The demote bail is gone and the bounded wait happens instead, exactly as
designed. That half is confirmed.

## 3. NEW LEAD — `P34J-RELOAD-RACE-BAIL` is the untouched twin

`xfs_mxfs_dlm.c` ~21475, inside `mxfs_dlm_reload_inode`:

    if ((ip->i_dlm_demoter && ip->i_dlm_demoter != current) ||
        READ_ONCE(ip->i_dlm_epoch) != r_entry_epoch) {
            pr_warn_ratelimited("... P34J-RELOAD-RACE-BAIL ... discarding pre-drain snapshot");
            kfree(merge_ours); kfree(snap); if (bp) xfs_buf_relse(bp);
            up_write(&ip->i_lock);
            /* leave i_dlm_stale set — caller retries post-drain */
            return;
    }

**That trailing comment makes the IDENTICAL promise the demote bail made**, and
sess22 proved for the demote flavour that *no caller ever implemented the
retry* — which is what leaves `i_dlm_dir_valid_epoch` behind the master
`dir_epoch`, so `P32E-DIREPOCH-FENCE` then skips EVERY flush of whatever the
operation goes on to commit, and the entry dies silently.

sess22 fixed only the DEMOTE flavour. This is the same half-fix pattern as
sess21's "sess20 fixed the CAW arm and left TCP broken".

**Hypothesis H2:** the race bail is the second producer of the silent loss —
the one that explains a loss with P195=0.

## 4. THE NEXT EXPERIMENT (do this first next session)

Do NOT patch on this hypothesis — RULE 4. Prove the chain first:

1. **Causal-link probe.** On a RACE bail, stamp the inode (e.g.
   `i_mxfs_racebail_ns` + a per-inode flag). Then have `P32E-DIREPOCH-FENCE`
   print whether the inode it is fencing carries a recent race-bail stamp, and
   have the dirent-publish path print the same. If fenced flushes are
   preferentially on race-bailed inodes, the chain is established with a number.
2. **Does anything actually retry?** `i_dlm_stale` stays set, so the NEXT access
   should reload — the real question is whether anything can PUBLISH a stale
   image in the window between the bail and that next access. Instrument that
   window directly (bail -> next reload on the same inode: elapsed time, and
   whether any P56-DIRWRITE / flush happened in between).
3. **Only then**, if proven, apply the sess22-shaped fix: a bounded RETRY of the
   reload (re-sample the platter after the racing drain settles) instead of
   abandoning — with a lever `mxfs.reload_race_retry_ms` for a paired A/B, and
   cost measured (sess22's wait cost 2.3s cluster-wide across a 120s storm, no
   RULE 0 concern).

Acceptance must be `dirent_durability` over MANY paired runs (it fails ~1 in 3
at 16 nodes; single-run deltas are worthless), NOT the P195 count.

## 5. New harness: tests/dd_loss_capture.sh

Loops `dirent_durability` until it FAILS, then harvests a per-node,
window-scoped census of every marker known to be able to drop a committed
dirent (P195/P188/P189/P146V/P32E/P177/P34J/P65/P6), plus full dmesg, and
prints a passing run as the control arm. 4 iterations produced no failure this
session — that is NOT evidence of a fix (RULE 6), the rate is ~1 in 3-10.
Baseline from a passing run: P188=0, P146V=0, P32E=0, P177=0 everywhere;
P189-RELOG-BEHIND-DISK=1 on one node; P6-MIDTENURE-RELOAD-SKIP=22-163 per node.
