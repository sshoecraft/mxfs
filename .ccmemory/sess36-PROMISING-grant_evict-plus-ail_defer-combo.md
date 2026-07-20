---
name: sess36-PROMISING-grant_evict-plus-ail_defer-combo
description: sess36: grant_evict+ail_defer combo = FLAKY (2 PASS, 1 FAIL+SHUTDOWN). ail_defer's 184s starvation shutdown recurs (disqualifying) AND loss still occ…
metadata:
  type: project
---

## sess36 — grant_evict + dir_ail_defer combo: FLAKY, NOT a fix (but the proven-root direction).

### RESULT (3 runs): cap_defer PASS, batch iter1 PASS, batch iter2 **FAIL+SHUTDOWN** (readdir=799 round7 + 184s DLM starvation wedge — test1 went unreachable). So 2 PASS / 1 FAIL+SHUTDOWN. **DISQUALIFIED**: the shutdown is a hard fail, and the loss still occurs intermittently.

### WHAT THIS ESTABLISHES (decisive, RULE 4):
1. **PROVEN clobber mechanism** (P-DATACLOBBER-SKIP, 168 events on a FAILING grant_evict run, dataclobber=1 detect): the durable single-dirent loss IS the **EX-holder's BACKGROUND xfsaild destage** of a stale-content dir DATA/LEAF block — real_mode=5(EX), in_txn=0 (NOT release-drain), comm=dd/rm, in_ail=1, bdirty=0, **stale=0 (bufgen==dirgen, gen-blind), SAME incarnation**. Leaf clobbers are count-preserving hash-divergent (371==371, different hashes); data clobbers off-by-one during rm. A FEEDBACK LOOP: stale async write→stale disk→stale acquire-reread→stale RMW→stale async write.
2. **ail_defer** (GFS2 invariant — only the release-drain writes contended dir blocks) is the proven-root fix BUT has TWO gaps (sess25): (a) 184s log-tail STARVATION (deferred BLIs pin the AIL tail → log fills → DLM acquire blocks → shutdown); (b) occasional whole-block loss (release-drain doesn't reliably land every deferred block / base still stale).
3. grant_evict (fresh base) + ail_defer (no bg clobber) PASSES sometimes (loop broken) but the STARVATION still shuts down → must fix liveness first.

### THE REMAINING TASK (well-scoped, hard): give ail_defer a LIVENESS VALVE so it never starves the log tail. Options to explore: (a) yield/release EX more aggressively when contended+deferring (bound defer to one short tenure → release-drain lands blocks → peer proceeds); (b) cap deferred-item count / age and force a COHERENT checkpoint (not a raw destage) under pressure; (c) ensure the release-drain provably flushes EVERY deferred dir block of the dir (extent-map walk completeness). The TENSION: any write under pressure must be coherent, but the in-core content is sometimes stale-by-content despite grant_evict (the stamps lie — stale=0 over stale content) → can't safely "just allow the destage". This is THE wall.

### FALLBACK / OTHER ANGLES if liveness proves intractable: re-examine WHY the in-core block is stale-by-content under EX with grant_evict (the loop seed) — is FUA-read on LIO actually always fresh? is there a block grant_evict's extent-walk misses? Instrument the FIRST clobber of a run (break the loop at its seed).

### Build CF57F8AB (grant_evict + ail_defer both default 0 = keeper). Test combo: MXFS_EXTRA_MODARGS="dir_grant_evict=1 dir_ail_defer=1". ail_defer impl at xfs_mxfs_dlm.c:18544 (returns XFS_ITEM_LOCKED in the buf_item push). See [[sess36-HEAD-handoff]] [[sess25...]] for the GFS2 design.
