---
name: AAA-ccloopdaf5-GPT-VERDICT-caw-salvageable-tenure-state-machine-plan
description: GPT-5.6 verdict (user-directed consult): CAW salvageable, do NOT build NET2. Fix set i+ii+iii+iv+vi in 5 phases; tenure state machine is the cure. A-…
metadata:
  type: project
tags: [ccloop-daf50d34, gpt-consult, tenure-state-machine, execution-plan, BINDING]
---

# GPT-5.6-sol consult verdict (2026-07-12, user-directed after mkdir-storm whack-a-mole) — THE EXECUTION PLAN

User directive: stop patch-guessing; either use new_dlm.md/DLM_PLAN.md or consult GPT. Consult done (full reply in session-1 transcript, ccloop daf50d34). Verdict + plan below is BINDING for next sessions.

## VERDICT
- **CAW is salvageable. Do NOT build NET2 for this.** NET2 = larger new correctness surface; envelope mode still depends on the same XFS durability boundary. Import NET2's identity DISCIPLINE into CAW only: non-lossy resource identity, incarnation-qualified tenure IDs, ONE state machine per resource, gen-qualified idempotent release, stale release ignored, loss-of-certainty stops grants. CUT: overlay, shards, replication, raft terms, midcomms, envelope delegation.
- Load-bearing fix set: **(i)+(ii)+(iii)+(iv)+(vi)**. (v) reader-monotonicity as PROPOSED (keep in-core superset) is UNSAFE — implement only as assertion + fail-closed invalidate/reread/refuse (in-core image may be an abandoned double-EX branch).
- "If the team cannot prove EVERY CAW release and acquire goes through the new state machine, CAW is unsalvageable in that implementation" — enforce the ownership boundary.

## THE PHASES (each with proof test; do NOT deploy i and ii separately)
**Phase 0 — clean oracle:** fresh mkfs per eval run (old runs left divergent lineages); add unique local tenure_id to every trace event; record successful CAW preimage/postimage + holder mask + slot gen + resource id + mount incarnation; UNCAP failure counters for focused tests. No ratelimited prints for correctness conclusions.

**Phase 1 — (i)+(ii) TOGETHER: non-lossy per-resource tenure table + single serialization state machine.**
Entry exists while (holder | acquire-in-progress | release-in-progress | queued BAST/reaper/noino work | any ref that can issue a slot transition). Fields: resource id+slot, mount incarnation, monotonic local tenure_id, state {IDLE,ACQUIRING,GRANTED,RELEASING,FAILED}, granted mode, user refcount, successful grant slot preimage/postimage, canonical dir_block0/dir_epoch fields, max committed LSN under tenure, sticky dinode_literal_or_format_modified flag, work refs + cancel/join state. Queued release carries {resource, mount_incarnation, tenure_id} and acts ONLY if that exact tenure is still RELEASING-appropriate. Tombstone until all work refs gone. NOTE: slot raw generation is NOT the tenure test (waiter/yield CASes bump it) — tenure identity + LOCAL serialization is the protection (disk cannot distinguish two successive same-node tenures).
ALL paths through it: normal unlock, BAST no-inode, orphan reaper, unmount, error recovery, acquire/reacquire, convert/demote, forced releases. RELEASING blocks new local acquires INDEFINITELY (not 2s). GRANTED-newer permanently blocks older release. Drain failure → FAILED/retry, never unlock. -ESTALE → re-establish holder, re-arm.
Proof test: fault-injection interleave (pause release pre-unlock, reacquire, resume) across all 5 release flavors; assertions: zero overlapping EX, zero stale-tenure unlock CAS reaching disk, zero acquires bypassing RELEASING; **P135-HELD-MISS must be ZERO at 32 nodes** (not merely lower).

**Phase 2 — (iii) canonical fields from the successful grant CAS slot IMAGE** (in hand at grant; zero added I/O), never from grant_meta (telemetry only). Failed CAW refreshes full image. Convert-gate consumes tenure-recorded canonical. Publication order: publish canonical under EX BEFORE conversion; durability before release. Proof: poison/evict ALL grant_meta entries → correctness unaffected; ≤1 successful LOCAL→EXTENTS canonical conversion per incarnation, ever.

**Phase 3 — (vi) remove rootino exemptions** (or root-safe equivalent) from CONVGATE/extent-reload/content-adopt/dentry-invalidation/dinode-durability. Watch for bootstrap/recursion deadlocks the exemptions may have dodged. Proof: identical invariant traces for ino 128 vs ordinary dir. For two-.parent: raw root dirent on disk vs cached positive dentry (may be TWO bugs: durable root loss vs stale dentry coherency).

**Phase 4 — (iv) tenure-based MANDATORY dinode durability barrier at EX handoff** (per-op calls stay as latency optimizations only). Sticky tenure flag set on shortform dirent add/rm, sf layout change, LOCAL→EXTENTS, extent-root change. At release: force max-committed-LSN, inode-cluster write completed, dependent drains, device flush — else keep slot held/retry/FAILED→withdraw. CIL-pin or 25×2ms budget expiry is NOT permission to hand off. No hot-path I/O added (coalesced at handoff). Proof: inject prolonged pin, delayed cluster writes, writeback/flush errors, reclaim-before-release, convert-then-BAST; unlock record {tenure_id, max_lsn, cluster_write_done, drains_done, flush_done, unlock_gen} impossible unless all true.

**Phase 5 — safe (v):** regression (EXTENTS→LOCAL same-incarnation, canonical-present-but-disk-LOCAL, lower epoch) = corruption signal → invalidate+serialized reread+retry → refuse grant/withdraw if persistent. Never auto-adopt in-core superset, never merge heuristically.

## Q3 — remaining misdiagnosis risk (RESOLVE DURING PHASE 0/1)
Stale-PLATTER dinode theory is INFERRED not proven. Five-boundary trace: A=pre-release expected image; B=post-drain direct-block-I/O read of physical dinode; C=next-grant direct read pre-reload; D=exact xfs_buf handed to reload (flags/identity); E=adopted in-core image. First mismatch localizes: A→B release-durability, B→C later stale write/path-cache/wrong phys block, C→D **stale xfs_buf surviving inode reclaim** (live alternative!), D→E adoption logic. Also tag inode-cluster bufs+transactions with dirtying tenure_id (detect old-tenure buffer written after newer tenure began); record di_gen+slot incarnation+dir_epoch+VFS gen together (VFS i_generation alone insufficient).

## ACCEPTANCE (fresh mkfs): zero double-EX, zero unexplained HELD-MISS, zero stale-tenure unlocks reaching disk, ≤1 canonical conversion/incarnation, every unlock durability-proven, full 1-32 matrix repeat-passes, injected drain failures stop handoff. Perf measured AFTER correctness (state table + slot-image = no hot-path I/O).

## Session-1 state ref: memory AAA-ccloopdaf5-sess1-END-storm-loss-chain-4-fixes-next-probe-durable-gating (builds 0.10.67-70, storm repro scripts/mkdir_storm.sh, cluster on 0.10.70 A6A1EAF8).
