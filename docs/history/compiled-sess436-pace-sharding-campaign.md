<!-- sess436: intents-census interim fix verified, D-401 shared-dir pace ruled to symmetric sharding design, zero-epoch monitor-downgrade root found. -->
# sess436: shared-dir create pace, intents-census fix, directory sharding design

One continuous session arc (2026-08-29, 01:40Z-02:50Z, ccloop c7ee71c6). Fleet
0.41.8 throughout; tree advanced 0.41.8->0.41.10 unbuilt behind a chain of
gated background test chains (2-11). Three threads: closing out
D-FOREIGN-SLICE-INTENTS-ABANDONED, diagnosing D-401/D-32NODE-SHARED-DIR-
CREATE-PACE down to a sharding decision, and a zero-epoch monitor-downgrade
root found as a side effect of exercising the first.

## D-FOREIGN-SLICE-INTENTS-ABANDONED — interim fix verified

Root cause (proven, `tests/evidence/20260829T012712Z_intents_burst/journal_test1.txt`):
the recovery window was 2 txns, both ATOMIC-SKIP whole, and
`mxfs_icensus_note` lived *inside* the item loop, after the verdict's
early-return (`xfs_log_recover.c` ~4103) — so the census never ran on a
whole-skipped batch. Fixed in 0.41.8: a pre-pass now notes intents/dones for
every batch before the verdict runs.
`docs/rulings/mid-intents-census-vacuous-pace-ruling-chains.md`

Verified on 0.41.8 (chain 3 + chain 4 burst): P226-ICENSUS intents=1 open=1,
terminal REFUSED reason=1 (POLICY-REFUSED runs first under armed enforcement;
census widens its domain — sess421 design), zero P163-RECOVERY-COMPLETE, zero
splats, burst 13/14 -> 14/14 after a survivors-assertion fix, clean lap 0
fails. Survivors are not writable because domain=FSWIDE (ag_mask=0 from
classless refused images) — that is D-513/-356 containment; the harness now
branches on domain. Item 5 — real completion of foreign intents at reap — is
still owed; this was only the interim fix (census correctness), not full
closure.
`docs/history/docs/history/docs/history/compiled-sess436-pace-sharding-campaign.md`
`docs/history/docs/history/docs/history/compiled-sess436-pace-sharding-campaign.md`

Harness fix alongside: the TERM trap now captures dmesg, since timeout laps
were previously losing evidence.

## D-401 / D-32NODE-SHARED-DIR-CREATE-PACE — measured, ruled, decided

Anatomy (`tests/evidence/sess436_tenure_modesplit/report.txt`,
`tests/cc_tenure_modesplit.py`, 0.41.6): 62s/node of a ~70s create wall lives
inside INODE-class DLM acquire of the shared dir. EX grants rotate strictly
every ~310ms fleet-wide (~9s/rev, 32 nodes) — that period is exactly
`inode_mht_ms=300` (Minimum Hold Time). The holder does ~13 serial O_SYNC
creates per tenure at ~23ms each (node-local sync latency; the dir ILOCK
itself is held <1ms/create) — so ~95% of each EX tenure is the lock sitting
idle, not doing dir work. Release (P138-BAST) is ~9.2ms p50; handoff dead time
9.75ms p50 / 303ms p90; 496/499 handoffs go to a different node.
`docs/history/docs/history/docs/history/compiled-sess436-pace-sharding-campaign.md`

MHT sweep (chain 2) confirms MHT is the lever but not the fix: mht=0/10/50 all
FAIL (BUDGET_EXHAUSTED/barrier), mht=300 PASSes at 86s. Per-hop cost at mht=0
is ~6ms local (P63-HANDOFF disk-superset adopt + dir reread/rebuild
P26-REBUILD-OK + create + 3x P-DIRWR) + ~10ms release (sb 2, su 5) + ~7ms
transfer -> a ~20ms/hop handoff floor -> 3200 hops = 64-77s either way. Neither
extreme reaches 2x native XFS (the derived-budget rule).
`docs/rulings/mid-intents-census-vacuous-pace-ruling-chains.md`

Headroom measurement settles the ceiling: `crash_consistency CC_PRIVATE=1`
(private subdir per node) PASSes 32/32 at 17s (test9 INODE acquire sum 1.66s,
EX p50 197ms) vs the shared-dir control FAILing at a 72s acquire sum, EX p50
6.8s. The shared dir lock *is* the entire gap — not O_SYNC, not journal, not
per-op overhead elsewhere.
`docs/history/docs/history/docs/history/compiled-sess436-pace-sharding-campaign.md`

Constraint on the fix: `docs/history/decision-reversal-stay-v5-port-mxfs1-coherency.md`
is a standing USER DIRECTIVE — no asymmetric MDS, never add a per-op RTT. That
rules out the obvious "pin the dir to one node" design.

the design-consult rule (GPT) ruling #1, on MHT/pace tuning
(`docs/rulings/shared-dir-create-pace-mht-delegation.md`):
ranks fixes as (1) directory delegation + remote-op combining — owner keeps
dir EX, peers send create/unlink/lookup intents, owner batches and returns a
handle, requester's O_SYNC data write runs concurrently — blocked by the sess68
directive since it needs an RPC/intent transport; (2) physical directory
sharding — hash to shard, each shard its own DLM resource over disjoint
mutable blocks, structural lock only for shape changes; lock striping alone is
NOT sufficient without disjoint blocks; (3) treat MHT as a *max useful
quantum* rather than a minimum idle tenure — on BAST go REVOKING, close
admission, finish the active op, release immediately if idle, zero grace with
remote waiters, direct baton transfer (holder's final CAS installs the
successor's grant), successor-only fast poll, others 10-25ms jittered, waiter
aging against starvation. Expect (3) to fix fairness/regressions, not to reach
2x native alone — go/no-go gate is ~1ms end-to-end token transfer. (4) adaptive
MHT as a policy layer on (3). (5) PR-lookup bypass is secondary and an EX/PR
demote-between-creates convoy trap.

Since (1) is directive-blocked, design-consult ruling #2
(`docs/rulings/symmetric-directory-sharding-design.md`)
designs (2) as the campaign: **fixed, mkdir-time symmetric sharding** — one
logical VFS directory inode, entries routed by `H(seed, name-key) mod N` to N
real XFS dir2 shard inodes that are *detached internal containers* referenced
by a durable manifest (never exposed as named children). Key invariants: N/
hash/seed/manifest-generation durable and N immutable in v1; every shard
mutation atomically updates a per-shard durable summary in the same txn so the
visible parent never needs EX per mutation (parent stat = base + aggregate);
parent fsync is a cross-shard barrier (parent EX, drain/recall shard
authorities, force logs, persist manifest, release); shard-set lifecycle
ALLOCATING->COMPLETE->PUBLISHED->DELETING->FREE with recovery resuming/freeing
ALLOCATING and never exposing incomplete sets; rename same-parent-cross-shard
is one txn, cross-parent needs a global canonical lock order. Rejected
alternatives: per-dir-block locking over unchanged dir2 (shared leaf/free/node
blocks), sticky node-private blocks (no sound index), online conversion of
populated dirs in v1, per-mutation parent EX, split rename into remove+add,
unproven high-bit readdir cookies, default-on before fault injection/tooling/
ancestry/quota are complete. Six-stage build order given (instrumentation ->
on-disk manifest -> opt-in sharded mkdir -> durability -> rename/hardlinks ->
child-dir ancestry -> ecosystem), each stage rig-measurable, target near the
17s headroom floor. Note: 32 random ops over 32 shards occupy ~20 shards at
once (64 shards -> ~25) — benchmark N=32 and N=64, the gain is parallel lock
domains, not full parallelism.

Decision point banked for the user, not yet made: reverse sess68 for the
CONTENDED-DIR-ONLY owner-combining case (no RTT added on uncontended dirs), or
commit to the sharding campaign. `docs/perf.md` and `docs/dir-sharding.md`
updated with the full anatomy and ruling.
`docs/history/docs/history/docs/history/compiled-sess436-pace-sharding-campaign.md`
`docs/history/docs/history/docs/history/compiled-sess436-pace-sharding-campaign.md`

## D-MONITOR-INCARNATION-DOWNGRADE-TO-ZERO — found exercising D-RECOV-ZERO-EPOCH

Side effect of deterministically arming D-RECOV-ZERO-EPOCH (`dbg_efd_hold_ms`
knob): the zero-epoch arm exercised item 1 of that defect's fix (DONE) and, in
doing so, exposed a second root — `dlm/disklock.c`'s epoch-change arm treated
an observed epoch of 0 as a restart, when it can also be a legitimate
transient read racing a peer's incarnation bump. Fixed 0.41.9 (later folded
into 0.41.10 as a proper zero-guard): on a zero read against a known
incarnation, retain `hb_rebase_epoch` and fall through to the timestamp arms
instead of downgrading; `node_track.inc_zero_logged` added as a one-shot log.
Root pinned to `disklock.c:1972`. Fix landed but **unverified** at session end
— the zeroinc rerun in chain 9 (post-restore leg) is the verification gate.
`docs/history/docs/history/docs/history/compiled-sess436-pace-sharding-campaign.md`
`docs/history/docs/history/docs/history/compiled-sess436-pace-sharding-campaign.md`

0.41.10 also folded in a P-EBADE-BOUNDARY fix in `pal/linux/xfs_buf.c` and
`xfs_aops.c` (translate -EBADE to -EIO after the D-498 conflict note) — also
unverified at session end.

## Chain/tree discipline

Tree ran ahead of fleet the whole session (fleet pinned 0.41.8 sv B37DDC30,
tree climbing 0.41.8->0.41.9->0.41.10) via a strict gated chain (2 through 11,
each `setsid`-launched, gated on the previous chain's DONE, logs in
`tests/evidence/sess436_chain<N>_*.log`). Chain 9 is the one that builds the
tree — the explicit rule threaded through every checkpoint this session is
**never `make modules` by hand while chains 7-11 are running**; keep the tree
buildable and let chain 9 build it.
`docs/history/docs/history/docs/history/compiled-sess436-pace-sharding-campaign.md`

Outstanding at session end (67 open on the ledger): chain 7's radv TAKEOVER
result (fails=4, not yet read — `tests/evidence/20260829T024351Z_radv_takeover`)
needs a D-RECOV-ADVANCE record; no_survivor result needs a D-OWN-CRASH record;
chains 8-11 (ubsweep rerun, 0.41.10 build + zeroinc/openunlink verification,
dir_recreate_estale + dlm_scaling loop for D-380, fence_live_node churn for
D-RSYNC-OVERWRITE item 2) still need harvesting; sharding campaign increment 0
not started; D-0359 step 2 and UNGATED-IMAGES steps 7-10 not started.
