<!-- sess436 RULE-5 ruling D-401/D-32NODE-SHARED-DIR-CREATE-PACE: MHT=300ms is the immediate cause but not sufficient; rank: dir delegation+op combining >… -->
# sess436 ruling (gpt-5.6-sol) — shared-dir create pace (D-401 / D-32NODE-SHARED-DIR-CREATE-PACE)

## Measured anatomy fed in (0.41.6, tests/evidence/sess436_tenure_modesplit/report.txt, tests/cc_tenure_modesplit.py)
- 62 s/node of ~70 s create wall inside INODE-class DLM acquire of the shared dir. EX (mode=5) 257 grants, elapsed p50 7.0 s; one EX grant fleet-wide every ~310 ms = strict 32-node rotation (~9 s/rev). PR (mode=3) 515 grants p50 787 ms, batched right after each EX grant.
- 310 ms = `inode_mht_ms=300` (Minimum Hold Time, xfs/xfs_mxfs_dlm.c:13189, mxfs_dlm_mht_defer_bast ~:33402). Holder does ~13 serial O_SYNC creates per tenure (~23 ms each = node-local sync latency; dir ILOCK held <1 ms/create) → ~95% of tenure the EX is held idle.
- Release P138-BAST p50 9.2 ms (sb log force 2.1 p50/17.6 p90; b2 drain 1.9/17.4; su unlock CAS 3.6/11.6; sx 1.1/11.6). Handoff dead time p50 9.75 ms, p90 303 ms. 496/499 handoffs to a different node.
- Floors: 6400 creates × 23 ms serialized ≈ 70 s (current); immediate-release ⇒ 6400 × ~10 ms handoff ≈ 64 s. One-transfer-per-create needs whole op-end→next-op-start ≲ 1 ms to fit single-digit seconds.

## Ranking
1. **Directory delegation + remote-op combining** (owner node keeps dir EX; peers send create/unlink/lookup intents; owner batches metadata, returns handle; requester does its O_SYNC data write concurrently; drain-before-unlock kept at delegation transfer). Needs RPC/shared-disk intent transport, idempotent op IDs, fencing/failover, rename ordering, local dentry coherency rule. Most likely way to single-digit seconds without format change.
2. **Physical directory sharding** (hash → shard, each shard its own DLM resource AND disjoint mutable blocks, per-shard free space/seq, global structural lock; inode-core summaries aggregated). Lock striping alone is NOT enough.
3. **(a)+(b) now**: MHT becomes a max useful quantum, not a min idle tenure: on BAST → REVOKING, close admission (bounded post-BAST batch), finish active op, release immediately if idle, zero grace when remote waiters exist; direct baton transfer via yield_to/sticky (holder's final CAS installs the successor's grant), successor-only fast poll, others 10-25 ms jittered; waiter aging (oldest waiter, rotating cursor, skipped-too-long ⇒ mandatory next). Expect fairness/regression fix, NOT 2× native by itself. Go/no-go: ~1 ms end-to-end transfer.
4. Adaptive MHT only as a policy layer on 3 (needs active-op count, queue depth, real dir-work time, waiter ages, handoff cost, dirty state; never waiter count alone).
5. (e) PR lookups bypass: secondary; EX→PR demote between creates just creates an upgrade convoy; dcache bypass needs a real lease/generation rule.

## Safety notes
- Skipping the log force at release: only with explicit proof the tenure produced zero dir-related log dependency (dirty gen at grant/release, highest LSN, buffers home and not writeback-pending, no ialloc/free-space dependency). Never infer from O_SYNC.
- Invariants: namespace serialization per mutable block; publication ordering (logged+home+drained before transfer); atomic ownership with generation/fencing epoch; bounded post-BAST admission; bounded wait (aging); mode compatibility (PR batches vs EX, upgrades); idempotent forwarded ops.
- Re-run the sess124 unlink-storm shapes (2-node + 32-node unlink churn, hot local node with remote waiters, successor death) for any MHT replacement; measure max waiter age + per-node share.

## Measurements to run before the large build
1. Per-create trace points (open entry, dir EX acquire, ILOCK, commit, dir buf submit/complete, first data write, O_SYNC force, return) — can dir EX be revoked right after the dirent insert?
2. Raw CAW token-transfer floor bench on the LUN (1 waiter, 31 pollers, direct A→B CAW vs unlock+claim, successor poll 0.25-2 ms, non-successors 10-25 ms jittered / silent): p50/p90/p99 of CAS, completion→observation, exit→entry.
3. MHT/grace sweep at 2/4/8/16/32 nodes: MHT 0,1,5,10,25,50,300; grace 0,1,5,10; direct handoff on/off; successor-only poll on/off. Record ops/tenure, active vs idle, dead time, max wait, same-node re-win, yield_to success.
4. Classify every release by dirty work (creates, blocks dirtied, already-home before BAST, log force needed and why, bytes drained, LSNs, overlap with O_SYNC).
5. Headroom: same workload with 1 private dir/node, 8/16/32 dirs, creates-only, O_SYNC to precreated files.
6. Owner-combiner prototype without format change (pin dir to one node, forward creates) — creates/s, batch size, forces, end-to-end.
7. Sharding feasibility census (hash→block map, independently mutable blocks, split frequency, inode-core updates/create).
