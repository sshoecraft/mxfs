<!-- sess436 RULE-5 ruling: fixed mkdir-time SYMMETRIC directory sharding (detached shard containers + durable manifest, per-shard summaries, parent-fsync… -->
# sess436 ruling (gpt-5.6-sol) — symmetric directory sharding for D-32NODE-SHARED-DIR-CREATE-PACE / D-401

Context: private-dir headroom 17 s vs shared 70-100 s; sess68 user directive bars asymmetric MDS / per-op RTT.

## Verdict
Proceed with **fixed, mkdir-time symmetric sharding**: one logical VFS directory inode; entries routed to N real XFS dir2 shard inodes that are DETACHED internal containers referenced by a durable MANIFEST (not hidden named children). Handoff-cost reduction = worthwhile tactical optimization, not the fix (unsharded best case ~20-30 s; floor max(17 s, 3200×2-3 ms)). REJECTED: per-dir-block locking over unchanged dir2 (leaf/free/node blocks shared; deep fork), sticky node-private blocks (no sound index), online conversion of populated dirs in v1, updating the visible parent under EX per mutation, split rename into remove+add, high-bit readdir cookies without proving bit width, default-on before fsync/recovery/tooling/ancestry/quota complete.

## P0 hazards → invariants
1. Routing: shard = H(persistent seed, XFS name-equivalence key) mod N; N/hash/seed/manifest gen durable; N immutable in v1; ops pin manifest generation via parent PR; no silent all-shard fallback (only chk_mxfs/recovery).
2. Visible-parent metadata must NOT need parent EX per mutation: each shard mutation atomically updates a per-shard durable summary (mtime/ctime, change counter, child-dir count, accounting) in the same txn; parent stat = base + aggregate; i_version monotonic; timestamps via monotonic rule; nlink = 2 + Σ child dirs.
3. Parent fsync = cross-shard barrier: take parent EX (mutations hold parent PR for their whole txn) → recall/drain shard authorities → dir buffers + summaries home / durably logged → force every relevant local/foreign slice → persist manifest → release. Define O_SYNC/O_DSYNC create, fsync(child) semantics, death during fsync, wait for foreign replay.
4. Shard-set lifecycle ALLOCATING→COMPLETE→PUBLISHED→DELETING→FREE, generation/UUID tagged; parent published last; references = ino + gen + shard UUID; recovery resumes/frees ALLOCATING, never exposes incomplete.
5. Shards detached: internal marker (logical parent ino+gen, index, manifest gen, hash params); never exposed via readdir/handles/exportfs/backup; MXFS incompatible feature bit.
6. Child dirs: logical '..' = visible parent; cycle checks on logical parents; dir rename updates logical '..'; parent-pointer records virtualized.
7. Rename: same parent cross-shard = ONE XFS txn (both shard locks canonical order, flags NOREPLACE/EXCHANGE); cross-parent = global canonical lock order, one txn or durable replayable intent.
P1: hard links (target nlink global), readdir (no internal names, '.'/'..' once, exact-once w/o mutation, cookie design proven or per-open cursor), rmdir (parent EX + all shards checked), quota/project/ACL/xattr on visible parent, tooling/export/notify audit.

## Build order (each rig-measurable)
0. Instrument + safe handoff optimizations (sequence-proven redundant-force skip, poller reduction, cached-copy validity by generation+epoch) — exit: full decomposition of the 70-100 s.
1. On-disk feature bit + manifest (checksum, UUID/gen, N, hash/seed, state, shard ino+gen) + shard marker + mkfs/chk support + unpublished-set cleanup; crash after every write; no namespace use.
2. Opt-in sharded mkdir (mount option/ioctl): regular-file create/lookup/unlink/readdir, parent summaries, stat synthesis, internal-object filtering; rig: 32×100 O_SYNC creates, N=16/32/64, uniform/prefix/sequential/adversarial names — target near 17 s.
3. Durability: parent fsync barrier, per-shard durable sequences, dead-node handling, foreign replay integration; crash matrix per stage.
4. Rename + hard links staged (same shard → cross-shard → cross-parent → sharded↔unsharded → links → exchange/noreplace); crash at every boundary.
5. Child dirs/ancestry: '..', derived nlink, dir rename, cycles, rmdir, getcwd, exportfs.
6. Ecosystem: quotas/project, ACL/labels, xattr, notify, export, backup, scrub/repair, freeze.
Note: 32 random ops over 32 shards occupy ~20 shards at once (64 → ~25): EX still rotates per shard; gain is parallel lock domains — benchmark N=32 and 64.

## Recovery interaction
Shards reuse per-inode replay/authority rules; add manifest/topology authority on the parent, manifest gen in shard token validation, multi-inode txn records; parent fsync waits for/triggers dead-slice replay; intent census must include shard-set create/delete intents, unpublished COMPLETE parents, cross-shard rename intents, orphaned internal shards (identify by UUID/gen, never ino alone); purge stays conservative.

## Before default-on
Full semantics, exhaustive fault injection, tooling, compat refusal, stable perf incl. adversarial names, accepted capacity cost (32-64 inodes/dir), hash equivalence proven, cookies proven, monitoring, no hidden fallback. Prefer policy-based enablement for hot/shared dirs.
