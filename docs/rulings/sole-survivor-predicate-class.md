<!-- sess574 RULE-5 ruling on the 77-guard is_single_node class: sweep all 77, retire the predicate, and the missing axis is recovery-drain state not memb… -->
# RULE-5 ruling (sess574): the `is_single_node()` guard class

Asked because the class had been declared closed **twice** at single call sites
(D-0904, D-0949) and 77 guards were still standing. Five shapes were put:
(a) hand sweep, (b) retire the ambiguous name and force every caller to pick,
(c) typed reason argument, (d) make `ever_multi` sticky so `is_single_node()`
returns false forever, (e) census-driven — fix only what a probe shows firing.

## The ruling

**(b), but not with the two predicates I proposed. And the sweep is
unavoidable — there is no shortcut.**

- **(c) rejected outright.** A reason tag records the *caller's opinion*, which
  is exactly what has been wrong every time. It does not encode the
  precondition that makes the optimization valid.
- **(d) is a containment mode, not the fix.** Useful as an emergency
  mitigation, a qualification knob, an A/B reference, and a way to price
  conservative behaviour — never the architecture.
- **(e) is coverage evidence, never a safety criterion.** A site that does not
  fire under the current suite can still be the one that eats a filesystem.

## The hazard that lands on work already done

> `ever_multi` is per-mount, while residue is not. A survivor can remount and
> reset it while remote residue remains on disk. A mount-local sticky bit
> cannot prove the filesystem has never had a remote writer.

**Verified in source the same session and it is real.** `ever_multi` is a plain
bool in the per-mount `struct mxfs_v5_dlm` (`dlm/v5_mount.c:536`), assigned in
exactly one place (`:17338`), backed by nothing durable. So
`sole_survivor()` = "has this MOUNT had a peer", not "has this VOLUME had
another writer" — and every guard built on it turns off again after any
unmount/mount-alone cycle. Filed as **D-0956**; it scopes the D-0949 closure to
the within-mount case and puts D-0955 behind the same hole.

### What the per-mount lifetime actually protects (the D-0956 resolution)

The hazard above assumes the guards need the fact "has this VOLUME ever had
another writer".  The consumer inventory says they need a narrower fact:
"does state from another writer's epoch exist that THIS mount has not
reconciled".  (0.87.16 removed `mxfs_v5_dlm_never_multi()` and its nine
sites: they were not protecting residue but exempting a lone mount from the
ownership protocol, and the replayer of that mount's slice after a death
needs the grants the exemption withheld — `docs/sole-survivor-sweep.md`.
The residue argument below is unchanged for the `sole_survivor()` consumers.)
Every consumer of `mxfs_v5_dlm_sole_survivor()` and, at the time,
`mxfs_v5_dlm_never_multi()` (7 + 9 real call sites) protected one of:

- in-core state inherited from the multi-node epoch: pending directory reload
  marks (`mxfs_dlm_dir_consumer_refresh_impl`), cached dentries
  (`mxfs_drevalidate`), cached inode-cluster images carrying a departed
  peer's passengers (`mxfs_submit_partial_inode_write`), phantom in-core EX
  modes on recycled shells (`mxfs_dlm_rearm_unpublished`), unpublished dirty
  inodes and the NL-logged bypass (`mxfs_dlm_ilock_begin/end`,
  `mxfs_dlm_publish_inode`, `mxfs_dlm_publish_dirs_work`, the three
  `xfs_iget_cache_miss/hit` reads);
- a departed peer's unpublished free still on the platter under a number the
  btree calls free (the candidate validator in `mxfs_dialloc_two_phase`);
- or a diagnostic (`MXFS_SOLE_SKIP_NOTE`, `mxfs_dino_clobber_probe`, the
  `sole=` flag on `P103-CHUNKFREE`).

None of that survives a clean unmount by every node followed by a mount:
caches are gone, every free and every image has landed, a dead node's slice
is replayed at mount before the mount is writable, and a lone mount reads all
of its state from the platter.  The one consumer whose consequence was itself
durable (deleting a fully-free inode chunk, whose blocks a later directory
could reuse) was taken off the predicate: a clustered volume never deletes a
chunk.  So after a quiesce the "residue" is durable, consistent state that a
fresh mount reads correctly, and a volume-lifetime predicate would only make a
lone mount run the multi-node protocol against itself with nothing to
protect.

What protects a lone mount's later peer is not a predicate at all but the
class-2 rule below: the join-ready invariants are converted at admission (the
join-time flush and publication of the incumbent's NL-logged state), and that
barrier runs the same way whether the incumbent is a never-clustered volume's
first mount or a remount after two writers.  Measured on 2/tcp
(`tests/d0952_sole_create_rejoin_coherency.sh` arm `lone`): both nodes write,
both unmount, one mounts alone (P-SOLE-SURVIVOR 0 for the whole lap), creates,
recycles, links, symlinks and renames without grants, the peer then joins for
the first time in that mount's life, sees every file, and both nodes read each
other's overwrites; the cold `chk_mxfs` afterwards is clean with the
chunk/free-space audit OK.

Other hazards named for (d), worth keeping even though (d) was not chosen:
- a "multi-node path" may *require a live peer* (waits for a BAST/AST, a remote
  master, quorum) and become a hang in a singleton — always check the slow path
  makes progress with zero peers;
- "not yet multi" ≠ exclusive: a node can act before it first observes a joining
  peer unless join is serialized against the singleton fast paths;
- even a never-clustered filesystem must maintain join-ready durable
  invariants, so "never had a peer" does not by itself justify omitting durable
  publication.

## The cut line I had wrong

Not "performance vs correctness". The question is:

> **What fact makes the skipped operation unnecessary, and what prevents that
> fact from changing during the operation?**

Three classes, not two:

1. **Current exclusive epoch** — transient coordination may be elided, but only
   under a *held token* proving no peer can become active before the operation
   finishes. A bare `alone_now()` boolean is a TOCTOU observation, fit for
   telemetry, not for deciding whether correctness work can be skipped.
2. **Join-ready durable invariant** — anything whose output can outlive the
   membership epoch (publication, allocation/reuse validation, inode-cluster
   write masking, invalidation obligations, ownership transitions). Maintain it
   regardless of membership, or install an explicit conversion barrier before
   peer admission: quiesce → publish/reconcile/validate → flush → invalidate →
   admit.
3. **Departure/recovery state** — *the axis I was missing*. Some decisions
   depend on the previous owner's disposition, not on member count. A node can
   be alone in at least six materially different states: no known remote
   tenure; peer draining; peer completed a clean ordered handoff; peer vanished
   and not yet fenced; fenced but recovery incomplete; recovery complete for
   some AGs/resources and not others. The safe optimization is often
   **scope-specific** — recovery of one peer or one AG does not prove every
   inode cluster, AG, lock resource and invalidation queue is reconciled.

"Clean leave vs dirty death" should be represented directly, and "clean" must
be a *protocol result* — not "unmount was requested" or "TCP closed normally".
A rejoining peer must carry a new incarnation/epoch, or stale completion
records from the old one get mistaken for proof about the new.

## API shape recommended

Do not export a general boolean answering "single node"; keep raw membership
inspection private to the DLM layer. Prefer proof-bearing calls — an
exclusive-epoch token the caller must acquire, a scoped
`recovery_complete(scope, epoch)`, a `join_ready(scope)` — and, where possible,
hide the decision inside the operation (`write_inode_cluster_safely()`,
`validate_inode_reuse()`) rather than having every caller pick a topology
predicate.

## Stopping the regrowth

1. Delete or privatize the ambiguous API so no filesystem code can compile
   against it — including `member_count == 1` and cached booleans.
2. CI-enforced semantic ban (Coccinelle/clang, or grep as a floor) on direct
   node-count tests outside the membership implementation. **The 77-site census
   is a lower bound** if the value can be propagated through a variable.
3. Runtime assertions on the proof tokens (join exclusion held, epoch
   unchanged, recovery complete, correct scope).
4. A reviewed site inventory: site id, skipped operation, invariant, required
   token, clean-leave behaviour, dirty-departure behaviour, join behaviour,
   covering test. **Closure of the class requires all 77 classified and the
   legacy API removed** — not individual bug fixes.
5. Test *transitions*, not stable states: joining, clean leave at each drain
   stage, power loss, partition before fencing, recovery in progress, rejoin,
   survivor remount, crash during recovery-complete publication.

## Ordering

Freeze the class in CI → keep (d) as a reference mode → define the
membership/recovery state machine → define join/departure ordering → introduce
proof tokens → mechanically remove the old predicate so every site fails to
compile → classify and convert all 77 *in semantic groups* (allocation, inode
writeback, publication, invalidation, locking), never in file chunks → verify
slow paths progress with no peer → fault-injection against the reference mode →
privatize every remaining raw topology predicate.
