<!-- Compiled: the CAW criteria-ladder era (0.10.6x-0.11.31) — FUA misconfig pivot, read-storm refutations, b_sema poisoning, claim TOCTOU, ICLUSTER, 4-co… -->
# The CAW criteria-ladder era (0.10.6x → 0.11.31, ccloop runs 12e0d157 / 0d6e174d / e8e920f7 / daf50d34 / ff214062 / 5d123e7b / 72513a13)

Criteria across these runs: **"1/2/4/8/16/32 node caw dlm multipath, 100%"**, later extended to
**four deployment conditions** — `tcp` (LIO), `cawp` (SCST passthrough), `cawd` (direct iSCSI),
`caw` (dm-multipath) (`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`,
`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`).

## 1. The misconfiguration that ate five sessions

The 32-node "read storm" — 31,000-41,000 cold AG0 re-reads in 3-4 seconds — was chased through
a code map, a staler-attribution probe, and **four separate refuted fixes** before the actual
cause turned out to be a one-line default.

**The storm's source was correctly identified early:** `mxfs_dlm_reload_inode` invalidates the
cached inode-cluster buffer on every run, and the FUA gate then cold-re-reads it. Buffers were
genuinely EVICTED, not merely invalidated (`docs/history/caw-sess5-staler-identified-reload-inode-and-levers-tried.md`,
`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`).

**Four fixes were built to skip that reload — all refuted, and all by the same test:**

1. `reload_skip_owned` gated on `grant_handoff` — **broke cache_coherency@4 to 0/4**
   (`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`).
2. The mode==0 + handoff-bit variant — passed cache_coherency and strong_consistency at 4,
   **still broke dir_reuse** (`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`).
3. `dir_slow_handoff_gate` — passed cache_coherency@4 4/4, **dir_reuse@4 0/4**. The gate fired
   heavily (n=3072 on the root dir); it was skipping exactly the reloads dir_reuse needs
   (`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`).
4. A create-authorship gate mirroring `xfs_icache.c`'s existing
   `!(flags & (XFS_IGET_CREATE|XFS_IGET_INCORE))` suppression was designed as the "correct"
   version (`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`).

**The pattern behind every refutation: `dir_reuse` is cross-node inode REUSE.** Any gate that
treats "no cross-node handoff since our acted gen" as "in-core authoritative" is false for a
recreated inode.

**The actual root — `lsscsi` on three nodes.** The CAW multipath target is **SCST_FIO**, not LIO;
`mxfs_fua_disable` had been defaulted to 0 by a session working on a **LIO** cluster. On SCST all
initiators share one coherent write-back cache, so **a SCSI-FUA read pierces to the un-destaged
platter (staler AND slower) while a plain BIO read hits the coherent shared cache (fresh and
fast)**. `fua_disable=1` took @4 to 17/17 — including the dir_reuse cell that had broken every
reload-skip fix (`docs/history/caw-sess6-pivot-scst-confirmed-fua-disable-is-the-storm-fix.md`,
`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`).

A companion measurement corrected the storm's own characterisation: a mode-split probe proved it
was **`mode != 0` DIRECTORY reloads (~75%)**, not the mode==0 self-recycle case that had been
chased for two sessions (`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`).

**And a second, genuinely separate root remained:** with `fua_disable=1` loaded and
cache_coherency@16 passing 16/16 in the same run, `dir_reuse@16` still stalled on round 2 — the
first REUSE round — with a live stack showing `stat → xfs_ilock → caw_wait_for_grant → msleep`.
That is **CAW grant starvation**, not the read storm
(`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`,
`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`).

## 2. Substrate freshness dominates every measurement

`run.sh` prep re-mkfs's every run and reloads the module, so on-disk degradation is impossible —
yet **fresh `dlm_scaling@32` scored 27-28/32 and a second run on the same substrate scored 3/32**,
with 1760 AG0 reads in 8s. The degradation is **transport-level** (SCST/iSCSI/PR); only a full
`virsh destroy+start` of all 32 plus preflight resets it.

Corollary that unblocked the ladder: `criteria.json` records each test independently, so each
failing test can be run on its OWN fresh substrate and its pass banked — a full 17-test sweep in
one invocation is not required (`docs/history/docs/history/caw-sess5-32node-fresh-baselines-and-fua-read-root.md`,
`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`).

Also from this era: `persig_flush=2` fixed the dir_reuse@16 rm-rf hang *and* kept it coherent
(the EX-release drain already enforces durability at handoff, so deferring the per-modify flush
is safe) — leaving reuse-round reload cost as the residual, 16× slower than round 1
(`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`).

## 3. b_sema poisoning — the enabler behind several "unrelated" families

`xfs_buf_relse` **is** unlock+rele. Two sites did `xfs_buf_unlock(bp); xfs_buf_relse(bp);` — so
every EX reload of the btree-format shared dir **double-unlocked every held bmbt buffer**, +1 to
`b_sema` each pass, leaving buffers permanently multi-ownable. Probes caught it one second into
round 1: 400 over-ups on a single daddr, count climbing 2→19 within one second.

That single defect explains: xfsaild's delwri trylock succeeding during `rm`'s hold → 54 double
submits → racing completions → double `xfs_buf_item_done` → spurious not-in-AIL shutdown and an
xfsaild NULL-relse oops → **and** write-write wire reordering of same-buffer double submits as a
prime single-dirent-loss vector. Likely also the enabler of the whole lost-wakeup family
(`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`).

Removing it produced **the first full pass of `dir_reuse_coherency@32/caw`** — 32/32 nodes,
24/24 rounds, every probe zero on every node (`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`).

## 4. The mkdir-storm dirent-loss family

**Claim-empty TOCTOU, caught red-handed.** `find_slot_skip` returns `-ENOENT` plus an empty
index; between that probe and the re-read, a peer's fresh claim of the same tombstone lands. The
re-read returns the peer's LIVE image, so our CAS (compare = live image, write = memset-fresh)
**succeeds** — **the re-read launders the race**. The peer's holder bits are wiped and the
generation resets to 1 while it still believes it holds EX → double-EX → its destage is refused →
a committed dirent never destages → durable loss. Evidence: three foreign-strip events all from
the claim CAS return address, disassembly-verified. **SCSI CAW itself was verified fine**
(`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`).

**And a second, unrelated shape closed the family:** an `iget` of a REUSED ino failed ENOENT
twice because a prior-incarnation shell was mid-teardown (I_FREEING) behind an ~18-inode inodegc
backlog; the lookup's 8-try/~360ms budget expired and `mkdir` died in path resolution — the
dirent was never created anywhere. Fixed with a gc-wait; **30/30 rounds clean** afterwards
(`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`,
`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`).

## 5. The AIL freeze — first discovery of the `_XBF_DELWRI_Q` collision

A 32-node `posix_multi` collapse looked like fence impatience, and layer 1 was: the release fence
gave the whole-AIL push 5×2s and treated "not landed in 10s" as a wedge → **five nodes
self-shutdown simultaneously**. Fixed to be progress-based.

But layer 2 was real. `P-AILMIN` proved the frozen AIL-min item was a **fresh inode-cluster
buffer with `XBF_DONE | _XBF_MXFS_ALLOC_QUEUED | _XBF_DELWRI_Q`**: `xfs_ialloc_inode_init` queues
fresh clusters with `_XBF_DELWRI_Q` preset, so xfsaild's `xfs_buf_delwri_queue` returns false and
the item stays `XFS_ITEM_FLUSHING` **forever**. Those buffers land only via the AG-release Phase-2
drain — and a **create-only** storm never fires AG BASTs, so they sit there and every fence on
the node stalls. `dir_reuse` never hit it because rm-churn constantly fires AG drains.
**`posix_multi@32` was the first post-fence create-only test to arm the landmine.** Fixed by
draining all AGs' alloc buflists at stall==3
(`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`).

This is the same design tension CLAUDE.md now records as `_XBF_DELWRI_Q` collision.

## 6. The GPT verdict that set the architecture

After the mkdir-storm whack-a-mole, a user-directed consult ruled, **bindingly**:

> **CAW is salvageable. Do NOT build NET2 for this.**

NET2 was a larger new correctness surface, and envelope mode still depends on the same XFS
durability boundary. Import NET2's identity **discipline** only: non-lossy resource identity,
incarnation-qualified tenure IDs, **one state machine per resource**, gen-qualified idempotent
release, stale release ignored, loss-of-certainty stops grants. Cut overlay, shards, replication,
raft terms, midcomms, envelope delegation. Reader-monotonicity as proposed was ruled **UNSAFE** —
an in-core image may be an abandoned double-EX branch — and permitted only as assertion +
fail-closed. Enforcement clause: *"if the team cannot prove EVERY CAW release and acquire goes
through the new state machine, CAW is unsalvageable in that implementation"*
(`docs/rulings/caw-salvageable-tenure-state-machine-plan.md`).

NET2 itself had been carried to gate 5 in a separate run before that ruling — lock plane, shard
scenarios ×4 seeds with ASan, and a first-ever `net2_epoch.c` build — and was then deliberately
not entered past step 5 (`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`,
`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`, `docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`).

## 7. The perf bar — a standing user directive

> No test may take 1-2 hours EVER. 32 nodes of users reading and writing must see
> seconds-to-minutes.

Budgets are **enforced product requirements**: ≤120s per test at 32 nodes, a 32-rung under 20
minutes, the whole ladder under an hour. **Never widen a budget toward a measured wall** — the
`dir_reuse 60*N → 90*N → 140*N` history is the named anti-pattern, and that override was deleted
from run.sh. Debug with bounded minutes-scale experiments (8 nodes, 6 rounds), not hour-scale
boards (`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`).

## 8. Roots proven and fixed across the ladder

- **EFI AG-wait**: `__xfs_free_extent` has the one unconditional blocking AG-DLM acquire; under
  32-node fio saturation an AG release drain takes minutes, the acquire times out, and
  `xfs_defer_finish_noroll` treats any non-EAGAIN error as **fatal** → shutdown. Fixed with a
  capped -EAGAIN requeue; 8 dead nodes → 0
  (`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`, `docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`).
- **mmap-fault vs bast-drain ABBA**: the fault holds locked folios then takes the cluster ilock,
  while the drain's invalidate needs those folios. It had passed on the previous build **by luck**
  — a probabilistic window, not a regression (`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`).
- **Freed-inode RELFLUSH**: an idle demote stripped the file inode's EX in the
  droplink→inactivation gap, so the freed dinode was never destaged under NL → stale-disk recycle
  adopt → *"Free inode N has blocks allocated"* → shutdown within 20s
  (`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`).
- **The close-demote was itself the trigger** for the dlm_fairness corruption — single-variable
  A/B: `ex_close_release_ms=0` → PASS 8/8 in 8s
  (`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`).
- **ICLUSTER phase 1**, reworked to a **coverage sweep rather than refcounts** after an audit
  found per-grant refcounts structurally fragile (PR→EX upgrade is lock-lock-unlock; ~6 recovery
  paths set `i_dlm_mode=NL` with no release call), plus sticky acquire-side routing, a
  `grant_seq` coherency clock for routed files, and stale-EX wedge fixes
  (`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`,
  `docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`,
  `docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`,
  `docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`,
  `docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`,
  `docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`).
- **MHT quiet-age gate** plus resource-scoped clock fixes killed a 470s ABBA wedge chain and took
  cc@32 from 79s to ~60-62s (`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`).

## 9. Methodology worth reusing

**The kprobe op-ledger.** Probes on the PAL I/O primitives, cluster-wide, windowed by the DRCph
phase markers, with `stacktrace` triggers for caller attribution and argument capture on the sleep
primitive. That measurement is what forced the batching pivot after five "shave" fixes measured
flat (`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`).

**The cc@32 rotation anatomy**, via per-grant wait prints with wall-clock pairing fields: batching
is *healthy* (tenures serve 40-60 EX ops); **two regimes** set the phase wall (fast-client ≈ 6s,
slow-client under host CPU load ≈ 10-15s); and **fragmentation under client jitter is the variance
driver** (`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`,
`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`,
`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`,
`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`).

**Single-build provenance is mandatory.** A matrix reading "all 17 tests PASS at every node count"
was assembled from passes spanning six days and mixed builds, some recorded implausibly fast —
so the whole matrix had to be re-validated on one build
(`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`). The milestone was finally
recorded as **32/caw = 17/17, all fresh on a single build, verified by a script with an explicit
`--since` cutoff** (`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`).

**Two wedge-preventer params had to become default-ON** — bast dedup and a bounded bast workqueue
— because 32-node coherency failed with the shipped 0 defaults
(`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`).

## 10. Rig hazards recorded here

- **Never mass-`virsh destroy` many VMs during heavy LUN I/O** — that caused a host SCST wedge
  that only a user-performed host reboot could clear
  (`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`).
- After a host crash, `/etc/init.d/scst start` restores a **stale auto-generated `/etc/scst.conf`**
  referencing a backing file that no longer exists, and `/tmp/.mxfs_pass` is wiped
  (`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`).
- Buffer double-free and rele-on-zero tripwires were added at the `xfs_buf_free` chokepoint after
  an agent proved all frees funnel there (`docs/history/docs/history/docs/history/compiled-caw-criteria-ladder-era.md`).
