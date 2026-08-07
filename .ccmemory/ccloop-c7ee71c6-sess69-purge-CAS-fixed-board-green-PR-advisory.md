---
name: ccloop-c7ee71c6-sess69-purge-CAS-fixed-board-green-PR-advisory
description: sess69: purge publication defect FIXED (0.11.412) + FIRST rig cycle in 11 versions, board GREEN + the constraint that breaks the sess68 ruling: PR fe…
metadata:
  type: reference
tags: [foreign-replay, recovery, disklock, purge, scsipr, fencing, board-verified, gpt-consult-pending]
---

# sess69 — a shipped defect fixed, the board finally boarded, and a constraint that breaks the sess68 ruling

Build **0.11.412**, srcversion `2C85D70AD8070513B81D772` (was
`93FB14589298C2E12BBAE2D` at 0.11.411).  Clean build; the two
`-Wframe-larger-than` warnings are pre-existing (`join_gate`,
`confirm_dead_mask`), not from this change.

**THE "DO NOT BOARD" STATUS IS OVER.**  0.11.402..412 had never had a rig
cycle; this session ran one and it is GREEN.  See the measurements below.

## 1. FIXED — `mxfs_disklock_purge_node` published by plain write (shipped defect)

This is GPT sess68 refusal item 4, which sess68 flagged as "a candidate
SHIPPED defect, audit it first".  Audited: **it was real, and worse than
described.**  Both zeroing sites did `read_sector()` then `write_sector()` —
a read-modify-write with no interlock against the other survivors running the
identical purge for the same dead node.  There are SIX call sites, and
`mount.c:1057`/`1126` run one on EVERY survivor at peer death, so concurrent
purgers are the normal case, not an exotic one.

Losing interleaving (no exotic timing needed):

    P1 reads slot S      -> the dead node's ACTIVE grant
    P2 reads slot S      -> the same image
    P2 writes zero       -> S is free
    live node E claims S -> writes its own ACTIVE grant
    P1 writes zero       -> E's LIVE grant is destroyed

E then believes it holds a lock that no longer exists on disk → the same
resource can be granted twice.  The **heartbeat** variant is worse: the late
zero erases a LIVE node's heartbeat record, every peer declares that node
dead, and the cluster fences it and replays its journal slice while it is
still writing to the LUN.  That is split-brain.

**A SECOND, INDEPENDENT HOLE in the same function** (not in GPT's list — found
during the audit): the sess65 phase-0 freeze gate is evaluated on a read taken
*before* the 65536-record scan, but the zero pass re-checked only
`recov_desc_names()` ("does the descriptor name this victim") — **not its
stage, not its owner, and not the unreadable case**.  A descriptor that
advanced, changed owner, or became torn during the scan was published anyway,
defeating the gate entirely.

### The fix (dlm/disklock.c)

- `purge_cas_zero()` — publication is now `mxfs_pal_bdev_compare_and_write()`
  of the exact validated image.  `-EAGAIN` (MISCOMPARE) ⇒ re-read and
  re-derive the decision, bounded by `MXFS_PURGE_CAS_RETRIES` (4); exhausting
  retries is counted as incompleteness, never as success.
- `purge_hb_zeroable()` — the full freeze gate (quarantine / stage /
  owner+epoch / torn), re-derived **on the image the CAS publishes against**,
  using `recov_lease_covers()` so a torn descriptor returns `-EPROTO` instead
  of being silently skipped.  Gate-and-publish are now one atomic step.
- `-EOPNOTSUPP` fallback: only reachable when `mxfs_bdev_to_sdev()` finds no
  SCSI device behind the bdev, i.e. not a shared LUN, so no second purger can
  exist.  Falls back to a plain write and COUNTS it —
  `P235-PURGE-NONATOMIC`.  Never silently.
- New probes: `P235-PURGE-CONTENDED`, `P235-PURGE-CONTENDED-HB`,
  `P235-PURGE-REFROZE`.  All feed the existing sess59 honesty accounting, so
  an incomplete purge still returns < 0 and recovery is NOT published.

**Status: FIXED, NOT YET FULLY VERIFIED.**  The board (below) proves the CAS
did not break the normal single-death path — no false MISCOMPARE stalls, no
wedge.  It does NOT exercise the concurrent-purger race itself.  RULE 6
closure needs a test that forces two survivors to purge the same victim
concurrently.  **Not yet in the ledger — add it (see "next" below).**

## 2. BOARD — first rig cycle since 0.11.401, GREEN

Deployed `MXFS_FORCE_PREP=1 ./run.sh 32 caw prep_cluster` — 70 s, all 32
nodes `active_count=32`, srcver confirmed.

| criterion | result |
|---|---|
| `fence_during_write` | **PASS** 32/32, 8/8 checks, **17s/60s** |
| `crash_consistency`  | **PASS** 32/32, **204/204** checks, **86s/90s** |
| `dir_reuse_coherency`| **PASS** 32/32, 93/93 checks, **107s/120s** |

`crash_consistency` is the thinnest-margin cell on the board and the first
place a regression lands — it is green.  `fence_during_write` and
`crash_consistency` both exercise the death→fence→purge path this session
changed.

`dir_reuse_coherency` had been the board's only FAIL at **120/120s (a
timeout) with hostload=32.60**; it passes at 107s with hostload=19.26.  That
cell is **load-correlated**, which is D-32NODE-SHARED-DIR-CREATE-PACE, not a
new fault.  Per RULE 6 a clean run is NOT a disposition — it stays OPEN, and
107/120 is still a thin margin that will time out again under host load.

## 3. THE CONSTRAINT THAT BREAKS THE sess68 RULING — PR fencing is ADVISORY

The sess68 ruling made takeover conditional on *authoritative retirement
evidence*, whose primary admissible form was "a locally completed fence for
that exact incarnation".  **I went to verify that is producible.  It is not,
in general.**  From `dlm/scsipr.h:63-78`:

> live_members ... used to classify the topology: when fewer keys than live
> members are registered, **per-node PR is unusable on this rig** (e.g. every
> VM shares ONE host I_T nexus, so each node's REGISTER overwrites the
> previous one's) and **PR is ADVISORY: no preempt, no self-fence**; reactive
> fencing via D1 (EBADE on write) + lease/disklock still applies.
> **Returns 0 when the victim is gone (fenced, never there, OR ADVISORY
> TOPOLOGY)**

So `mxfs_scsipr_fence_node()` returning 0 does **NOT** mean the victim was
fenced — it can mean "we determined we cannot fence anyone", and the call site
cannot tell the two apart.  Consequences:

- GPT's evidence form (1) is available only on hardware where PR is active.
  On the VM rig there is **no hard I/O exclusion at all**.
- **The `FENCED` stage may be a lie.**  It records that a fence was
  *attempted and returned 0*, which on an advisory topology means nothing was
  fenced.  I consider this a SEPARATE defect from the wedge — it is a durable
  on-disk claim that is not backed by the guarantee its name implies.
  **Not yet in the ledger — add it.**
- Real SAN hardware may honor per-node PR (see `physrig-fixes-v74-76-...`), so
  the design must handle BOTH cases and must record WHICH guarantee was
  obtained.

## 4. STILL OPEN — defect B, the permanent recovery wedge

Unchanged from sess68 and still the highest-severity thing in the tree.
Line-proven this session:

- `recovery_begin` (disklock.c ~2000-2010): descriptor present and owner is
  not us ⇒ refuses, "another survivor owns this recovery; not publishing".
- `purge_node` freeze gate: stage < GRANTS_RELEASED ⇒ `-EBUSY`; owned by
  another survivor ⇒ `-EBUSY`.
- `recovery_refresh`, `recovery_read`, `recovery_takeover` are **called from
  nowhere**.  Only `begin` (v5_mount.c:2079) and `advance` (2106, 2153) are
  live.

⇒ An owner that dies between `begin()` and `GRANTS_RELEASED` freezes the
victim's slot forever; the victim's grants are never released, so it holds
locks permanently.  **This is strictly worse than 0.11.401** and is a
regression introduced at 0.11.409 when the descriptor went live without its
takeover driver.

## 5. NEXT SESSION — do these in this order

1. **Re-issue the RULE-5 consult.**  I sent it; it exceeded the 120 s MCP
   window, went to background as task `k5vyqp0lk`, and **does not survive the
   session**, so the answer was lost.  Re-send it — the full question is in
   this session's transcript.  Its five points, in short:
   (1) correct takeover predicate when hard I/O exclusion is unavailable, and
   whether a durable fencing TOMBSTONE is meaningful or just relocates an
   unprovable claim; (2) is "fail closed, require administrative fencing" the
   honest answer under advisory PR, given a permanent wedge is itself a
   defect; (3) is GPT's own software-only alternative — "replay application
   rejects writes from an obsolete owner term" — actually constructible, given
   replay writes are bulk XFS buffer images written straight to the LUN with
   no device-side authority check, and would per-sector CAS gated on
   `owner_term` be sound or merely slow and still racy; (4) split `FENCED` to
   record WHICH guarantee was obtained (hard-preempt vs advisory) — minimal
   wire change, and the format is still free (no deployed cluster has ever
   written a descriptor); (5) whether finer-grained durable per-image replay
   progress is needed or is subsumed by (3).
   **Give it the advisory-PR constraint up front** — it is what invalidates
   its previous ruling.
2. **Ledger the two new defects** in `tests/criteria/OPEN_DEFECTS.json`:
   the purge non-atomic publication (FIXED in 0.11.412, verification of the
   concurrent-purger race still owed) and `FENCED`-may-be-a-lie (open).
   The board's `open_defects` cell reads that file.
3. Then the coordinator + takeover, per whatever the re-issued ruling says.
4. Re-board after the coordinator lands.

## Method note worth keeping

Eleven versions went unboarded because each session deferred the rig cycle to
land "one more fix" first.  Breaking that cost 4 minutes of rig time and
converted eleven versions of unverified change into a green baseline.  When
the unboarded backlog is deep, **board first** — the verification is worth
more than the next increment, and building a coordinator on an unverified base
is how a regression gets buried.
