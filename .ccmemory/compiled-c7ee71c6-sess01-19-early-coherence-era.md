---
name: compiled-c7ee71c6-sess01-19-early-coherence-era
description: Compiled: c7ee71c6 sess1-19 (0.11.77-163) — torn-dir-block roots, withdraw ordering, D3 co-resident clobber, TCP false death, and the birth of the ob…
metadata:
  type: project
tags: [c, o, m, p, i, l, e, d, ,,  , t, o, r, n, -, b, l, o, c, k, ,,  , c, o, r, e, s, i, d, e, n, t, -, c, l, o, b, b, e, r, ,,  , w, i, t, h, d, r, a, w, ,,  , t, c, p, -, f, a, l, s, e, -, d, e, a, t, h, ,,  , o, b, l, i, g, a, t, i, o, n, -, l, e, d, g, e, r, ,,  , s, h, a, p, e, 1, ,,  , t, e, n, u, r, e, -, c, o, h, e, r, e, n, c, e]
---

# c7ee71c6 sess1-19 — the early coherence era (0.11.77 → 163)

The era that produced the **tenure-coherence doctrine**, the **withdraw-ordering barrier**, and —
after per-exit patching was exhausted — the **publication-obligation counter** that every later
session's ledger work is built on.

## 1. The doctrine: a grant is not coherence

GPT's RULE-5 ruling, which reframed everything downstream: **DLM acquisition establishes
ordering and exclusion, NOT cache coherence.** State is valid only if loaded under the current
uninterrupted PR/EX tenure or an authoritative modification cookie. Corollaries that killed
several standing assumptions:

- `gen == 0` must mean **UNKNOWN → refresh**, not "no refresh".
- A `mode != EX` refresh exclusion is **wrong** — EX is exclusion, not validity; an EX holder
  mutating after a grant gap can relog a stale base.
- Async evict-ring events must be optimisations, never correctness inputs.
- **`drop_caches` does NOT purge xfs_buf metadata buffers**, so "pure LUN" probes never
  disprove a cached-stale-leaf theory ([[ccloop-c7ee71c6-sess7-C-gpt-tenure-coherence-drc-phase1-and-perf]]).

## 2. The 8/tcp torn-directory-block family

`crash_consistency@8/tcp` produced 28-109 CRC errors per node on a **fresh LUN within ~30s**
and a 5-node shutdown cascade, durably corrupting the LUN
([[ccloop-c7ee71c6-sess6-B-torn-da3-crc-and-hole-dossier]]).

Two independent deadlocks were live-captured and fixed first — **FIX-26**, a writeback-vs-
bast-drain AB-BA (flusher holds a locked folio and wants ILOCK; drain holds ILOCK and wants the
folio), plus a zombie AG grant left by membership purge. Both of the inherited attributions
("verify wedge", "pace fail") turned out **wrong**
([[ccloop-c7ee71c6-sess6-fix26-wb-deadlock-orphan-nak]]).

The torn-write root: peers writing **stale dir-block images at sub-EX modes** (`gmode=3/0`),
proven by merging per-node `P-DIRWR` timelines for one daddr — normal phase is strictly
sequential per-node EX bursts, then a PR/NL write lands mid-split
([[ccloop-c7ee71c6-sess6-C-torn-write-ROOT-stale-image-subEX-writes]]).

A submit fence (FENCE-V1) was landed to suppress sub-EX dir writes, and a **FUA bypass** had to
be closed alongside it — suppressed bios' stale bytes were still reaching the platter via a raw
SCSI passthrough write after `werr==0` ([[ccloop-c7ee71c6-sess7-A-fence-v1-landed-fua-bypass-defectB-dominant]]).

**The actual root, found after the fence:** `mxfs_dir_rebuild_leaf_from_data` called
`xfs_dir3_leaf_read(geo->leafblk)` **unconditionally** for any EXTENTS-format dir. On a
BLOCK-form dir that maps LEAF_OFFSET without `HOLE_OK` → the corruption machinery fires on
**every armed create** (EUCLEAN storms, `mark_sick` side-state, ms of latency each); and the
stale-leaf relog raced the split, producing the tear. Gating it turned crash_consistency green
([[ccloop-c7ee71c6-sess7-B-ROOT-rebuild-ungated-leafread-relog-CC-GREEN]]).

## 3. Withdraw ordering — a shutdown that corrupts on the way out

`drc` Shape-2 chain, proven end to end: xfsaild pushes a dirty in-AIL AG bnobt → the AG isn't
held so it is staled as "prior tenure" → the next read hits `P110-BIO-OVER-LOGGED` with
`undest=1` → in-place read completion runs `verify_read` **against dirty in-core content** →
manufactured EFSBADCRC → shutdown → **withdraw released grants BEFORE the slice was replayed**
→ torn dir state ([[ccloop-c7ee71c6-sess9-A-ROOT-drc-shape2-withdraw-tear-and-P110-crc]]).

Fixed as **D2**: withdrawal is a *death stamp* (`MXFS_DISKLOCK_FLAG_WITHDRAWN`, heartbeat
stopped, own slot FUA-stamped); the monitor confirms and fires death instantly; **the local
purge is deferred behind the elected replayer's slice replay**. Plus D1b — in-place read
completion no longer verifies dirty in-core content
([[ccloop-c7ee71c6-sess9-B-D2-withdraw-replay-barrier-VERIFIED]]).

A second membership defect, found on the first-ever `withdraw@2` run: the dead node **never left
lease membership**, because the recovery path purged DLM state but never called
`mxfs_lease_unregister_node`, and the zombie (a force-shutdown FS stays mounted) kept renewing.
TCP mastership is `active_nodes[hash % count]`, so at N=2 the root inode hashes to the corpse
with p=1/2 and nothing ever remasters. **N≥16 passes had been partial-coverage luck**
([[ccloop-c7ee71c6-sess11-B-withdraw2-membership-fix-and-boards]]).

## 4. The Shape-1 family — reused inode numbers and unorderable generations

`xfs_lookup` could return an inode whose in-core state was a **stale prior incarnation of a
reused inode number**, because the in-place reload it armed **silently bails** under storm
(trylock contention + race-bail) and the old code single-shotted it. In the type-flip arm the
in-core is a stale FILE shell while dirent and disk agree DIR, so every walk into the name
returns **ENOTDIR** for ~1s — bash's "Not a directory" in the node shell log was the smoking-gun
artifact, and creates were silently lost
([[ccloop-c7ee71c6-sess10-ROOT-shape1-lookup-returns-unconverged-reused-ino]]).

The same family surfaced in cache_coherency as a **block→leaf conversion not durable before
visible**, on a reused ino whose prior incarnation was a FILE — with
`RELOAD-TYPEFLIP-STALE-SKIP` firing five times because **random generations are unorderable**
(incore 2802965944 vs disk 665119007) ([[ccloop-c7ee71c6-sess9-C-shape1-ROOT-conversion-durability-cc-capture]]).
That unorderability is the same defect class sess27 later proved for typeflip and sess28 for
dir_epoch.

**Ghost dirents** had their own root: an `ls` holds ILOCK_SHARED (taken so the DLM hook fires)
while its own armed reload needs the write side → bails forever → serves a stale shortform body.
A removed name stayed listed on 3 nodes for minutes, `stat`=ENOENT, immune to `drop_caches`.
Fixed with a bounded-blocking converge in `xfs_file_readdir` **before any ilock**
([[ccloop-c7ee71c6-sess11-C-readdir-fix-physboard-tcpflip-incident]]).

## 5. D3 — the co-resident cluster clobber, four roots deep

Physical platter proof came first: a rename failed identically on **all 32 nodes**, and a raw
`dd` decode of the cluster block showed correct current incarnations in most slots and a stale
one in the victim's — durable data loss, with both names resolvable and both `-117` an hour
later ([[ccloop-c7ee71c6-sess13-B-32caw-coherency-ROOT-corident-stale-clobber-repro-recipe]]).

The P172 ring then caught a **live split** — test1 serving ino167 as a FILE while test2 served
it as a DIRECTORY from a storm-era incarnation
([[ccloop-c7ee71c6-sess14-B-D3-ROOT-CAPTURED-dead-incarnation-relog-FIX-deployed]]).

**Three write-side filter predicates were built, deployed and REFUTED by measurement** — worth
never re-walking:

1. Skip every NL logged DIR slot → cc passed but **regressed**: it stranded a freshly created
   dir (whose landing IS a post-demote write), leaving the platter slot FREE and the dir
   invisible cluster-wide.
2. Gate the skip on dir-epoch supersession → the epoch helper returns 0 after release, so the
   skip never fired and the loss returned.
3. Gate on the RELFLUSH publication token → **decisive**: the reverting writes carry
   `relflush=1`, i.e. they ARE the sanctioned release drain publishing with the grant still
   held. **No write-side filter could work** ([[ccloop-c7ee71c6-sess14-G-D3-ACQUIRE-SIDE-ROOT-stale-fork-rmw-FIXED-P174]]).

The byte-exact revert was captured in a merged 32-node ledger — three lines telling the whole
story: a correct 7-name write, then a `mode=0` write of 3 names **erasing 4**, then everyone
building on the corpse. The four erased names were exactly the four the test reported missing
([[ccloop-c7ee71c6-sess14-F-D3-CV-ROOT-BYTE-EXACT-nl-logged-dir-slot-write-FIXED]]).
A third arm — ghost dirents resurrected by xfsaild flushing retained zombie dir items at NL —
was fenced with `P32E-DIREPOCH-FENCE` ([[ccloop-c7ee71c6-sess14-C-D2-ab-proven-barrier-dual-role-and-D3-arm3-epoch-fence]]).

**True root (acquire side):** the cached-EX fast path RMW'd a fork that was never rebuilt across
peer modifications (`dgen > lgen`), and its authorised drain then published it. cc went from
failing 4 of 6 runs to passing 4 of 5 ([[ccloop-c7ee71c6-sess14-H-HANDOFF-status-and-next-steps]]).

## 6. The birth of the obligation ledger

The D3 residual was isolated to a **reproducer** — the first cc after a fresh prep (later runs
on the same prepped cluster pass) — and diagnosed to the platter: dirents resolving to inodes
that ARE free ([[ccloop-c7ee71c6-sess14-I-D3-residual-is-READ-side-first-cc-after-prep]]).

Then a drain was caught printing `flushed=1 wrote=0` — **declaring durability without writing**.
Extending the drain's identity test to memcmp the shortform fork against the platter was
**REFUTED**: the residual recurred with the new probe firing **zero** times. That result ended
the approach — *stop patching drain exits*
([[ccloop-c7ee71c6-sess14-J-P175-REFUTED-obligation-tracking-required]]).

The replacement is the counter every later session depends on: `pending_seq++` at
`xfs_trans_log_inode` — a single chokepoint for "a change was committed", **deliberately
independent of `ili_fields` / `XFS_LI_DIRTY` / AIL membership, all of which read clean while a
committed change sits in the log, which is the whole reason this defect hid** — with
`durable_seq` promoted only at a real synchronous home write. Validated immediately: the drain
declared success with an unlanded committed change **116 times across 6 nodes**
([[ccloop-c7ee71c6-sess14-K-P176-obligation-counter-VALIDATED-116-fires]]).

GPT's companion designs from the same session — deadline-bounded coalesced destage with
per-dirty-parent "visibility tickets", and the warning that per-inode EX does not protect
neighbour slots in a cluster buffer — set the agenda for sess27-32
([[ccloop-c7ee71c6-sess14-D-gpt-consult-designs-d2-tickets-d5-queue-d3-poison]]).

## 7. Diagnoses that were revised — the record matters

- **sess12-E → sess13-A.** A confident "truncate holds ILOCK + dirty trans, waits on AG-11"
  cycle was **wrong in its final parking spot**: the AG poll actually succeeded in 26ms and the
  block was freed. The real parking spot was unknown, and an owner-stack probe had to be
  deployed to find it ([[ccloop-c7ee71c6-sess12-E-32caw-ROOT-PROVEN-truncate-agwait-self-deadlock]],
  [[ccloop-c7ee71c6-sess13-A-32caw-wedge-REVISED-parking-spot-unknown-probe-deployed]]).
- **sess12-C → sess12-D.** `fence_during_write` is a **NEGATIVE** test — nobody is supposed to
  die — so a "4 survivors not writable" reading was a misframing; the real defect was a spurious
  shutdown ([[ccloop-c7ee71c6-sess12-C-32caw-coherency-regression-OPEN]],
  [[ccloop-c7ee71c6-sess12-D-32caw-spurious-shutdown-wedge-chain]]).
- **D1 root, stack-captured twice 60s apart**, identical: `cancel_work_sync` in the AG
  pre-CAW/yield drain waiting on a work stalled behind the caller's own ILOCK
  ([[ccloop-c7ee71c6-sess14-A-D1-ROOT-FIXED-cancel-work-sync-deadlock]]).

## 8. Infrastructure disproofs and traps

- **The cawp@16 catastrophe was a kernel bug, not mxfs.** A standalone probe
  (`tests/caw/caw_align_probe.c`, direct against `/dev/sda` on the host, no VMs) showed CAW
  payloads **within one page always OK, crossing a page boundary always CORRUPT** — bytes
  arriving as zeros or recycled stale bounce content. Upstream `compare_and_write_callback`
  literally comments *"Currently assumes NoLB=1 and SGLs are PAGE_SIZE"*
  ([[ccloop-c7ee71c6-sess11-A-tcmloop-caw-corruption-INFRA-disproved]]).
- **TCP false death of a live peer:** duplicate-connection churn during a join storm killed a
  socket 0.86ms after "connected"; the outbound reconnect never fired `connect_cb`, so a 40s
  timer declared a LIVE peer dead and exiled it. The survivors with zero errors were the
  culprits ([[ccloop-c7ee71c6-sess12-A-tcp-false-death-outbound-cb-ROOT-FIXED]]).
- **A "failing" criterion that was harness overhead:** `dlm_scaling` measured 21.4 ops/s/node
  against a floor of 30 — but a **fork-free** probe measured 60 ops/s at K=32. The test's own
  process forks were the cost ([[ccloop-c7ee71c6-sess12-B-dlm-scaling-harness-and-32tcp-green]]).
- **A stale cluster marker recorded PASS against the wrong module.** `.cluster_marker.json`
  matched a physrig marker for a VM invocation, so five tests recorded PASS against a stale
  build. The marker now records `node_list` and live-verifies each node's
  `/sys/module/mxfs/srcversion` ([[ccloop-c7ee71c6-sess1-d9-mount-abort-and-rig-fixes]]) — the
  same note carries the D9 fix (DLM-init failure must fail the mount; previously both nodes
  mounted the same LUN uncoordinated) and the LIO `/etc/target/pr` missing-directory trap,
  where **every PR OUT had side effects while reporting failure**.
- **A kernel PANIC that went unnoticed for a session** — `xfs_dir2_sf_verify` NULL-deref during
  BAST release, captured only from a serial log because the node was power-cycled by prep and
  the journal was non-persistent ([[ccloop-c7ee71c6-sess13-C-sfverify-NULL-panic-and-recipe-hit-matrix]]).
- **Board rows persist across builds.** Always check `jq .runs[...].iso` against the current
  build's deploy time before trusting a green row.

## 9. sess19 — the reproducer, and a measurement confound

`tests/sf_mkdir_storm.sh` reproduced three shortform-dir defects at ~25% per round, making the
whole family tractable ([[ccloop-c7ee71c6-sess19-A-sfstorm-reproducer-and-three-defects]]).

And the RELFLUSH publication exemption was **measured unsound**: adding the *actual* grant to
the publish probe and ordering every node's publishes by wall-clock `realns` showed the first
publisher in every failing round held `held=0`. Also recorded: **storm hit-rate decays with prep
age, so single-run A/Bs are confounded**
([[ccloop-c7ee71c6-sess19-B-held0-root-and-prep-age-confound]]).

## 10. Also fixed here

`dlm_scaling` was doubled (15 → 34 ops/s) by skipping the mode/gen disk read entirely under
`MXFS_IF_LOCAL_UNLINK` — `P137 fua_us` went 46-123ms → 0
([[ccloop-c7ee71c6-sess10-B-perf-infra-boards-and-cawp-front]]). A **bnobt lost-update
double-free** caused a healthy node's designed voluntary withdrawal — recovery machinery worked
perfectly, and a healthy node shutting down is still an open defect under RULE 6
([[ccloop-c7ee71c6-sess14-E-bnobt-lost-update-withdrawal-test10-fdw]]).
