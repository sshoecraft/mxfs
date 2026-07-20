---
name: sess50_lessons
description: "sess50 — PROVEN the dominant cache_coherency barrier stall = CAW writer starvation; landed anti-starvation fix (stalls 4-5/20→1/20, criterion passed 0→1)"
metadata: 
  node_type: memory
  type: project
  originSessionId: efd1f3bd-eaba-4192-bbb1-98139d3b29f8
---

# sess50 (2026-06-03) — barrier-dir stall ROOT-CAUSED = CAW writer starvation

**Build `86855C4428A26B4D1F068CF`** (deployed test1-4). Builds on sess49 `10A04B9E` (all 3 KEEP
fixes intact) + sess50 anti-starvation fix + 2 always-on detectors.

## PROVEN root (RULE 4, quantitative) of the ~60-120s barrier-visibility stall
The dominant cache_coherency blocker — the ~120s barrier stall that tips the sequential criterion —
is **CAW lock writer starvation**. Evidence:
- New repro `tests/repro_barrier_latency.sh` (mimics tests/lib/cluster.sh barrier signal+wait:
  mkdir+touch nodeN then poll `find -name node*` til 4 seen). Reproduces the stall ~1/4 iters on
  the OLD build. The stall is a PURE readdir dir-block visibility miss (NO corruption/EIO on a clean
  mount; `find` only does readdir(PR)).
- Non-perturbing STARVE probe (in CAW `bast_poll_fn`, uses the already-read slot = no extra I/O):
  during a 69s stall, `SESS50-STARVE` fired **130×** on the 3 reader nodes with persistent
  `our_mode=3(PR) waiter_mode=5(EX)`, and the slot **generation churned ~45→1695** (~24/sec). The PR
  readers across nodes continuously re-grant PR among themselves (each grant bumps gen) → a peer's EX
  request NEVER finds a zero-PR-holder window → its dir modification (barrier marker) stays invisible
  ~69s until a read lull. COHOLD detector = 0 (NOT a PR+EX co-hold — sess46 theory refuted; sess49 Q1
  "on-disk PR slot dropped" also refuted: census showed sticky PR keeps the on-disk slot).
- **Heisenberg**: ANY perturbation (logging in the dir ilock fast-path, census double-reads, a 3s
  idle settle) creates the read lull the writer needs → stall vanishes. This is why sess36-49 kept
  losing it. Use poll-thread detectors (PROVEN non-perturbing), NOT dir-path logging.

## FIX (build 86855C4, KEEP) — anti-starvation in mxfs_dlm_caw_lock (dlm/dlm_caw.c ~L1446)
Before the compat-grant branch: `defer_for_waiter` = FRESH acquire (our_mode==NL) of a SHARED mode
(PR/CR/CW) while a PEER waits for an EXCLUSIVE mode (waiter_mode EX/PW) → do NOT grab the compatible
lock; fall through to waiter-register/wait so holders drain and the exclusive waiter wins.
**Readers yield to writers ONLY** — writer-writer and reader-reader never mutually defer. (v1
deferred ALL fresh incompatible-waiter cases → all-4 stall + writer ENOENT, refined to shared-yields-
to-exclusive.) RESULT: repro_barrier_latency stalls **4-5/20 → 1/20**; `cache_coherency.sh --nodes 4`
**passed 0→1** (test_unlink_visibility now PASSES). The remaining 1/20 is NOT starvation (STARVE
fired once, gen=13 no churn).

## REMAINING (two DISTINCT roots, neither starvation)
1. **Reused-inode ENOTDIR on barrier dir** (cross_write_read): `cwr_verify` dir inode reused from a
   reg file, peer cached as reg → "Not a directory" → 120s barrier timeout. sess48 family. The
   sess48/49 type-mismatch evict + force_peer_flush are in xfs_lookup (child path) — verify they
   fire for the barrier-dir lookup.
2. **Dir-block lost-update** (rename 1/240; ~1/20 in repro): two concurrent EX writers each add a
   dirent but one reads a stale dir block before re-adding → loses the peer's entry. read-side
   i_dlm_dir_gen covers READERS; the WRITER under EX may add to its own stale cached block. Candidate:
   on slow-path EX acquire of a dir, invalidate the cached dir DATA block (not just bump dir_gen).

## Detectors added (always-on, ratelimited, fire only on the bug — KEEP)
SESS50-STARVE + SESS50-COHOLD in dlm/dlm_caw.c bast_poll_fn (non-perturbing). New repro scripts in
tests/: repro_barrier_latency.sh, repro_barrier_probe.sh. State: /src/mxfs/state.md.
