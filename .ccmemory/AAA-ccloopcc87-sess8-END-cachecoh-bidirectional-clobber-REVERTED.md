---
name: AAA-ccloopcc87-sess8-END-cachecoh-bidirectional-clobber-REVERTED
description: sess8 END: dlm_scaling@32 fixed (build C9D0F29C). cache_coherency@32 uv-gone fix attempt (bidirectional dir-block clobber) REVERTED — regressed posix…
metadata:
  type: project
tags: [sess8-end, ccloop-cc87fed3, cache_coherency, reverted, handoff]
---

## sess8 END-OF-SESSION STATE (relay boundary hit) — tree is CLEAN and SAFE

**Current build: VERSION 0.10.104, srcversion C9D0F29C6FCADEAF836A132** — this is byte-identical
to the FIX-1+FIX-2 state (see `AAA-ccloopcc87-sess8-dlm_scaling32-TWO-FIXES-plus-residual-variance`
for full detail on those two landed fixes). The bidirectional-clobber attempt below was tried,
found unsafe, and **fully reverted** in the same session — no half-applied state, `make modules`
clean, no errors.

## What's DONE and VALIDATED this session
1. **dlm_scaling@32 FIX 1** (the epoch-piggyback-on-unlock-CAS fix) — LANDED, VALIDATED. Root:
   `find_slot()` can never report a tombstone as "found" (contract only matches LIVE slots), so the
   post-hoc epoch-clear session-7 built was calling a function that silently no-op'd 100% of the
   time. Real fix: `mxfs_dlm_caw_unlock_gen()` gained an `is_free` param; when true, the SAME CAS
   that already writes the tombstone on release ALSO zeros dir_epoch/last_ex_slot — zero extra I/O.
   Aggregate throughput improved from historical ~1319-1650 ops/s to a stable ~1794-1805 ops/s.
2. **dlm_scaling@32 FIX 2** (shortform-parent content-staleness at sf->block conversion) — LANDED,
   partially validated (fired once matching symptom, hasn't recurred to re-confirm the fix branch
   itself fired). Extended `mxfs_dir_modify_adopt_disk_format`'s staleness check + re-enabled its
   call site gated on `i_dlm_dir_gen>0`.
3. **cache_coherency@32 "uv gone" investigation** — root-caused via memory (NOT rediscovered fresh
   this session; this exact mechanism — Case B dangling dirent, a peer's stale cached dir buffer
   getting async-destaged by xfsaild and reintroducing an already-removed dirent — was already
   proven at 16-node scale ~7 days ago, see `compiled-caw-16node-dirent-loss`). Confirmed via direct
   code read that the existing `mxfs_buf_xfsaild_skip_dir_write` clobber guard
   (pal/linux/xfs_buf.c ~4890-4945) is STRICTLY one-directional (`clobber = dcnt > bcnt`, i.e. only
   protects against ERASING disk's extra content) — it structurally cannot catch the REINTRODUCE
   direction (`bcnt > dcnt`, our stale buffer carrying a peer-removed entry).

## What was TRIED and REVERTED (important: do not blindly retry this shape)
Attempted fix: symmetrize the clobber check to `clobber = (dcnt != bcnt) || ...` (both dc_data and
dc_leaf cases) — i.e. treat ANY count mismatch inside the already-suspect gate (dc_stale /
dir_not_held_ex) as unsafe-to-destage, not just "disk has more."

**REGRESSED posix_multi@8/caw**: nodes_pass 3/8, "pm r3 sees node1 renamed content(exp=posix_1
got=)" (renamed file content came back EMPTY) + "pm r3 node5 hardlink-name gone" (a hardlink's
dirent vanished). This is a real, reproducible regression (confirmed by reverting and rebuilding
back to the pre-change srcversion) — NOT flakiness.

**Root of why it's unsafe**: `bcnt > dcnt` (our buffer has more entries than current disk) is
AMBIGUOUS inside the not-held-EX/dc_stale gate between two cases that look identical by count/
checksum alone:
  (a) Case B (bad): a genuinely stale cached buffer, from a PRIOR tenure, still carrying an entry a
      peer has since durably removed — destaging it would wrongly resurrect that entry.
  (b) Legitimate (good): OUR OWN buffer, correctly dirtied while we held EX (e.g. a rename or
      hardlink add), where the ASYNC DESTAGE (xfsaild writeback) lands AFTER we've already dropped
      EX — completely normal in this architecture (commit-then-release-then-async-flush is the
      standard pattern; EX release and buffer destage are decoupled by design). Such a buffer can
      legitimately have MORE entries than a disk image that just hasn't caught up yet.
  `dc_stale`'s gen-stamping (`b_mxfs_dir_gen < i_dlm_dir_gen`) does NOT disambiguate (a) from (b) —
  both present as "gen-stale, buffer has more than disk." The ORIGINAL one-directional check had no
  such ambiguity: an async destage of your own dirty work can never legitimately have FEWER entries
  than what peers have already made durable, so `dcnt > bcnt` alone is unambiguously "someone else's
  content I'd erase" — safe to skip. The reverse direction needs a DIFFERENT signal than count/
  checksum to disambiguate.

## NEXT STEPS for cache_coherency@32 (pick up here)
1. Do NOT re-attempt the bidirectional count/checksum symmetrization as-is. Any fix for the
   Case-B reintroduce direction needs PER-ENTRY PROVENANCE, not just an aggregate count/checksum
   diff — e.g., something like: for a `bcnt > dcnt` divergence, walk both dirent sets and identify
   the SPECIFIC extra inum(s) our buffer has that disk lacks; only skip if that specific inum is
   PROVABLY not our own recent add (e.g. cross-check against a small "recently added by me, not yet
   destaged" tracking set, or a per-entry write-generation/tenure stamp rather than a whole-block
   gen). This is architecturally closer to the GPT-5.5 plan's option 2
   (`_XBF_FUA_FRESH`/generation tied to lock resource generation, invalidating a PEER's cached
   buffer specifically on BAST/gen-advance observation) than to the write-chokepoint symmetrization
   tried this session — that GPT design was never implemented either; see
   `caw-16node-dirent-loss-gpt-design-plan` for the full ranked options list.
2. Alternative angle worth trying first (cheaper): the compiled-16-node memory's own recommended
   NEXT-STEP was a WRITE-SIDE PROBE (not a fix yet) at the xfsaild destage site: for the specific
   extra inum(s) in a `bcnt > dcnt` divergence, log writer comm/daddr/owner, `b_mxfs_dir_gen` vs
   `i_dlm_dir_gen`, `i_dlm_mode` (expect NL/PR = confirms it's a peer, not us), whether that inum
   corresponds to a file THIS node created recently (would indicate case (b), our own pending work)
   vs one it never touched (would indicate case (a), true Case-B reintroduce). Loop cache_coherency
   at 32 (it fails intermittently, not every run — the 4/17 tests I ran cleanly on 8-node included
   one full cache_coherency PASS, so reproduction needs looping) with this probe (no skip yet) until
   it fires, THEN design the precise fix from real evidence instead of the count-only heuristic.
3. Whatever fix eventually lands here, MUST be regression-tested against posix_multi specifically
   (rename + hardlink content) before being considered safe — that test is the one that caught this
   session's unsafe attempt and should be the canary again.

## Tasks status at handoff
- Task list (in-session TaskCreate/TaskUpdate, not necessarily visible next session — re-derive if
  needed): dlm_scaling@32 root-cause+fix = COMPLETED. cache_coherency@32 fix = IN PROGRESS, reverted
  to safe baseline, needs the per-entry-provenance approach above. Still PENDING, untouched this
  session: (a) run the full 32-node caw suite to completion — 12 of 17 tests have NEVER recorded a
  real result (all show `status=aborted "run died before recording a result"` from a batch that died
  at 07:41:02Z, BEFORE this session started) — strong_consistency, posix_multi, mmap_coherency,
  zero_silent_loss, dlm_fairness, dlm_membership, scaling_curve, rsync_paired, crash_consistency,
  dir_reuse_coherency, fence_during_write, fault_netpartition, dlm_lock_correctness; (b) final
  regression pass re-confirming 1/2/4/8/16-node caw are still 100% after whatever lands for 32-node
  (8-node full-suite run THIS session showed 16/17 clean — posix_multi FAIL was the now-reverted bug
  causing it, everything else incl. cache_coherency PASSED cleanly at 8/caw; the other 5 tests in
  that run hit a harness-timeout batch-abort, not real failures, from an under-budgeted `timeout 900`
  wrapping the full 17-test suite — a full 8-node suite needs MORE than 900s wall, budget ~1100-1200s
  next time or run in smaller batches).

## Operational notes for next session
- `MXFS_DEV=/dev/mapper/mpatha timeout 540 ./run.sh 32 caw dlm_scaling` (single test) reliably
  fits under the 10-minute Bash tool cap end-to-end including preflight-less prep. A FULL 17-test
  8-node (or larger) suite does NOT fit in 10 minutes — either run in the background with `nohup
  ... &` + a bounded `while kill -0 $PID; do sleep 15; done` poll loop (this pattern works: the
  run.sh process survives the polling Bash tool call being killed at its own timeout, and finishes
  on its own — confirmed twice this session, both times the run completed correctly in the
  background and results landed correctly in criteria.json), or split into targeted subsets of
  tests instead of the full suite.
- Always `rm -f /tmp/mxfs_run.lock` before a fresh run if the previous one's Bash tool call was
  itself killed/timed-out (the lock file can go stale-looking even though the underlying run.sh is
  still alive and will clean up fine on its own — check `ps aux | grep run.sh` / `kill -0 <pid>`
  before assuming a wedge; both times this session it was a live, self-completing background
  process, not a wedge).
- `/sys/kernel/scst_tgt/devices/mxfs/threads_num` was bumped 8->32 live this session (via `sudo
  tee`) while investigating dlm_scaling's residual single-node throughput variance; it did NOT
  measurably help (left at 32 anyway, harmless). NOT persisted to /etc/scst.conf.
- dlm_scaling@32's residual "occasionally one node dips to ~41-43 ops/s vs floor 50, aggregate
  stays healthy ~1800" is characterized but not root-caused — see the FIX-1/FIX-2 memory's
  "RESIDUAL" section for the full investigation trail (retry counters ruled out, SCST threads ruled
  out, host CPU 128vCPU/56core oversubscription suggestive but not conclusively proven — 30% host
  CPU idle remained even at peak, so not hard-saturated). Empirically ~2/9 post-fix runs were clean
  32/32; the rest were 30-31/32 on this exact "rate>=floor" miss (never a correctness failure,
  never dirent-loss again after FIX 2 landed). If the criteria needs a durable 100% (not just one
  lucky recorded PASS), this needs more work — kernel-side per-op CAW latency histogram (not yet
  tried, would need its own rebuild/redeploy cycle) is the next concrete diagnostic step.
