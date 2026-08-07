---
name: ccloop-c7ee71c6-sess41-gpt-openunlink-audit-ruling
description: sess41 GPT audit of open-tracking: 2 NEW holes (open-at-NL via dcache; lazy-CLEAR staleness) + G1-G6 confirmed; fix list C1-C10 with priorities
metadata:
  type: project
---

# sess41 (ccloop session 23) — GPT audit ruling on the shipped open-tracking design

Full GPT text in session transcript (task km63t74uz). This is the actionable distillation.

## Verdict
BAST-publish (set at grant-release when protected) is sound ONLY if publication is an
inseparable precondition of release AND local open initiation is serialized against release.
Shipped code violates both. "Best-effort SET" and "recovery-free-without-EX" invalidate safety.

## NEW holes GPT found (beyond my G1-G6 audit)
- **OPEN-AT-NL (data loss, default config):** open() can complete from dcache with the inode
  at NL (grant idle-released earlier). No grant → peer's EX gets no BAST from us → no publish →
  B6 sees nothing → free under our live fd. "Open implies grant history" is NOT "open implies
  current grant or bit". FIX C3: xfs_file_open must ensure grant-or-protection before
  returning — acquire PR when i_dlm_mode==NL (serializes vs freer's EX: either we get PR and
  later BAST-publish covers, or the acquire surfaces the free → open fails ESTALE, which is
  correct POSIX since unlink+free completed first). Naked-bit-set at open has an ABA (bit can
  land after B's B6 read but before unlock_free zeroes → protection silently destroyed);
  grant-acquisition avoids it.
- **LAZY-CLEAR STALENESS (liveness):** bit published under BAST stays until evict (hours);
  later peer unlink defers reclaim unboundedly, reap retries forever against a stale bit.
  FIX C4: eager clear at protected-activity 1→0 (last close, !mapped), serialized vs
  concurrent reopen (i_dlm_lock / open-transition serialization on i_mxfs_open_pub).

## Fix list (C-numbers, this tree)
- C1 (G4): publish MANDATORY — fold set-bit into the RELEASE CAS itself (one CAS: remove
  holder bits + set open bit). On CAS failure: retain grant, never release-and-continue.
- C2 (G5): during log recovery, failed EX acquire ⇒ SKIP destructive free (keep zombie).
  Recovery does not justify bypassing mutual exclusion.
- C3: open-at-NL fix (above).
- C4: eager clear at last close (above).
- C5: B6 fail-closed — open_holders query must distinguish error from empty; error ⇒ defer.
- C6: mask open_holders with LIVE MEMBERSHIP at B6/reap (kills full-outage residue bits;
  fence-strip becomes optimization). Opener must be a member (join precedes mount).
- C7 (G3): version enforcement = on-disk INCOMPAT feature bit old code must reject + join
  handshake feature word. Advertising alone is insufficient.
- C8 (G2): survivor sweep of dead slot S bucket after fence+replay, with DURABLE/reconstructible
  "sweep pending per (slot,epoch)" state + bounded periodic retry; one survivor owns a sweep;
  mount-time scoped recovery stays as fallback.
- C9 (G1): TCP open tracking — set-BEFORE-usable at the resource master (no slot exhaustion
  on TCP so the stronger invariant is free); SET/CLEAR/QUERY serialized by master; EX grant
  reply can carry bitmap; fence strips (node,epoch) entries; master death = freeze grants →
  fence-or-hear-from every survivor → rebuild holders+open marks from survivors' local
  protected-resource tables → resume. No grants during reconstruction.
- C10 (G6): ICLUSTER (icluster_dlm=1, default 0) has ZERO protection (open_set no-ops —
  no per-inode slot under cluster routing; verified). Gate: refuse multi-node mount with
  icluster until per-covered-inode publish exists. GPT: gating is the lower-risk choice.

## Also required
- B6 must cover ALL destructive-free entries: unlink, rmdir, rename-over-target, O_TMPFILE
  orphans, create-failure cleanup, recovery orphan cleanup, scrub/repair. rename-over-open-
  target belongs in the core test matrix.
- Peer truncate/fallocate/punch of an open file are LEGAL coherent mutations — bits must not
  block them (B6 only gates nlink==0 inactivation — OK by construction, but test).
- Fence-strip only after CONFIRMED fencing (not mere disconnect); slot reuse ordered after
  strip+replay+epoch advance.
- 9-group verification matrix recorded in full in GPT reply: basic; multi-opener; open/reopen
  races w/ fault injection around publish; mmap-only (+exec/private/shared); writeback/AIO/DIO
  after close; opener death+fence (partition-without-fence must NOT clear); unlinker death at
  4 crash points; O_TMPFILE+linkat resurrection + rename-over; free/reuse/gen hygiene (stale
  CLEAR must not clear new incarnation's SET). Plus TCP master-failover cases; CAS-exhaustion
  (must retain grant); recovery-EX-failure injection; mixed-version admission set.

## Priority (GPT): G3 → G4 → G5 → gate G1/G6 now → implement G1 → G6 → G2.
My C3 (open-at-NL) sits WITH G4/G5 (default-config data loss).
