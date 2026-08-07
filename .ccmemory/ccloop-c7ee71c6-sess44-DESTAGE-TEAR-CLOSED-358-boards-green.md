---
name: ccloop-c7ee71c6-sess44-DESTAGE-TEAR-CLOSED-358-boards-green
description: sess44: D-DESTAGE-TEAR FIXED AND VERIFIED on 0.11.358 (4 race arms PASS, GPT gaps discharged); 32+8 boards 27/27; 12 OPEN of 34
metadata:
  type: project
tags: [ccloop, destage-tear, guard, race-arms, boards]
---

# sess44 — D-DESTAGE-TEAR-BUCKETLESS-ORPHAN CLOSED on 0.11.358

## What closed it (all on the final build, srcver 4148EC203AC92D0FB40D703)
GPT gap-review (RULE 5) demanded: boards on final build, stale-holder fencing,
deferred-open liveness, ABA review, live-no-progress answer, crash-of-repair
treatment. All discharged:

- **tests/guard_race_arms.sh** — four arms, all PASS live at 32 nodes:
  - `joiner` (2/2 on 357): B rebooted INSIDE a 180s guard hold
    (mxfs.ubsweep_hold_ms debug knob, 0.11.356) — claim SKIPPED the guarded
    slot attempt 0, 0 races, holder sweep rc=0. In-hold certified by
    hold/done count deltas (dmesg persists → every detection is count-growth,
    never line-exists; ino numbers are REUSED → baseline reap counts too).
  - `abandoned` (357): holder virsh-destroyed mid-hold; test6 judged the
    corpse guard abandoned by CHANGE-DETECTION 105s later (62s lease + batch
    + 3s probe), reclaimed, swept rc=0, freed the zombie end-to-end.
  - `stale_resume` (358): holder held 15s then STALLED 240s (no refresh;
    mxfs.ubsweep_stall_ms, 0.11.358); rejoining B's settle scan reclaimed the
    frozen guard; the RESUMED holder's refresh CAS failed → P99-GUARD-LOST →
    rc=-116 → **zero sweeps after takeover** (P97-SWEEP-AG count unchanged).
  - `inherit` (358): dense rig (full prep first — REQUIRED), B died with
    bucket-insert-landed shape, rejoined onto the SAME slot inheriting the
    nonempty bucket; ordinary last close freed in 10s with ZERO recovery
    events (P163 counters frozen) — the last-close liveness gap GPT called.
- **Code-level fencing facts** (cite, don't re-derive): guard refresh+unguard
  are full-512B owner-image CAS (any change → refresh -ESTALE P99-GUARD-LOST;
  unguard logs UNGUARD-RACED and leaves a successor's guard alone); refresh
  timestamps forced monotonic (+1 floor); guard_slot is in-memory only (a
  rebooted holder cannot resume); refresh runs IN the sweep thread between
  AGs (no independent timer → wedged sweeper's guard freezes → takeover);
  sweep is READ-AND-ENQUEUE only — all frees revalidate on fresh iget under
  EX+AG-DLM via the P19 B1-B5 gates, so double-drive is safe by construction.
- **Boards**: 32/caw 27/27 PASS + 8/caw 27/27 PASS on 358; policy row red.
- Torn tally at close: 352 4/4, 354 3/3, 355 1, 357 3 — all converged, zero
  leaks ever. Crash-of-the-repair = recurrent fixpoint argument (documented
  in ledger); per-buffer atomicity in general stays D-FOREIGN-REPLAY (OPEN).

## New defects filed (RULE 6) — ledger now 12 OPEN of 34
- **D-MASS-TEARDOWN-DEPARTURE-WAVE-WEDGE (major)**: during 32-node mass
  teardown, tail nodes saw cleanly-departed peers as 62s-FROZEN slots →
  fencing wave → 4 umounts wedged → harness power-cycled them (prep still
  converged). Evidence: scratchpad prep358.log + test13 journalctl -b -1
  07:16:41Z. Next: instrument HB-zero write rc + watcher raw reads (stale
  read vs ordering). NOTE: prep aborts can leave HALF-TORN clusters that
  seed this; an aborted prep earlier (test24 mid-reboot) preceded the wave.
- **D-RELOAD-FREED-ADOPT-BOGUS-IMODE (minor)**: fix shipped 357 (skip iops
  rewire when reload adopts mode-0 freed image). VERIFICATION PENDING: need
  one observed P116-ZOMBIE-ADOPT on ≥357 with zero 'bogus i_mode' lines —
  check opportunistically after death tests (producer: peer frees while
  FDH's reap-adopted shell is in-core; nondeterministic, test1 lost the race
  twice).

## Rig/tree state at write
Tree=0.11.358, rig marker=8/caw on 358 (boards left it at 8) — RE-PREP TO
32/caw BEFORE running anything 32-node. Host load 12-44 swings; hostload= is
recorded per result. guard_race_arms.sh cleans up (knob 0, victims rejoined)
even on FAIL, but an ABORTED arm leaves ubsweep knobs set on survivors —
`set_knob 0` shape: echo 0 > /sys/module/mxfs/parameters/ubsweep_{hold,stall}_ms.

## Remaining 12 OPEN (by severity)
critical: D-FOREIGN-REPLAY-UNGATED-IMAGES, D-INODE-CLUSTER-PUBLISH-WITHOUT-
AUTHORITY, D-CROSSNODE-OPEN-UNLINK-DATA-LOSS, D-CACHE-COHERENCY-UV-COUNT-
MISS-2332; high: D-DIRVIEW-NONCONVERGE-SESS25; major: D-32NODE-SHARED-DIR-
CREATE-PACE, D-READDIR-PEER-CACHED-DIR-PACE, D-CRASH-CONSISTENCY-32-
NOTERMINAL-354, D-MASS-TEARDOWN-DEPARTURE-WAVE-WEDGE; minor: D-MATRIX-
UNMEASURED, D-RELOAD-FREED-ADOPT-BOGUS-IMODE; unknown-sev: D-AGI-UNLINKED-
CROSSNODE-RECOVERY-SHUTDOWN.
