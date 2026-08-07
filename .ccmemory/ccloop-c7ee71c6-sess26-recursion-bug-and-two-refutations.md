---
name: ccloop-c7ee71c6-sess26-recursion-bug-and-two-refutations
description: sess26: pending build had an INFINITELY RECURSIVE mxfs_is_demoter (kernel stack overflow, objdump-proven); D-BAST-IRELE verified with exposure; P32E…
metadata:
  type: project
tags: [demoter, wedge, silent-mkdir-loss, rule4, measurement-trap, journalctl, racebail]
---

# sess26 — one crash bug fixed, two documented leads refuted

## 1. THE PENDING BUILD WAS A GUARANTEED KERNEL CRASH

sess25 left "the two-slot revision built but not re-verified". It was
**infinitely self-recursive**:

    static inline bool
    mxfs_is_demoter(const struct xfs_inode *ip)
    {
            return mxfs_is_demoter(ip) || ip->i_dlm_demoter2 == current;
    }

Not a theory — read off the shipped object:

    00000000000cb580 <mxfs_is_demoter>:
       cb580: push %rbp
       cb588: call cb580 <mxfs_is_demoter>     <-- calls ITSELF, no base case

Called from 16 hot-path sites, so every invocation = kernel stack overflow.
The `.ko` on disk (v0.11.215) was undeployable. **Lesson: "it compiled" is not
"it links to something sane" — for a self-referential inline, check the
disassembly.**

Fixed to `demoter == current || demoter2 == current`.

## 2. INCOMPLETE REFACTOR: 6 sites still asked the ONE-slot question

`ip->i_dlm_demoter && !mxfs_is_demoter(ip)` means "a foreign drain is live"
only when there is ONE slot. With two slots it reads FALSE whenever slot 1 was
released while slot 2 still drains — a reachable, ordinary state. Added
`mxfs_foreign_demoter()` (checks both slots) and converted all 6:
P34J demote-wait (x3), the race bail + its print, the dir-EX divert.

## 3. D-BAST-IRELE-INACTIVE-SELF-WEDGE — verified WITH measured exposure

New instrument `tests/demoter_claim_census.sh` + `mxfs.demoter_dump` →
`P75-DEMOTER-CLAIM`. Per 32-node run of dirent_durability+node_responsive:

| arm | slot2 (2nd drain admitted) | contest | foreign_clear | legacy_steal |
|---|---|---|---|---|
| fixed (default) | **30-37 on 21-23 nodes** | **0** | **0** | 0 |
| `demoter_legacy_clobber=1` | n/a | n/a | n/a | **30 steals, 19 live clears** |

So the theft genuinely happens pre-fix and is impossible post-fix, ON ONE
BUILD. crash_consistency **PASS 61s/90s** (the sess25 single-slot fix
regressed it to FAIL@90s; baseline 74s) — the regression is gone.
dirent_durability + node_responsive PASS 32/32, dstate=0.

`foreign_clear` needed splitting: the DLM-state initializer calls
MXFS_CLEAR_DEMOTER as a plain field reset ~62x/node/run, always with BOTH slot
pids 0. Folded together it was a permanently-nonzero "MUST be 0" counter, i.e.
a standing false alarm. Now `clear_noclaim` is separate.

## 4. THE WEDGE NEEDS THREE CONDITIONS, not one — measured

Theft alone does NOT wedge: 30 steals + 19 live clears → `wedge_precond=0`.
New TEST-ONLY `mxfs.bast_irele_unclaim_inject` forces bast_work_fn to drop its
own claim before the trailing irele (exactly what a steal leaves). Armed on 4
of 32 nodes, it fired **646+ times and still never wedged**. The probe prints
i_count and state, which explains why:

    test5:  count=2 state=0 x107   count=3 state=0 x51   count=1 state=0 x30
            count=2 state=1 x3     count=2 state=2 x2

**Every i_count==1 injection had state=0 (NONE).** The demote-wait only parks
in DEMOTING/ACQUIRING/BAST. So the wedge needs: (a) no claim, (b) i_count==1 so
the irele cascades to inactivation, (c) state != NONE at that instant. The
captured wedge had state=3 because a SECOND drain re-armed DEMOTING. In this
workload (b) and (c) never coincide — which is why the wedge is rare, and why
absence of a wedge proves nothing without the census.

## 5. MEASUREMENT DEFECT ACROSS THE WHOLE CAMPAIGN: dmesg is too short

On test19: `dmesg` = 1824 lines / **112 seconds** retained. `journalctl -k` =
**59067 lines / ~50 minutes**, and it still held the `MXFS_DIRENT_WINDOW`
markers that had already scrolled out of dmesg. The dirent_durability run
being measured is 116-120s — **longer than the dmesg window**.

Every `dmesg | grep -c` census in this campaign was reading a truncated
window. state.md's ring-dependence finding is this, and only half-fixed.
**Harvest kernel probes with `journalctl -k`.** prep already sets journald
RuntimeMaxUse=400M, so the retention is there for free.

## 6. REFUTED: P32E is NOT the discriminator for D-SILENT-MKDIR-LOSS

state.md: "P32E is the only marker that is zero on every passing run ... the
sharpest signal available", and the designated next-session target was "catch a
run with P32E > 0".

Caught a LOSING run — test19, `durable_loss=8 late_ok=4 mkdir_err=0` — and
scoped the census to the last MXFS_DIRENT_WINDOW via journalctl:

    P32E-DIREPOCH-FENCE               0     <-- the "sharpest signal"
    P195-STALE-BASE-ALREADY-DIRTY     0
    P34J-RELOAD-DEMOTE-BAIL           0
    P177 / P188 / P146V / P51 / P65 / P194   all 0
    P34J-RELOAD-RACE-BAIL            14     <-- only live marker
    P198-RELOAD-DEMOTE-WAITED        13
    P6-MIDTENURE                    693

All 11 probes verified present in the built module (`strings mxfs.ko`) first,
so the zeros are real, not missing probes. **P32E is neither necessary nor
sufficient — same verdict sess23 reached for P195. Do not use it as the
acceptance signal or as an A/B arm.**

Every P34J line had `epoch == entry_epoch`, so the bail fires EXCLUSIVELY on
the foreign-drain arm, never on an epoch change.

## 7. REFUTED: sess23's H2 (state.md's "THE NEW LEAD")

H2 = "the race bail abandons the reload and nothing ever retries, same as the
demote flavour sess22 fixed". Instrumented directly: stamp the inode at the
bail, clear it at the next COMPLETED reload (`P79-RACEBAIL`).

    racebail_total=533  resolved=533  unresolved=0     (cluster-wide, 32 nodes)

**Every one of 533 bails was followed by a completed reload.** The promise
"caller retries post-drain" IS honored for the race flavour. H2 as stated is
dead.

Retry LATENCY, though, is not small: per node `max_ms=938..1345
mean_ms=124..195`. So there is a window up to ~1.3 s where the inode carries
`i_dlm_stale=true` and a knowingly-stale in-core image.

**Refined H2' for the next session** (sess23's experiment 2, still open): does
anything READ or PUBLISH from the image during that stale window without
honoring `i_dlm_stale`? That is now the question, not "does it retry".

## Tree

v0.11.222, srcver `608D708E50455FB77258BCE`. New: `mxfs.demoter_dump`,
`mxfs.bast_irele_unclaim_inject` (TEST-ONLY), P75/P76/P77/P78/P79 probes,
`tests/demoter_claim_census.sh`. Rig healthy, prep converges in ~67s.
