---
name: technique-discriminate-two-arms-of-one-guard-by-the-probes-via-field-not-by-whether-the-probe-fired
description: TECHNIQUE (s116): a hang-vs-no-hang pair was settled from captures already on disk by counting one probe's `via=` field — the guard was armed in both…
metadata:
  type: feedback
tags: [measurement, evidence, dlm, recovery]
---

# Discriminate two arms of one guard by the probe's `via=` field, not by whether the probe fired

## The situation

Two injected arms of `tests/tcp_death_replay.sh` reached the *identical* terminal
recovery verdict. One arm's survivor could not unmount (SIGKILLed at 70 s); the
other's unmounted in 2 s. The defect record concluded that the hang "needs the
page the SB summary lock lands on to be one the dead victim authored" but
recorded the discriminator as **not established**, and its next step asked for
six fresh rig laps (three per arm) to settle it.

## What actually settled it — with no new laps

`P-TAUTH-TAKEOVER-UNDER-JUDGEMENT` carries a `via=` field naming which takeover
path was refused. Counting by that field across the captures already in
`tests/evidence/`:

| arm | distinct pages refused | via=takeover | via=takeover-ondemand | umount |
|---|---|---|---|---|
| straddle (no hang) | 260 | 780 | **0** | rc=0 at 2 s |
| agino lap 1 | 250 | 750 | 840 (843 on ONE page) | rc=137 at 70 s |
| agino lap 2 | 237 | 711 | 661 (664 on ONE page) | rc=137 at 70 s |
| plain control | 0 | 0 | 0 | rc=0 at 2 s |

The guard was armed **identically** in both injected arms — ~250 victim-authored
pages refused by the bulk sweep in each. The refusal *path* was not the
discriminator at all. The only difference is `via=takeover-ondemand`: in the
hanging arms one parked request kept asking for one page every ~100 ms; in the
non-hanging arm nothing ever asked for a protected page.

## The lesson

**"The probe fired in the failing arm" is not a discriminator until you have
checked whether it also fired in the passing arm.** A guard can be fully armed
in an arm that passes; what distinguishes the arms is often *who asked*, not
whether the guard said no. When a probe carries a field naming its caller
(`via=`, `comm=`, `site=`, `how=`), count by that field and by DISTINCT subject
(page/inode/slot) as well as by total lines — the shape
`780 = 260 pages x 3 passes` versus `843 lines on 1 page` is the whole finding,
and a bare `grep -c` collapses both to "about a thousand".

## Also: a record's own prose can carry a claim its evidence refutes

The same record asserted that `P218-RECOV-OWNED` "is logged on the agino laps"
and offered it as the candidate discriminator. It appears **zero** times in
either agino lap and **twice** in the plain control — it marks a replay that ran
to completion. Re-derive a record's stated discriminator from the captures
before spending laps on it; the cheapest experiment is often the one already
run.
