<!-- sess481: crash_consistency board FAIL root-caused to write-phase budget exhaustion; CAW unlock + create-cost accounted; pace ceiling ruled; 2 instrum… -->
# sess481: crash_consistency ceiling campaign

One session, one defect (`D-32NODE-SHARED-DIR-CREATE-PACE` / board row
`crash_consistency`), worked start to finish from evidence already on disk (no
rig time spent measuring — only the chain-128 build+verify lap at the end).
Two derivation bugs were caught and fixed mid-session; both left permanent
method fixes in tooling.

## 1. What the board FAIL actually was

sess480 had read `steps[]` and concluded 3 stragglers (test23/test27/test30)
were stuck at `cc_ready` while 29 nodes waited. `mxfs-CCph` kmsg phase
markers refute this directly: **all 32/32 nodes reach `PHASE=dropcaches-done`**,
both barriers clear cleanly and near-instantly, and the **write phase alone
consumes 85-88 s of the 90 s budget** — the cross-node cold verify (the actual
durability assertion) never runs on any node. `checks=1 passed=1 failed=0`
meant no check was reached, not nothing failed. Per-node timeline and the two
independent leads (EXWIN quantum reads 1 ms against a per-create cost of
hundreds of ms; `MXFS_WATCH_ARM=1` puts 11,431 kernel lines/90s on the hot
directory, untested for cost) are in
`docs/history/docs/history/docs/history/compiled-sess481-crash-consistency-ceiling-campaign.md`.
Reporting-semantics fix landed this session: `tests/suite/lib.sh` `suite_plan`
+ `planned=`/`notrun=` so a run that never reaches its declared assertions can
no longer print PASS; `crash_consistency.sh` now declares 204 and the failing
row reads `notrun=203`.

## 2. Two ways this session manufactured a confident wrong root cause

Both on the same defect, both from real data, both caught before landing in
the ledger — method captured in
[[trap-check-cumulative-vs-last-value-before-dividing-probe-fields]]:

- **Naming a subtracted residue after the mechanism you suspect.**
  `P381-UNLK-CONTEND` wall minus sleep, divided by attempts, gave 9.42 ms;
  called "slot I/O service time" and filed as root cause. Wrong — the residue
  contains everything unaccounted in the loop, including two entirely
  uninstrumented mechanisms (`find_slot` hash-chain walk, `caw_inode_backoff`
  sleep). Rule: name a residue "unaccounted", never after a suspected
  mechanism; go find a direct probe for that mechanism, and if none exists
  that absence is the finding.
- **Dividing a cumulative field by a last-value field.** `read_ms` is a plain
  assignment per poll (`dlm/dlm_caw.c:6908`, last-value); `reads` is
  cumulative. Dividing produced "0.22 ms/read" and, separately, "~242 ms per
  acquire wait unaccounted" (comparing a cumulative `el_ms` against last-value
  `slept_ms`/`read_ms`) — both retracted. Correct reading of the same probes:
  slot read 0.77 ms mean, CAW op 1.54 ms mean; the acquire side is UNKNOWN,
  not anomalous. Check before dividing: is each field `+=` or `=`? does the
  denominator count the same episodes as the numerator? does a direct probe
  for the suspected mechanism already exist and just go unprinted?
  `tools/caw_unlock_audit.py` now encodes all three checks and prints
  `UNACCOUNTED` in capitals rather than a false mechanism name.

A third, structurally separate trap from the same session:
[[trap-a-probe-exists-is-not-a-probe-that-covers-your-path-check-its-gate]] —
`P132-CREATE` had decomposed create cost since sess132, but its clock started
only under `if (mp->m_mxfs_dlm && is_dir)`. Every workload that sets this
filesystem's create ceiling creates **files**, not directories, so the one
probe able to attribute create cost had never fired on the path that mattered
for ~350 sessions. "The probe exists" is not "the probe covers your path" —
check the gate on the clock (not just the gate on the print), the print
threshold, and any per-boot print cap before trusting a coverage claim. Fixed
in 0.65.0: clock now starts for file creates too, with `pre_ms` split into
mutually-exclusive `res_ms`/`dlk_ms`/`dia_ms` stamped at call boundaries, plus
`dir=`/`ag=`/`comm=`. `tools/p132_attribute.py` refuses to report when no
input carried the probe rather than printing zeros.

## 3. Probe census, run separately over the same evidence

`docs/history/docs/history/docs/history/compiled-sess481-crash-consistency-ceiling-campaign.md`
generalizes the same discipline into a technique: census every `mxfs: P*` tag
across a full row (2,902,825 lines / 32 nodes / 276 tags here), rank by
frequency, filter for failure-shaped names, then **read the source at each
probe before believing its label**. Found:
- `P165-AFFINE-STALE` 100% vacuous — 229,444 hits, all `d_time=0`, because the
  dentry's affine fast path returns before the one place that stamps
  `d_time`, so the probe's own discriminating rule is structurally never
  satisfiable for the population it samples. Filed
  `D-AFFINE-FASTPATH-STALE-DENTRY-VECTOR-UNTESTED` (high) — the vector it
  names (stale positive dentry from a dead parent incarnation, truncating a
  live occupant) is real and had been completely unmeasured while looking
  observed. Two OPEN ledger records that inferred from mere *presence* of
  P165 were annotated as contaminated; a third that uses P165 volume as an
  activity proxy survives.
- `P13-SFPARENT-DURABLE-FAIL` / `P68-DIRINODE-DURABLE-FAIL`: a durability
  barrier can fail and release anyway, and whether that matters depends on
  which retry-budget arm it failed in (`icd_releasing ? 1500 : 25` tries) —
  both arms print identical text with no state field, so the failure's
  severity is currently unknowable from the log. Filed
  `D-DIR-INODE-DURABLE-BARRIER-FAILS-ARM-UNCLASSIFIED` (major); 0.65.0 adds
  `state=`/`releasing=` behind a shared predicate so the two arms can't drift.
- Refuted: printk volume was not suspected of throttling the filesystem
  (guest UART never receives ring-buffer traffic; negligible either way).

## 4. CAW wire-unlock accounting, the number that actually holds

`docs/history/docs/history/docs/history/compiled-sess481-crash-consistency-ceiling-campaign.md`:
contended CAW unlock is 21.4% of node-time in the crash_consistency row
(17,558 unlocks, 616.5 s / 2880 node-s). The residue is super-linear in
retries (5.41 → 19.84 ms across retries 1-6), and the convexity is
**mostly selection, not an escalating code path** — retry count tracks local
contention almost 1:1. Quote the least-contended bucket: retries=1 (n=10181)
→ **5.41 ms/attempt unaccounted**, against a measured slot round trip of
0.77-1.54 ms. Filed `D-CAW-WIRE-UNLOCK-100MS-CONTENDED-INODE-SLOT` (major).
Fix direction that does NOT work: per-field versioning against `multigen` —
`MXFS_CAW_SLOT_SIZE=512` is `_Static_assert`-pinned to one sector, the
granularity of SCSI COMPARE-AND-WRITE, so the compare covers every peer's
waiter bit regardless of struct layout; the real fix is splitting a slot
across sectors, an on-disk format change to a structure pinned at 65536
slots. If `find_ms`/backoff census both come back null on the next
measurement, instrument inside the CAS attempt itself
(`caw_cas_slot`/lreq/publication), not a fourth guess at the same three
suspects. Landed 0.65.0: `find_ms=`/`backoff_ms=` on `P381-UNLK-CONTEND`,
`read_sum_ms=`/`sleep_sum_ms=` on `P297-TKT`, `tools/caw_unlock_audit.py`,
`tools/caw_slot_census.py`.

## 5. The pace ceiling ruling

End-of-session state and full landing list:
`docs/rulings/end-create-cost-instrumentation-and-ceiling-ruling.md`.
GPT RULE-5 ruling, checked against the full measurement package:
`docs/rulings/pace-ceiling.md`.

Ceiling arithmetic: `S_max = 1/(1-f_H)`. Closing the row (target 106.7
creates/s from current 37.6) needs 2.84x, requiring `f_H ≥ 64.8%`. Measured
`P138-BAST` handoff fraction on the shared dir: **f_H ≈ 5-16%**, ceiling
1.05-1.19x. **Handoff-only tuning — including the already-queued fastpoll
A/B — cannot close this row**, even working perfectly; keep fastpoll queued
but reframe it as a LUN/poll-congestion experiment (31 waiters polling one
slot can inflate the WORK term, not just the handoff term), not a fix
candidate.

The binding term is the per-create cost that survives removing the shared
directory entirely: **4.6 ms/create at 1 node → 27.8 ms/create at 32**, with
nothing shared but the mount. Ranked priority: (1) diagnose that mount-wide
32-node degradation — highest-priority shipping issue, caps any sharding fix
too; (2) make directory sharding transparent/automatic (legitimate
architecture — but sharding only buys concurrency if shards can update the
physical XFS directory structure concurrently, not just take separate name
locks under one B-tree-root transaction lock); (3) CAW unlock latency, filed
separately (§4); (4) fix reporting semantics (done, §1). Seven ranked
candidate mechanisms for the private-arm 6x regression, each with its
cheapest instrumented test, and five legitimate ways to make the directory
term fundamentally cheaper (hash-partitioned name locks singled out as most
practical, with the caveat that the physical B-tree update path must also
become concurrent) are enumerated in the ruling; not restated here to avoid
drift between the two copies — read
`docs/rulings/pace-ceiling.md` directly before choosing
the next fleet run.

**One correction NOT to make**: GPT flagged "32 nodes over 25 AGs ⇒ 14 nodes
share an AG" as not strictly derivable (minimum in non-singleton AGs is 8).
Correct as arithmetic, but `D-RSYNC-LAP-PACE-AG-SHARING-388`'s "14" is
**measured**, not derived (18 exclusive-AG nodes at 22-27s, 14 shared-AG
nodes at 34-50s, set equality exact) — do not weaken that record. The caveat
applies only to predicting the mapping on a future run; chain 128's `ag=`
field measures it directly going forward.

## State at relay

Tree is 0.65.0 source, **compile-verified but UNBUILT** — deployed module
still 0.64.37. `tests/sess481_chain128_create_cost.sh` (gated on prior chain
DONE) builds 0.65.0, verifies `dlk_ms=` actually linked into the `.ko`,
freezes it, and runs crash_consistency in both shared and private arms with
the new probe armed on all 32 nodes. Reading it: `dlk_ms` should collapse
between arms; whatever remains in the private arm's `total_ms` is the
ceiling term — `res_ms` implicates shared-log serialization, `dia_ms`
implicates AG contention, a large `other_ms` means the decomposition needs
another boundary.
