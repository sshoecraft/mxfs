# Ledger split — `OPEN_DEFECTS.json` → index + per-defect narratives

**Status:** proposed, not implemented.
**Scope:** this is a CORRECTNESS fix for the RULE 6 gate. It is *not* a
token-burn fix — see "What this does not buy" below.

---

## The problem

Measured 2026-08-07 on `tests/criteria/OPEN_DEFECTS.json`:

| | |
|---|---|
| records | 70 |
| size | 558,822 bytes (~139k tokens) |
| avg per defect | 7,983 bytes |
| distinct keys across records | 174 |
| keys used **exactly once** | 139 |

Those 139 single-use keys are session-tagged narrative fields —
`ATTEMPTED_AND_REFUTED_sess25`, `CAUSAL_LINK_sess25`, `NARROWING_sess25`,
`ROOT_CAUSE_sess27`, `sess28_AGING_IS_LOAD_BEARING_AT_2_NODES`. The file
stopped being structured data and became an append-only narrative that
happens to be valid JSON.

It is larger than the entire ccloop context cutoff (145k). It cannot be
read whole at any cutoff, so every consumer parses it and extracts.

### The enums are not enums

`status`, as it exists today:

```
29  FIXED AND VERIFIED
28  OPEN
 5  RESOLVED
 5  DISPROVED
 2  FIXED-VERIFIED
 1  FIXED-AND-VERIFIED
```

Three spellings of one closed state. `severity` is worse — alongside
`critical`/`major`/`high`/`minor`/`medium` (five tiers where the ledger
means three) and two `None`, **four records carry a whole prose sentence
as their severity value**:

- `correctness-visible (statfs lies to userspace); allocation impact unproven`
- `resource leak (on-disk slots) + first-reaccess latency; demand-driven`
- `resource growth: pinned in-memory inodes + held wire slots`
- `on-disk CAW slot leak per created-then-evicted file (~gen=1 per file)`

`defects.sh` sorts the queue by severity. It cannot order those.

### Five implementations of "is this defect closed?"

The closure rule is duplicated, by hand, across five sites in three
different languages:

| site | mechanism | rule |
|---|---|---|
| `defects.sh:53` | python | `norm(status) not in CLOSED` |
| `tests/suite/open_defects.sh:52` | python | `norm(status) not in CLOSED` |
| `tests/suite/open_defects.sh:64` | grep fallback | `grep -cviE 'RESOLVED\|DISPROVED\|FIXED[ _-]?AND[ _-]?VERIFIED\|...'` |
| `.ccloop/state.sh:91` | python | `norm(status) not in CLOSED` |
| `showstat.sh:161` | **jq** | `select((.status // "OPEN") == "OPEN")` |

`defects.sh`'s own header acknowledges the hazard: *"Three other consumers
read the same file; all four MUST agree on what counts as closed, so the
closure set below is a verbatim copy of theirs."* A verbatim copy
maintained by hand across five sites is a divergence waiting to happen.

**It has already happened once.** sess43, quoted in
`tests/suite/open_defects.sh:43`: the gate used to test
`status != "RESOLVED"`, so every entry legitimately closed as
FIXED AND VERIFIED or DISPROVED still counted as open. The board reported
**26 unresolved when 11 were open.**

**And a second divergence is live right now.** The first four sites test
*exclusion* (anything not in the closure set is open — correct under
RULE 6). `showstat.sh` tests *inclusion*: only a literal `"OPEN"` counts.
They agree today only because every non-OPEN status happens to fall in the
closure set. The first entry written as `IN PROGRESS`, `INVESTIGATING`,
`REOPENED`, or with a typo diverges them: the gate blocks on it, and
showstat's live count silently omits it.

Under RULE 6 that is the dangerous direction. Over-counting blocks a
legitimate exit and is loud; under-counting hides an open defect and is
silent.

---

## The split

**1. Index — `tests/criteria/OPEN_DEFECTS.json`**

One flat record per defect. No narrative. ~120 bytes each, ~8KB total.

```json
{
  "schema": 2,
  "defects": [
    {
      "id": "D-CROSSNODE-OPEN-UNLINK-DATA-LOSS",
      "status": "OPEN",
      "severity": "critical",
      "opened": "2026-08-01",
      "opened_sess": 40,
      "summary": "one line, <=120 chars",
      "next_step": "one line",
      "narrative": "defects/D-CROSSNODE-OPEN-UNLINK-DATA-LOSS.md"
    }
  ]
}
```

`status` ∈ `OPEN | FIXED_AND_VERIFIED | DISPROVED` — exactly the two RULE 6
closure dispositions plus OPEN. `RESOLVED` is historical and migrates to
`FIXED_AND_VERIFIED`.

`severity` ∈ `critical | major | minor`. The prose currently sitting in
that field moves to `summary`, which is where it was always trying to go.

**2. Narratives — `tests/criteria/defects/<ID>.md`**

Everything else: evidence, refuted hypotheses, session-tagged findings,
RULE 4 loop history. One file per defect, markdown, loaded on demand by
`./defects.sh <ID>` or read directly when working that defect.

**3. One closure implementation**

`tools/ledger.py` becomes the only thing that knows the schema. The five
sites above call it. The grep fallback in `open_defects.sh` is deleted —
with an enforced enum there is nothing left for it to get subtly wrong,
and a coarser second implementation of a load-bearing gate is exactly the
failure mode this document exists to remove.

**4. A validator**

`tools/ledger_check.py`, wired into the board: fails on an unknown status,
an unknown severity, a missing narrative file, a duplicate id, or a
summary over its length cap. Schema violations become loud at write time
instead of silent at count time.

---

## Migration

1. Write `tools/ledger_split.py` — `--dry-run` by default. It reads the
   current file, emits the index plus 70 narrative files, and reports every
   field it could not place.
2. Run dry, review the unplaceable-field report by hand. **RULE 6: no
   entry's disposition may change during migration.** The record count and
   the open-set membership before and after must be identical, and the
   script asserts it.
3. Keep `OPEN_DEFECTS.json.backup` (per CLAUDE.md: back up in place, no
   `_old` suffixes).
4. Convert the five call sites to `tools/ledger.py`.
5. Verify: `./defects.sh -t` tally identical pre/post; `open_defects.sh`
   reports the same `n_open`; `showstat.sh` live count now agrees with the
   gate instead of coinciding with it.

---

## What this does not buy

**Token savings — essentially none.** The old audit (2026-08-03) sold this
as "cuts hundreds of KB off every session's re-read." That was true at the
500k cutoff. It is not true now: sessions reach the ledger through
`defects.sh` (20 of 22 references measured across 22 sessions), and the
ledger's contribution to session context is the ~2k-token
`## Current project state` block that `.ccloop/state.sh` renders — not
139k. Splitting the file does not shrink that block.

Do this for the gate's correctness. Do not expect it to move the burn
numbers.

## Related

- RULE 6 (`CLAUDE.md`) — the two permitted closure dispositions
- `docs/handoff-history.md`
- The ledger grew 39 → 70 records and 11 → 28 open between 2026-08-03 and
  2026-08-07. Discovery is still outrunning closure; the schema should be
  fixed before it is another 30 records further in.
