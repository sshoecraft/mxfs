---
name: ccloop-c7ee71c6-sess21-open-defects-ledger-is-the-readiness-gate
description: sess21: tests/criteria/OPEN_DEFECTS.json + the open_defects criterion are the DETERMINISTIC production-readiness gate. Intermittent behavioural crite…
metadata:
  type: project
---

# sess21 — the `open_defects` ledger IS the production-readiness gate

## Why behavioural criteria are not enough
`showstat` read 20/20 green through all of these:
- a soft lockup that killed test31 for 522 s and starved all 31 peers
- an ILOCK assertion failure (`xfs_assert_ilocked`) on 3 of 4 soak nodes
- a `mkdir(2)` that returned SUCCESS with the entry existing on no node

Even after adding criteria for them, the INTERMITTENT ones cannot gate:
- `dirent_durability` reproduces its defect ~1 run in 10
- `dirent_publish_integrity`'s precursor (P195) fires 0-1 times per run

Both go green whenever a run gets lucky. **"This run did not reproduce it" is
not "fixed" — but a green cell asserts the latter.**

## The gate
- **Ledger**: `tests/criteria/OPEN_DEFECTS.json` (readable from every node —
  the rig NFS-mounts `/src`).
- **Criterion**: `tests/suite/open_defects.sh`, group P9, FAILS while any entry
  has `status != RESOLVED`. Unreadable ledger also FAILS (unverifiable is not a
  pass).

Board @32/caw after adding it: **26 tests — 25 PASS, 1 FAIL**, the FAIL being
`open_defects open=5 of=5`.

## Current entries
| id | sev |
|---|---|
| D-SILENT-MKDIR-LOSS | critical |
| D-RELEASE-BARRIER-OPEN | critical |
| D-MOUNT-DEGRADES-WITH-USE | major |
| D-STRANDED-AG-REPAIR-UNVALIDATED | major |
| D-MATRIX-UNMEASURED | minor |

Each carries `evidence`, `mechanism`, `detector`, `blocking_fix`, and
`attempted_and_refuted` — the last exists so a future session does not re-walk
a dead end (e.g. the epoch-override at the conversion gate, the lookup-time
freshness gate, and `pub_skip_rearm`'s measured livelock are all recorded there
with their measurements).

## The rule
An entry leaves ONLY under RULE 6's two dispositions:
- **DISPROVED** — direct evidence the behaviour was not a defect
- **FIXED_AND_VERIFIED** — RULE 4 proved the cause, the patch targets THAT
  cause, and testing that exercises the cause passes under unchanged criteria

"Cannot reproduce", "rare", a clean run, a plausible explanation, a workaround,
or documentation are NOT dispositions.

**Never delete an entry, weaken the check, or drop the criterion to make the
board green.** A green board that is not true is the exact failure this gate
exists to prevent.
