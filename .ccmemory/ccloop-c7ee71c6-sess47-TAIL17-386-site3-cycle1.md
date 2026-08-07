---
name: ccloop-c7ee71c6-sess47-TAIL17-386-site3-cycle1
description: sess47: 0.11.386 (install site 3: reverify/readahead hook) cycle 1 = matrix 9/9, laps PASS, ZERO shutdowns; one BENIGN inverse P53 (overlay latest-va…
metadata:
  type: project
---

# 0.11.386 (32AA923745B10D30481A3D2) — site-3 hook live; cycle 1 result

## Added over 385
Overlay install site 3: read_map's "already read" reverify branch (readahead-filled buffers' first verified use) — TAIL16 audit item 1.

## Cycle 1 (lap PASS ×2, matrix 9/9): ZERO shutdowns/-117 fleet-wide.
One NEW P53 shape on test2, ABSORBED (no shutdown): `old_ptr=NULL old_agino=0xaf next_agino=NULL` — INVERSE of the fossil: the overlay installs the LATEST committed value (per-ino record), which can be a LATER item's target while an earlier in-flight item still expects the intermediate value; the buffer is then already in the later item's desired state → idempotent carve-out no-ops it → final chain correct. This is the overlay∘pipeline composition working as GPT prescribed (tolerated + instrumented). If this shape ever appears with old_ptr != next_agino (non-absorbable), revisit: record() could keep a small per-ino VALUE HISTORY so precommit can validate against any committed-not-home value, or precommit could consult the store directly.
Store activity test2 alone: 37 overlay+skew events — the machinery is carrying real load.

## Tally at 386: cycle 1/8 clean (this new benign shape noted). Producer fatals: v1 c1, v2 c2, v3 c2, site-3 → none yet. Soak continues per TAIL15 protocol; promotion bar unchanged (≥8 clean cycles, P53-fatal=0; benign absorbed events tolerated but tracked).
Rig: 32/32 green on 386 ship config. Rings: test2 ×6 + test9/test10/test32.
