---
name: ccloop-c7ee71c6-sess27-three-vacuous-evidence-bugs-in-the-board
description: sess27: three evidence-integrity bugs made board cells lie — first-marker window scoping, dirent_publish_integrity never sourcing lib.sh (scanned 0 l…
metadata:
  type: reference
tags: [harness, evidence-integrity, vacuous-pass, sess27, dirent_publish_integrity]
---

# sess27 — three bugs that made board cells lie (all fixed)

## 1. `dirent_window_scope` scoped from the FIRST marker, not the last

`tests/suite/lib.sh`. Body was:

    awk '/MXFS_DIRENT_WINDOW/{seen=1; next} seen{print}' "$raw"

which latches on the OLDEST marker still in the ring and prints everything after
it. With two runs since boot the "window" spans BOTH, so every criterion using
the helper re-counts the previous run's hits forever — the exact failure the
marker exists to prevent.

MEASURED: a 107k-line ring with markers at 20020.8 and 20656.9 made
`dirent_type_integrity` report `test1 unresolved=6 win_src=marker win_trunc=0`
while the current window (after 20656.9) held **zero** P95B/P201 lines. All six
belonged to the previous run and to the prep between them.

Fixed with `grep -n ... | tail -1` + `tail -n +$((mln+1))`.

Note `tests/dd_loss_capture.sh`, `dd_loss_differential.sh` and
`rank1_straggler_probe.sh` were already correct (`{n=NR}` / reset-buf idioms).
lib.sh was the only buggy consumer.

## 2. `dirent_publish_integrity` NEVER SOURCED lib.sh

`tests/suite/dirent_publish_integrity.sh` had no `source .../lib.sh` at all, yet
sess24 changed it to call the shared `dirent_window_scope` helper. An undefined
function is just a failed command: the call errored to stderr, DW_HAVE /
DW_SOURCE / DW_TRUNC were never set, `WINDOW` was the empty string, both
counters came out 0, and the criterion reported **PASS having scanned ZERO
kernel lines**. Every green cell it recorded after that change is vacuous.

The tell was in the recorded `measured` string all along: `window=0 win_src=
win_trunc=` — three EMPTY values, not `win_src=none` which the helper sets on
its first line. Empty globals mean the function never ran. Read the measured
string, not just the status.

After adding the source: `window=1 win_src=marker`, and it is **genuinely red** —
3 of 32 nodes FAIL, `test4 stale_base_mutations=1` (P195, the
D-SILENT-MKDIR-LOSS precursor). So the board gained a real red that had been
hidden, not a cosmetic one.

## 3. `have_window` was computed and printed but never used in the verdict

Same file. With no locatable window the script scanned an empty string and
PASSED *because* it had no evidence — one branch away from its own
`probe_built=0` rule that says "unverifiable is not a pass". Now fails closed
with that reason.

## 4. manifest vs criteria.json divergence (documentation, not dispatch)

`dirent_type_integrity` and `ag_strand_repair` were missing from
`tests/suite/manifest` while present in `criteria.json`. **My first conclusion —
"run.sh could never dispatch them" — was WRONG and is corrected in the file:**
run.sh builds its matrix from criteria.json
(`mapfile -t ROWS < <(jq '.categories[]...' "$CRIT")`, ~line 1160) and
`applicable()` additionally requires `tests/<cat>/<name>.sh` to exist. Both were
dispatchable the whole time. The real defect is that the manifest calls itself
"THE INDEX", so omitting a live criterion misleads readers — it misled me into
thinking a stale FAIL cell was unfixable. Keep the two sources in agreement.

`posix_single`/`fsx`/`fio_verify`/`integrity_filetypes`/`fault_enospc` carry
`max_nodes=1` in criteria.json and are intentionally single-node-only; they do
not appear at N>1.

## Generalisable lesson

For every criterion, ask "what would this cell look like if the measurement
never happened?" If the answer is PASS, the cell is not evidence. All three bugs
here had that shape, and two of them were introduced by a *refactor* to a shared
helper that the caller could not reach.
