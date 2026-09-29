---
name: technique-derive-flake-window-laps-from-the-board-before-a-release-board-run
description: TECHNIQUE (0.90.17): a row FLAKY on the board needs 11-k more runs (k = window index of its newest genuine FAIL, 0 = live); run 10-k single-row laps,…
metadata:
  type: feedback
tags: [release, board, flake-window, criteria, laps]
---

# Derive the window laps from the board, never by feel

`tools/criteria.py` grades a row FLAKY while any genuine FAIL (status FAIL, reason not rig noise, no `detector_defect` annotation) sits in its 11-run window (the live run plus 10 history entries). NOT RUN and ABORTED entries do not count but DO occupy a slot, so they age a failure out like a PASS does.

To know how many clean runs a row still needs, read its window from `data/criteria.json` (`per_config[<cfg>]` is the live cell, `history` the older runs, newest first) and take k = the index of the NEWEST genuine FAIL. The row reads PASS again after 11-k more runs of that row. The board run that closes a verification is one of them, so run 10-k single-row laps first, then the board — the board's read-back then sees a clean window.

Measured 2026-09-29 before the 0.90.17 release: 4/tcp chk_clean k=6 (2 chain laps pending) -> 2 more laps + the full-verify board; 2/tcp fio_perf k=3 -> 7 laps + board; 2/cawd crash_audit k=2 -> 8 laps + board. `tests/release_verify_chain.sh` takes these as W4_LAPS / W2TCP / W2CAWD and `tests/board_4node_chain.sh` (NODES=2|4, `dlm:row,row`) runs each lap as one forced prep plus the rows together under one run id.

Two traps this replaces: counting laps from "how many failed" instead of from where the newest failure sits (a failure at index 2 needs 9 runs even if it is the only one), and running the board first and the laps after (the board's read-back is what a release cites, and it was taken before the window was clean).
