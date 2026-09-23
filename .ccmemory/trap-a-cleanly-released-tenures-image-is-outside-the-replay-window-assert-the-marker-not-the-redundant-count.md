---
name: trap-a-cleanly-released-tenures-image-is-outside-the-replay-window-assert-the-marker-not-the-redundant-count
description: TRAP (sess593, D-FOREIGN-REPLAY-UNGATED-IMAGES): a victim's released-tenure image is landed by the release drain and the log tail moves past it befor…
metadata:
  type: feedback
tags: [trap, replay, harness, foreign-replay, tcp]
---

# A cleanly released tenure's image is not in the victim's replay window

**Measured (s593g, s593h; tests/evidence/20260912T094158Z_tcpdr_s593g, 20260912T095057Z_tcpdr_s593h, 2 nodes / TCP, 0.84.8):**

- s593g (the arm as first written): the victim's adds to the survivor's block directory were acknowledged, the survivor added names (BAST → the victim drained, published its clean-release marker, released), and the victim's writer then streamed 700 more files for 6 s before the kill. The slice window held only the stream's last two transactions (`P273-SHADOW-EVAL txn=2 buf=18 relmarks=0`): neither the directory image nor its marker. The arm's data assertions passed trivially — no image of that block was ever replayed — a vacuous pass on the question asked.
- s593h (writer mode `prestop`: the victim's adds are its LAST transactions, the kill follows the survivor's writes at once): the window held `txn=0 buf=0 relmarks=2` — the two clean-release markers and nothing else. The release drain wrote the directory block before releasing (the ordering contract of `mxfs_relmark_publish`), the AIL delete moved the tail, and the marker's forced commit carried that tail, so the released-tenure image sits before the tail and is never replayed.

**Consequences for a replay harness:**
1. `REDUNDANT_CLEAN >= 1` (or `P227-FR-REDUNDANT-SKIP >= 1`) cannot be required for a released tenure: the image is outside the window by construction whenever the release was clean. Assert the marker was in the window and seen (`P273 relmarks >= 1`) and that nothing was refused (`notheld=0 staleep=0 wlineage=0 untagged=0`); report `REDUNDANT_CLEAN` as information.
2. A plain-lap vacuity guard that requires "manifest hits >= 1" (`P-RMAN-EVAL hits`) fails on such a window (no image consults the manifest); the arm's own guard is the marker count.
3. The victim's dmesg says nothing about a published marker — `mxfs_relmark_publish` prints only `P-RELMARK-FAIL`; success is a counter. Grep the victim for the FAIL line, and read the evaluator's `relmarks=` on the survivor for the positive.
4. To put a released-tenure image INSIDE the window you would need something older still pinning the tail at the release (an un-landable item); the destage kick lands everything within ms, so that shape does not arise from the workload alone.

Related: `trap-mxfs-slice-holds-only-last-txns-destage-kick-crash-tests-need-target-txn-last`, `trap-a-silent-instrument-and-a-clean-system-are-the-same-observation`, `vacuous-pass-the-dominant-evidence-failure-in-this-project`.
