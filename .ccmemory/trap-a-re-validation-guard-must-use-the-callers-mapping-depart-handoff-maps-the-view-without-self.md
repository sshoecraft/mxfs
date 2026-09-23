---
name: trap-a-re-validation-guard-must-use-the-callers-mapping-depart-handoff-maps-the-view-without-self
description: TRAP (sess514): a 'recompute and compare' guard added inside a shared helper used the helper's own view (dlm_page_owner) while one caller (handoff_de…
metadata:
  type: feedback
---

# TRAP: a re-validation guard must use the caller's mapping (sess514, 0.75.18 -> 0.75.19)

**What happened.** To close a time-of-check/time-of-use hole (a page hand-off prepared to a node that had just said goodbye, D-0909) I added a re-check inside `dlm_page_hand_to`: "if `dlm_page_owner(page) != target` or target not in view, refuse". `dlm_page_hand_to` has TWO callers with DIFFERENT owner mappings:
- `mxfs_dlm_handoff_tick` (view-change): owner = `dlm_page_owner` = active_nodes[page % N] — the guard's mapping.
- `mxfs_dlm_handoff_depart` (clean departure): target = others[page % (N-1)], the view WITHOUT the departing node — because the departing node is still in its own active list and `dlm_page_owner` still names IT for its own pages.

Result: every depart hand-off was refused (`P-TAUTH-HANDOFF-STALE-TARGET why=depart` on every clean leave, `P-TAUTH-DEPART pages_left=1`), the root inode's page was left ACTIVE under the departed authority, the successor's mount parked on it (`P-TAUTH-PAGE-PARKED ... in_view=0 purged=0 bootstrap=1`) until the departure worker's takeover, and 17 of 24 armed rejoins took 14 s instead of 1 s. The guard's own probe on the NODE I WAS WATCHING (the survivor) read zero — the refusals were on the departing node's journal, which the harness had only just started capturing.

**Why it was missed.** I verified the mechanism of the new defect carefully but wrote the guard without re-reading the second caller; the depart path's "view without us" was documented in that caller, not in the helper. The one-lap smoke test I ran before the laps (s514c on 0.75.17) predated the guard.

**Rules for next time.**
1. Before adding a "recompute and compare" check inside a shared helper, list every caller and confirm they all compute the compared value the same way; if not, pass the caller's expectation (a flag or the mapping) into the helper.
2. A guard that can refuse work needs a probe on EVERY node it can fire on, and the first lap after it lands must grep all journals for the probe — a zero on the wrong node is not a zero.
3. Fixed by `bool departing`: a departing node requires only that the target is a live member; owner equality applies to the view-change pass alone (0.75.19).
