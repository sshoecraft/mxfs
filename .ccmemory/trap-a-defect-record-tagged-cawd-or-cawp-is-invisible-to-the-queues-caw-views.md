---
name: trap-a-defect-record-tagged-cawd-or-cawp-is-invisible-to-the-queues-caw-views
description: TRAP (0.90.24): defects.py matches dlm exactly; a record added with -D cawd (the board's name) never shows in `N caw`, the view a release cites.
metadata:
  type: feedback
tags: [defects, release, caw, cawd, queue]
---

# A defect record tagged `cawd` or `cawp` is invisible to the queue's `caw` views

**What happened (0.90.24 release prep):** `tools/defects.py 4 caw` listed 9
records and the README said "9 reach 4-node CAW". The queue held a tenth,
`D-DIRSHARD-REUSE-PEER-READDIR-EUCLEAN-ON-CAW-AT-4-NODES`, added the day before
with `-D cawd` because the board it failed on is called `4/cawd`. It was the
only record of 89 with that tag (36 others say `caw`).

**Why:** `blocks()` in `tools/defects.py` tests `seen_dlm in ("any", dlm)`:
an exact match. `caw`, `cawd` and `cawp` are all accepted values, but they are
the rig's names for how the LUN is attached (multipath, direct in-guest iSCSI,
passthrough). `run.sh` maps `cawd|cawp` to `BASE_TRANSPORT=caw`. The transport
is CAW in all three.

**What to do:**
- When adding or updating a record from a board failure, pass `-D caw` for
  anything seen on a `caw`, `cawd` or `cawp` board, and `-D tcp` for TCP. Never
  copy the board's condition name into `-D`.
- Before citing a per-configuration count (README, changelog, release notes),
  count the tags in `data/defects.json` and confirm nothing carries `cawd` or
  `cawp`: a record with one of those is missing from `N caw` and
  `N caw --release`.
- The board tool is the opposite: `tools/criteria.py` wants the condition name
  (`4 cawd`), and `4 caw` is a different, mostly empty column.

The record here was classified as not blocking, so the release verdict did not
change, but the published count did (9 to 10), and a blocking record tagged
this way would have passed the release filter unseen.
