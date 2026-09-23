---
name: trap-a-knob-lap-that-toggles-a-publication-filter-must-end-in-the-offline-structural-check
description: TRAP (sess574→615, D-0957): an A/B knob lap on the inode-cluster write filter stranded a directory core on the platter and reported nothing; only a l…
metadata:
  type: feedback
tags: [D-0957, D-0955, harness, oracle, chk_mxfs, partial-write, trap]
---

# A lap that toggles what reaches the platter needs the platter read back structurally

## What happened
`tests/d0946_disklive_knob_vs_aging.sh` ran `partial_iwrite_sole` as an A/B knob on
0.75.128 (s574iwr): knob=1 rounds put the sole survivor on the partial inode-cluster
write filter without DLM grants. One knob=1 round's directory was dropped from every
cluster write (P56-NL-LOGGED-DIR-SKIP, item retired from the AIL under
`pub_skip_rearm=0`) and its core never landed. The lap's own instruments — round
counters, P218 passenger lines, later the cold namespace readback — all read clean or
were not there yet. The stranded inode surfaced 20 minutes later in a DIFFERENT
harness's cold `chk_mxfs` as "inobt-allocated agino 128 has a FREE core", filed as a
critical defect with no mechanism, and cost a session to attribute.

## The rule
- A harness whose knob changes WHAT REACHES THE PLATTER (a write mask, a publish
  gate, a flush skip) must end with both nodes unmounted and `chk_mxfs -v` on the
  quiesced device, and assert on the checker's verdict — not only on probes and names.
  Probes count decisions; a name walk sees dirents, not inode records; only the
  offline check compares an inode's two records.
- Alternating arms hide the damage: a knob=0 (whole-write) round can land what a
  knob=1 round dropped if a co-resident flush rewrites the same cluster buffer. One
  stranded object out of N knob=1 rounds is the expected shape; do not read "only one"
  as "a different cause".
- A dmesg capture that starts at the LAST mark instead of the first (the ring rotated)
  is not the lap's dmesg. The s574xm capture began at the `-SOLE` mark; every create
  of the lap was already gone.

## Where the oracle now lives
`d0946_disklive_knob_vs_aging.sh` ends every lap with the COLDCHK epilogue (0.85.2,
`MXFS_D0946_COLDCHK=0` skips it); `d0949_sole_survivor_chunkfree.sh` has had its cold
check since 0.75.126; the board row is `tests/criteria/chk_clean.sh`.
