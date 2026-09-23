---
name: technique-pin-the-victims-log-tail-to-put-a-released-tenure-image-in-front-of-the-replayer
description: TECHNIQUE (sess594, D-FOREIGN-REPLAY-UNGATED-IMAGES): a released tenure's image never sits in a live node's replay window (drain lands it, destage ki…
metadata:
  type: feedback
---

## The gap
Four laps (s593g/h, s594a and every P273 line in tests/evidence) had REDUNDANT_CLEAN=0: the verdict for a cleanly released tenure's image was code-read only. Invariant 1 (drain before unlock) plus the coalesced destage kick (async log force + AIL push-all ~10 ms after creates) means the victim's on-disk tail (h_tail_lsn of its last record) has always moved past a released image by the time the marker is forced; s593h's window was two markers and nothing else.

## The instrument
`mxfs.dbg_ail_pin_ino=<ino>` (xfs/xfs_inode_item.c): `xfs_inode_item_push` answers XFS_ITEM_LOCKED for that inode and the `xfs_iflush_cluster` loop skips it (a SIBLING's push would otherwise flush the whole cluster buffer, pinned inode included), so the item stays in the AIL and pins the tail. Prints `P-AILPIN-HOLD ino= n=` (first 4 hits, then every 1024th). Harness handshake (tests/tcp_death_replay.sh TDR_FALSE_APPLY=3): the writer creates the pin file, prints PIN_INO, waits for /root/tdr_pin.go; the harness sets the knob over ssh and touches the go file; the writer re-dirties + fsyncs the file (relog at an LSN before the images under test) and proceeds. Read `P-AILPIN-HOLD` on the victim BEFORE the kill — its dmesg dies with it.

## Traps met on the way
- A released resource is absent from the fence-time manifest by definition, so `P-RMAN-EVAL hits` can be 0 or 1 on such a lap; the arm's own REDUNDANT_CLEAN>=1 is the vacuity check, not the manifest hits.
- Never set the pin on a node meant to survive: a pinned tail eventually exhausts the log.
- Editing the harness file while a lap runs is safe only for text AFTER the point bash has reached (it tracks byte offsets); an insertion before it desynchronises the running script.
