---
name: trap-sameboot-remount-harness-reloaded-module-without-force-transport-measured-caw-not-tcp
description: TRAP (sess510): tests/sameboot_remount.sh reloaded mxfs.ko with target_cache_protected=1 only; every remount (s509c, s509d) came up CAW, so the TCP s…
metadata:
  type: feedback
tags: [trap, harness, transport, tcp, sameboot]
---

# A harness that reloads the module must assert the transport it comes up on

sess510 (2026-09-04), run 140e6b67. tests/sameboot_remount.sh was written in
sess509 to verify the 0.75.3 TCP same-boot settle port (record
D-TCP-LAST-NODE-SAMEBOOT-REMOUNT-HANGS-OWN-RETIRE-PENDING-SLOT-KEY-PRESENT-SETTLE-UNHELD-0904).
Its `join` does `rmmod` + `insmod $KO $MODARGS` with MODARGS defaulting to
`target_cache_protected=1` — no `force_transport=1`.  The last leaver
forms a NEW cluster, and a new cluster tries CAW first; the peer then
conforms (`P-TRANSPORT-CONFORMED caw votes tcp=0 caw=1`).  Every join in
`tests/evidence/20260904T213050Z_sameboot_s509d/*_join_journal.txt` reads
`DLM init: ... transport=caw` (5 of 5), and s509c was the same.

So the sess509 claim "0.75.3 same-boot port verified on lone-node cycles"
was a CAW measurement (the CAW path has had the settle since sess451).
The TCP path was only exercised by transport_conformance arm A's rejoin.

Fixed sess510: MODARGS default now carries `force_transport=1`, and every
join asserts `DLM init: node_id=N transport=$MXFS_TRANSPORT` (default tcp).

General rule: any harness that rmmod/insmods must (1) pass the transport
explicitly and (2) assert the `DLM init: ... transport=` line per mount.
A prep's force_transport=1 does not survive the harness's own reload.
The lone `P-TRANSPORT-CONFORMED caw` INFO line was the only visible sign;
INFO lines in a PASS lap are worth one read.
