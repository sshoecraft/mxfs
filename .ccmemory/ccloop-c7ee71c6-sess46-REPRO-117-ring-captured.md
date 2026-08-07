---
name: ccloop-c7ee71c6-sess46-REPRO-117-ring-captured
description: sess46 FINAL: D-REAP-IFREE-117 REPRODUCED (2/5 aged lap→matrix cycles); FULL RING SAVED test2:/root/ifree117_run2_1785703032.dmesg; exit is NOT in di…
metadata:
  type: project
tags: [ccloop, sess46, defect, repro]
---

# D-REAP-IFREE-EFSCORRUPTED-SHUTDOWN-372 — REPRODUCED, ring in hand

## Repro protocol (2 hits / 5 cycles, both on test2!)
fresh prep (ship config) → rsync 6-test lap → openunlink_matrix.
Signature: multi_opener + mmap_only rm_B EIO (post-shutdown fallout);
xfs_ifree rc=-117 → 0x1 shutdown → withdrawal on test2 (nodeB of the
matrix = the UNLINKER role — likely role-correlated, not node-hardware).

## THE FORENSIC RING IS SAVED (do this FIRST next session)
test2:/root/ifree117_run2_1785703032.dmesg (16.8MB, node root disk —
survives re-prep). Event at ring time ~1950.533. MINE IT:
  grep -n 'error -117' → context window ±30s
  the failing ino: P137-INACT-TIME line AT the shutdown moment
  P82-ADD/P82-REM bucket ops for that ino
  P71 / iunlink / bucket lines — KEY: **373 completed P-DIFREE-CORRUPT
  coverage and NO P-DIFREE line printed → the -117 exit is NOT under
  xfs_difree** → it's in xfs_ifree proper or xfs_iunlink_remove
  (the P71 empty-bucket family) BEFORE difree. The ring decides.

## Rig state at relay
32/caw ship config 0.11.373 (691714A3B35E853F0E417FB); test2 SHUT DOWN
(needs re-prep before further rig work — ring already captured, safe to
recover). Laps: 9 clean rsync laps total (7A+2B), P217=0 throughout.

## Next actions in order
1. Mine the ring → name the -117 exit + ino + bucket state.
2. Instrument that exact exit (if not already probed) + fix per RULE 4.
3. Re-prep, resume lap rotation.
