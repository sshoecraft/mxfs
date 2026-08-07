---
name: ccloop-c7ee71c6-sess47-TAIL5-381-findingB-armed
description: sess47 truly final: 0.11.381 fleet = finding-B discriminator live (P-B-MODE-DIVERGE + self-correct to coherent mode at the authority guard); repro CL…
metadata:
  type: project
---

# 0.11.381 (5E766F6B474262821AD4ECD) — fleet state at sess47 relay

Adds over 380: finding-B discriminator at the xfs_inactive authority guard (xfs_inode.c ~4641): when the raw disk-mode read says LIVE for a foreign zombie, also runs mxfs_dbg_disk_di_mode_coherent; on divergence prints P-B-MODE-DIVERGE (cap 60) AND adopts the coherent verdict (fail-safe direction: coherent mode==0 → B-guards skip destructive). Extra round-trip only on the rare foreign-zombie live-verdict path.

Deploy verification: reap repro CLEAN ×2 scenarios, matrix 9/9, zero divergences through first full matrix (burst-conditioned class — the trap waits).

## Relay watchlist on 381 (all capped/quiet in healthy runs)
P-B-MODE-DIVERGE (finding B proof), P-IFR-AGI-STALE (true prior-tenure AGI staleness), P-PINNED-REREAD (delwri fossil culprit + stack), P53-IUNLINK-MISMATCH pairs (fossil producer alive), P-UNLREM-*/P-UNLPRE-* (-372 family), plus shutdowns. Aged soak protocol + promotion gates in TAIL3; full queue in END memory. 3 clean aged cycles so far across 380-381.
