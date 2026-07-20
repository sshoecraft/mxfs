---
name: mxfs1-vs-v5-not-mirror-images
description: CORRECTION: mxfs.1 = bespoke hand-written XFS-like FS (own cache layer); v5 = fork of REAL Linux kernel XFS. NOT mirror images. mxfs.1 coherency code…
metadata:
  type: project
---

# mxfs.1 and v5 are NOT mirror images (user correction, ccloop sess69)

The user explicitly corrected the repeated "mirror images" framing. Do NOT use it.

## The real distinction
- **mxfs.1** = a **bespoke, hand-written XFS-like filesystem**. Its own kernel
  code from scratch, including its OWN cache layer (custom dir_cache/block_cache).
  It controls its entire cache, so it can drop/re-parse on BAST.
- **v5** = a **fork of the ACTUAL upstream Linux kernel XFS** (6.19-rc0, the real
  xfs/ tree). "v5" = the real XFS **v5 on-disk format**. The MXFS coordination
  overlay (xfs_mxfs_dlm.c, DLM hooks) is bolted onto genuine Linux XFS.

## Why this matters for the cache_coherency blocker
"Just use mxfs.1's code / mxfs.1 already solved this" is a FALLACY — there is NO
shared code to copy. mxfs.1 solved coherency INSIDE a cache layer it fully owned.
v5 must make the REAL Linux XFS machinery coherent across nodes: xfs_buf cache,
the AIL, CIL, delwri queues, pin/unpin, log force — none of which mxfs.1 had. The
coherency invariants (flush-dir-before-release, evict-on-acquire, drop-on-BAST,
re-read-fresh) can be borrowed as PRINCIPLES, but every mechanism must be
re-derived in real-XFS terms. That re-derivation is the whole difficulty and why
v5 is at 3/4, not done.

## SCOPE IS NOT LIMITED TO XFS (user correction #2, ccloop sess69)
Do NOT say "must stay a valid XFS filesystem." v5 must stay a valid **MXFS**
filesystem. We own `mkfs_mxfs`, `chk_mxfs`, `resize_mxfs` — the on-disk FORMAT
and every tool that reads/writes/checks it. The layout is already non-stock XFS
(the MXFS envelope — disklock slot table + journal slice — precedes the XFS sb
region). So changing dir-block layout, adding a coherence epoch / per-dir version
region / extra dinode fields / a dedicated coherence metadata area is ALL on the
table — just update our tools to match. Stop imposing "native-XFS" constraints
that don't exist.

The ONLY real constraints:
1. Don't regress the won perf (single-node 104%, rsync 103% — the reason v5
   exists). Surgical dir-block coherence is fine because perf path = file data
   I/O, mostly distinct from shared-dir-block coherence.
2. Stay crash-recoverable (recovery / node-death journal replay is OUR design).
3. Stay readable by our own tools (update them alongside any format change).

A pull-based on-disk dir epoch (reader cheaply checks an on-disk version, re-reads
on mismatch — sidesteps CAW's unreliable cross-node BAST) is the leading method.

Related: [[sess68-baseline-evidence-bnobt-fua-gap]] [[sess94_lessons]]
