---
name: sess48-config-combo-and-leaf-tear-and-relabort-lead
description: sess48(ccloop): 8/tcp dir_reuse — owner_scan+grant_evict+target_flush (baked default, build 237F937D) kills P13+shutdowns, residual ~1/24 single-loss…
metadata:
  type: project
---

## sess48 (ccloop 4cb2d0a2) — config combo + leaf-tear + P15-REL-ABORT lead

### BAKED DEFAULTS (build 237F937D, xfs_mxfs_dlm.c) — KEEP, big improvement
Set DEFAULT 1 (were 0): `dir_owner_scan`, `dir_grant_evict`, `dir_modify_target_flush`.
Each was "insufficient ALONE" in prior sessions but the COMBO eliminates the P13-COLLIDE
multi-loss AND all shutdowns at 8/tcp dir_reuse. Residual: ONE durable single-dirent loss
~1-2 per 24 rounds (no shutdown). Also added P48 instrumentation (DG-CHAIN, OWNEREVICT-DIRTYSKIP)
in dlm.c + xfs_mxfs_dlm.c — harmless.

### REVERTED (cause regression — DO NOT re-enable naively)
`dir_release_flush_all_done` (DATA-only force-write at release) and new `dir_release_flush_leaf`
(DATA+LEAF force-write): BOTH cause **P21H-LEAFHOLE tear → FS shutdown** (data on platter ahead
of / inconsistent with leaf hash index). DATA-only desyncs leaf; DATA+LEAF still tears (writing
our leaf creates an inconsistent on-disk index for the next acquirer). This is the ~30-session
leaf-vs-data architectural core. Left as default-0 A/B levers. The naive GPT-consult-#1
force-complete-entire-fork did NOT work as implemented (still tears).

### RESIDUAL ROOT LEAD (RULE 4, NOT yet proven): P15-REL-ABORT
The residual single-loss (e.g. round22 node8_f1.md5, LOOKUP_ENOENT REREAD_MISS, all nodes agree)
= the entry's dir DATA block was not durable on the shared platter when a peer cold-read it
(owner_scan acquire-evict + target_flush make the read coherent, so the gap is WRITE-side).
Correlates with **P15-REL-ABORT** (dlm.c, sess15 P58-avert): "holder re-acquired during drain;
release aborted, BAST re-armed" — fires 230×/node under 8-node MHT batching (inode_mht_ms=300).
HYPOTHESIS: the release-abort churn (holder re-acquires mid-drain repeatedly) leaves a window
where a block isn't drained durable before a peer reads, OR the abort interplay reverts an add.
NEXT: test inode_mht_ms=0 (disable MHT batch) — if loss vanishes, the batch/abort interplay is
root. Then targeted fix (e.g. ensure drain completes for the specific just-added block, or don't
abort if a peer is genuinely waiting). RULE 0: mht=0 may be very slow.

### Tools
- `tests/drc_dirtyskip.sh "<modargs>" <rounds>` — reboot-clean once, run 8/tcp dir_reuse,
  correlate RDMISS/CLASS/P13/DIRTYSKIP. Logs to scratchpad.
- Build identities this session: 05BC5765(keeper start) → 237F937D(3-lever default, current).
- Repro is ~16s/round (owner_scan per-AG rhashtable walk per handoff = RULE-0 slowness to fix later).

See [[sess48-progress-ownerscan-flush-cuts-loss-residual-release-drain]],
[[sess47-GPT-consult-leaf-coherence-invariant-and-design]].
</body>
