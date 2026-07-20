---
name: sess17run-FIX-forkadopt-handoff-round1-fixed-round5-residual
description: sess17(ccloop) FIX (build 9AF854E6, KEEP): fast-path dir reload uses post_release=dir_ex_handoff on genuine handoff → dir_reuse 8/tcp round 1 FIXED,…
metadata:
  type: project
---

## sess17 (ccloop) — fork-adopt handoff fix (KEEP) + round-5 residual

### THE FIX (build 9AF854E62C318B799F513FB — KEEP, stable, no regressions)
In `mxfs_dlm_ilock_begin` cached-EX FAST-PATH (xfs_mxfs_dlm.c ~11027-11460): added `bool dir_ex_handoff`, set TRUE only at the two RELIABLE cross-node handoff setters (grant_gen change ~11295, dir_epoch advance ~11331) — NOT the lossy gen/RELOAD-flag setter (~11229). Changed the fast-path reload (`mxfs_dlm_reload_inode(ip, ..., false)` → `..., dir_ex_handoff`): on a genuine handoff a DIFFERENT node held EX since our last grant, so our prior work was drained at our release → force disk-SUPERSET adopt (post_release=true) overriding keep-stale guards → the converter never freezes a stale shortform/fork base.
**RESULT: dir_reuse 8/tcp failure moved ROUND 1 → ROUND 5.** Round-1 fresh-dir sf→block conversion loss (node2_f1) is FIXED. No DLM timeouts, no corruption, P22-DATASCAN heals leaf holes. KEEP this fix.

### Round-5 RESIDUAL (single-entry data-block revert, sameincarn=1)
After rm-rf+recreate (reused ino 131), round-5 loses ONE first-dirent (e.g. node3_f1). Signature: `P13-STALEREAD ino=131 use_block=2 daddr=2093296 ... node3_f1 — REUSED data block read near-EMPTY (stale/reverted read of a should-be-full block)`. incore_gen==disk_gen (sameincarn=1) at failure — so NOT incarnation mismatch; it's a TENURE-scoped durable data-block lost-update: a node keeps a stale near-empty block (a REUSED daddr) across a handoff (the payload-LSN "undestaged" keep-guard FALSE-POSITIVE in mxfs_dir_drain_evict_data_blocks line ~5242), then RMW/writes it, reverting the peer's committed dirent.

### REFUTED this session (data-block acquire-side evict override is the WRONG lever):
- BLANKET force-evict (drop undestaged keep on handoff): REGRESSED round 5→3, 1 entry→24 entries (dropped a CURRENT-tenure undestaged block holding genuine un-drained work). Build A95DE7B9.
- EPOCH-GATED force-evict (only evict in_ail block whose b_mxfs_dir_epoch < valid_epoch): introduced **2142 DLM acquire timeouts** + unhealed leaf holes (DATASCAN-HEAL=0), died at round 5 barrier. Build CC554745. RULE-0 fail. Both REVERTED → back to 9AF854E6.

### Conclusion: the round-5 data-block staleness must NOT be fixed by acquire-side bulk evict (destabilizes). Per [[sess16run-acquire-side-refresh-cannot-work-must-be-release-side]] + GPT [[sess17run-GPT-design-incarnation-stamp-dirbuf-plus-digen-reload]] part-2: the structurally-sound place is the READ-path per-buffer stamp check (xfs_da_read_buf already has a b_mxfs_dir_epoch < cur_ep check ~line 3336 — verify it's ACTIVE and uses the AUTHORITATIVE master epoch, not lagging valid_epoch) OR the RELEASE side (invalidate own cached dir buffers after drain). NEXT: investigate why the read-path epoch check doesn't catch daddr=2093296; do NOT re-try acquire-side bulk evict. Criterion NOT met; marker not written. Tests harness: tests/suite/dir_reuse_coherency.sh now streams dmesg to /src/mxfs/tests/tcp/drc_cap/stream_rankN.log (NFS, survives reboot) — KEEP for diagnosis.
