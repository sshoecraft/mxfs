---
name: ccloop-c7ee71c6-sess42-lkerr-tripwire-350-eio-hunt
description: sess42: matrix B-EIO unreproduced in 5 faithful replays; zapped-fork+open_protect theories ELIMINATED; P-LKERR tripwire shipped in 0.11.350
metadata:
  type: project
---

# sess42 (ccloop session 24) — B-side EIO hunt + P-LKERR tripwire

## The sess41 matrix failure (multi_opener/mmap_only B-EIO)
- NOT reproduced in 5 attempts on fresh 349/350 state: 3x full matrix, deaths→matrix,
  crash_consistency(204 foreign replays)+deaths→matrix. All 9/9 PASS.
- Transcript forensics: B's rm never removed the dirent (test1 saw file intact);
  B had ZERO victim-ino dmesg lines (never reached B6 bitmap check — blocked at path walk);
  probes: ls/statx under BASE → EIO; later P95-SAMETYPE-RELOAD ino=133 (dir,gen-mismatch,try=1,
  no P95C-unresolved → reload landed) at t=1513 = probable self-heal moment.
- Timeline theory: BASE(133) poisoned between eager_clear and multi_opener; healed by the 1513 reload.

## ELIMINATED (code+rig evidence)
- xfs_lookup:1228 zapped-fork EIO — XFS_SICK_*_ZAPPED set ONLY by scrub/repair (never runs here).
- shutdown EIO — shutdowns=0 verified in-run.
- mxfs_dlm_open_protect C3 fail-closed — logs P95-OPEN-PROTECT-FAIL (B had none); file-open only.
- Literal EIO normalization in icache/dlm hooks — grep: xfs_icache.c has ZERO EIO, xfs_mxfs_dlm.c exactly 1 (open_protect).

## GPT consult (sess42, recorded in transcript)
Ranked: (1) DLM/coherency error normalized to EIO in lookup/iget hooks; (2) cached dir-buffer b_error;
(3) child-iget cluster read. Structural risk named: in-place generation-changing reload mutating an
externally-visible inode identity + d_prune-at-reap racing walkers. Tripwire design adopted.

## SHIPPED in 0.11.350 (srcversion 5A26BA1653B7C8C1EFB4EC9)
- P-LKERR tripwire at xfs_lookup out_unlock: any non-ENOENT error on multi-node logs
  stage(1=dir_lookup 2=iget-ladder 3=post-iget) err inum dpgen fmt nx sz stale ssrc dmode dstate
  dgen lgen sick iflags comm. Verified SILENT on healthy traffic (matrix+crash+deaths, 0 lines).
- openunlink_matrix.sh multi_opener/mmap_only now capture rm_B errno in FAIL verdicts.
- NEW tests/dir_reuse_stale_shell.sh: dir2dir mode (25/25 clean, 73 P95 on B) and file2dir
  type-flip mode (reap-freed file ino reused as dir; sacrificial-dir trick pulls AG grant to A
  — cycle1 reuse clean; later cycles allocator drifts to next stride AG).

## Allocator facts learned (load-bearing for reuse reproducers)
- Multi-node: dirs AND files pick node's own stride AGs (strict partition agno%L==slot%L, L=4);
  test1 dirs walk stride AG0,4,8,... per successive mkdir (trylock pass skips foreign-held AGs).
- A peer's reap-free takes the AG-DLM grant to the freeing node → creator's next trylock pass
  SKIPS that AG → same-chunk cross-node reuse needs the blocking pass (all-owned-AGs busy) or
  an ifree-class op (rmdir sacrificial) to pull the grant back.

## Standing watch
grep P-LKERR after EVERY board/matrix run. If it fires: stage+err localizes the producer;
correlate with P95/P34H on the same dp ino.
