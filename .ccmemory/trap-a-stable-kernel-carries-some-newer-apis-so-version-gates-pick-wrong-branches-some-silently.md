---
name: trap-a-stable-kernel-carries-some-newer-apis-so-version-gates-pick-wrong-branches-some-silently
description: TRAP (0.89.91): Debian 13's 6.12.107 has some 6.13-6.17 APIs and not others; LINUX_VERSION_CODE gates broke the build, and one compiled silently wron…
metadata:
  type: feedback
tags: [kcompat, porting, debian, trap]
---

A stable/LTS kernel (Debian 13 6.12.107) carries backports: embedded ioend io_bio + iomap_ioend_from_bio, ->map_blocks(len), iomap_file_buffered_write(..., private), 3-arg kvrealloc, mapping_max_folio_size_supported — yet keeps io_type/IOMAP_F_SHARED. MXFS gated these at 6.13/6.15/6.17 by version, which picked the wrong branch.

Worst case compiled cleanly: xfs_end_bio read bio->bi_private as the ioend; once the bio is embedded iomap no longer sets it. Compile errors are NOT a complete guide — audit every gate above the target kernel against its real headers (copy /usr/src/linux-headers-* out of the build container).

Fix pattern: a probe per API in pal/linux/kcompat_probe.sh (split bundled gates: one change per probe), export-check any function a module calls (6.12 declares generic_atomic_write_valid but does not export it -> modpost undefined). Then prove no regression: tabulate each new probe's answer on every shipping kernel (6.8, RHEL 5.14, PVE 6.17, 7.0) and confirm it equals what the old gate chose.

Also found by that audit: a gate that leaves a feature flag OFF can hide a missing check behind it — enabling fop_flags would have exposed MAP_SYNC acceptance, which was already live on 6.17 (see CHANGELOG 0.89.91).
