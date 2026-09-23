---
name: trap-a-clean-rig-build-on-ubuntu-6-8-says-nothing-about-the-proxmox-kernel-run-pve-kbuild-check
description: TRAP (0.89.77): shipped a .deb whose DKMS build failed on PVE 9 (6.17 + 7.0); rig only builds 6.8. Run scripts/pve_kbuild_check.sh; the API drift lis…
metadata:
  type: feedback
---

0.89.77 passed every rig gate and shipped; on Proxmox VE 9 its DKMS build failed on every node, so nothing installed. The rig and clyde build only against Ubuntu 6.8.0; code under `#if LINUX_VERSION_CODE >= ...` gates for newer kernels had **never been compiled** (e.g. the `>= 6.19` `mmap_prepare` branch still used `desc->vm_flags`, gone in 7.0).

**Check:** `scripts/pve_kbuild_check.sh [KREL ...]` compiles the module, staged as the .deb stages it, against Proxmox headers in a Debian 13 container (default kernel + any named ABI) — about 2 min. `scripts/release.sh` runs it first. Run it after any change that calls a kernel API the tree has not used before.

**Container gotchas it already handles:** host network (bridge has no egress); `libelf1t64` (objtool) and `libdw1t64` (gendwarfksyms) or the build dies with `Error 127` and no compiler message; `make -k` or make stops scheduling after the first failed object and hides the rest.

**Kernel API drift found (6.8 → 6.17 → 7.0), and the fix used:**
- `d_hash_and_lookup` VFS-internal from 6.16 → `try_lookup_noperm(q, dir)` (args reversed; returns ERR_PTR too).
- `destroy_timer_on_stack` → `timer_destroy_on_stack` (6.16; shim in `xfs_platform.h`).
- `inode->i_state` is `struct inode_state_flags` from 6.19/7.0 → read through `mxfs_istate()` (unsigned long; safe for `%lx`), write with `inode_state_assign_raw()`. A struct passed to `pr_warn` varargs COMPILES — only the `&`/assignment sites error, so grep every read.
- `iomap_read_folio`/`iomap_readahead` take a read ctx in 7.0 → `iomap_bio_read_folio`/`iomap_bio_readahead`.
- `vm_area_desc.vm_flags` → `vma_flags` + `vma_desc_set_flags(desc, VMA_HUGEPAGE_BIT)`; `daxdev_mapping_supported(desc, ...)`.
- `kernel_bind`/`kernel_connect` take `struct sockaddr_unsized *` in 7.0 → pass `(void *)&addr`.
6.18/6.19 headers are not available here (kernel downloads are forbidden), so gates at 7.0 are proven only at 6.17 and 7.0.
