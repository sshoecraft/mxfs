# What a platform release claims

A release claims a set of platforms (`data/platforms.json`, written only by
`tools/platforms.py`). This document says what such a claim means and why.

## A claim names kernels, not a distribution

MXFS is a kernel module built by DKMS against the kernel it will run on, and
it adapts to that kernel's API at build time (`pal/linux/kcompat_probe.sh`
writes `MXFS_HAVE_<API>` for each API the kernel's headers declare and, where
it matters, export). Two kernels that answer the probes differently compile
different MXFS code. So what a verification proves is bounded by the kernel it
ran on, not by the distribution's name:

- **RHEL** reports 5.14 for every RHEL 9 minor release and backports newer
  block, VFS and iomap APIs into each one. 9.2 carries far fewer than 9.8. A
  minor release is a different build.
- **Ubuntu LTS** ships a GA kernel and then hardware-enablement (HWE) kernels
  in point releases; a new install of a later point release boots the HWE
  kernel.
- **Proxmox VE** carries more than one kernel series at once (the ISO's, the
  default, an opt-in newer one).
- **Debian stable** keeps one kernel series across its point releases, so its
  claim is the least ambiguous.

A released platform's `kernels` field and its name therefore list exactly the
kernels verified, the README lists them in a table, and anything else is
stated as untested. Someone who builds MXFS for a kernel outside the claim and
sees it fail has found an unclaimed kernel, not a broken release.

## A claim names architectures

`arch` lists the CPU architectures, by Debian name. The packages carry
compiled tools and the module is built per architecture, so a verification on
one says nothing about another. `verified` holds one record per architecture;
`check` requires every listed architecture verified at the release's version,
and refuses one that `scripts/release.sh` builds no packages for.

## Open: widening a claim beyond the kernels runtime-tested

Today every claimed kernel is runtime-tested. That does not scale to a range
such as "RHEL 9.4 through 9.8". The intended rule:

1. A platform's claim is a list of kernel lines, the oldest being its floor.
2. Every claimed kernel line is build-checked (a container per line; RHEL keeps
   each minor's `kernel-devel` in its vault repositories).
3. Each build check yields a fingerprint: `LINUX_VERSION_CODE` plus the set of
   `MXFS_HAVE_<API>` the probes found. Kernels with the same fingerprint compile
   the same MXFS code, so one runtime verification covers them all. **Every
   distinct fingerprint in the claim is runtime-verified at least once.** An
   older minor with less backported technology shows up as a different
   fingerprint and cannot ride on a newer one's test.
4. The DKMS build could print a notice when it builds for a kernel whose
   fingerprint is outside the claim.

Not yet implemented: `platforms.py` records one verification per architecture,
not per fingerprint, and the build checks print the probe set without
recording it.
