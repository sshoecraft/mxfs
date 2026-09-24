---
name: user-a-platform-release-claims-exact-kernels-never-a-whole-distribution
description: USER 2026-09-24: a platform release claims exactly the kernels verified (e.g. RHEL 9.8 / 5.14.0-687.49.1), never "RHEL 9"; anything else is stated un…
metadata:
  type: user
tags: [platforms, release, rhel, kernels, user-decision]
---

The user chose (2026-09-24, while releasing 0.89.84) that a release names the exact kernels it was verified on — registry name and `kernels` field, README table, release notes — and says every other kernel is untested, even on the same distribution.

Why, in the user's words: "If we get somebody who clones it and builds it for a different version and it fails, they're gonna say 'it's not ready'."

Why it is technically required: MXFS probes each kernel's API at build time (pal/linux/kcompat_probe.sh), so kernels that answer differently compile different code. Every RHEL 9 minor reports 5.14 with different backports (9.2 has far fewer than 9.8); Ubuntu 24.04 point releases install HWE kernels (6.11+) that were never tested; PVE 9 carries 6.17 and 7.0, which probe differently (7.0 has IOMAP_DIO_BOUNCE, 6.17 does not).

How to apply:
- Never write "RHEL 9" / "Ubuntu 24.04" as a claim without the kernel(s). Every claimed kernel gets a runtime round (tests/packaged_round.sh; on PVE use KERNEL=<krel> to pin one).
- Widening a claim to a range is an OPEN design in docs/platforms.md: build-check every kernel line, runtime-verify once per distinct probe fingerprint (LINUX_VERSION_CODE + MXFS_HAVE_* set). Not implemented yet.
- rhel9-1/rhel9-2 are stuck on RHEL 9.2 (no subscription) — they are the pair for a future 9.2 claim, not usable for 9.8. AlmaLinux 9.8 (alma9-1/2) stands in for current RHEL 9.
