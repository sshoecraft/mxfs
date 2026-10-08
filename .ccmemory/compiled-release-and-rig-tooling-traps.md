---
name: compiled-release-and-rig-tooling-traps
description: Release/rig tooling traps: util-linux 2.39 hides errorfc, defects.py -w replaces evidence, empty dist dir skips build, host glibc, exact-kernel claim…
metadata:
  type: feedback
tags: [compiled, release, packaging, rig, defects, platforms]
---

Release, packaging and rig-tooling traps, each learned from a lost hour or a wrong conclusion. The inputs share one shape: a tool or marker looks like it did the thing and did not.

**Mount refusal reasons are invisible on the rig (0.90.65).** MXFS sends a refused mount's reason through `errorfc(fc, ...)` with EPERM. On Ubuntu 24.04 (util-linux 2.39.3) mount(8) prints only "permission denied. dmesg(1) may have more information", and the errorfc text is not in dmesg either. `logfc()` printk's only for a context with no log (classic mount(2)); an fsopen() context stores the message for read() on the context fd, and util-linux 2.39 mounts through fsopen/fsconfig without reading it. 2.40+ does (PVE 9 / Debian 13 ships 2.41).
- Verify any errorfc/invalfc message on a host with util-linux >= 2.40 (the nested pve9 pair); never conclude it is broken from the rig's mount(8).
- Keep the reason also in the module's own kernel-log line (`mxfs_pal_log`); on 2.39 that is the only place an operator finds it.
See [[trap-util-linux-2-39-mounts-through-fsopen-but-never-prints-the-kernels-errorfc-message]].

**`tools/defects.py update -w` replaces evidence (0.90.39).** It looks like an append because the next-step flag has `-a`, but evidence has no append form. Adding 20 GiB board measurements to `D-TAUTH-RECOVERY-SCANS-SCALE-WITH-LUN-SIZE-NOT-LEDGER-USE` erased its 1 TB takeover measurement, sizing pointers and consult reference; recovered only because the text was still in context from an earlier `show`.
- Run `tools/defects.py show <id>` first, pass `-w "<old evidence> ===== <new evidence>"`, then `show` again to check.
See [[trap-defects-py-update-w-replaces-the-evidence-field-it-does-not-append]].

**An existing `dist/<V>` is not a finished build (0.90.39).** `tests/full_verify.sh` tested `[ ! -d dist/$V ]` to decide packages were built. A chain stopped while `release.sh` was starting left an empty `dist/0.90.39`; the packages step then ran nothing and printed nothing, and all 12 packaged rounds (four platforms, both configurations) failed in about a second with `FAIL: missing .../mxfs_0.90.39_amd64.deb`. The script still exited 0 because its last command was a summary grep. About an hour lost.
- Fix: a finished build is a `dist/$V` whose `SHA256SUMS` verifies (release.sh writes it last); the exit status counts failed platform steps.
- General: a directory or marker existing does not prove the step that creates it finished; test for the artifact written last. When a chain's rounds all fail within a second, read one round's first FAIL line before anything else.
See [[trap-an-empty-dist-version-directory-made-full-verify-skip-the-package-build]].

**Host-built packages ship tools that will not start on target (0.89.77).** `make package` / `packaging/mkdeb.sh` on clyde link `mkfs.mxfs` and `chk_mxfs` against glibc 2.39 and require GLIBC_2.38 (`objdump -T | grep GLIBC_`). PVE 8 / Debian 12 has 2.36, RHEL 9 has 2.34, so the package installs and the tools then refuse to run. The DKMS module is unaffected (built on target).
- Release packages come only from `scripts/release.sh`, which builds in a container of the oldest targeted distribution: `debian:bookworm` for both .debs (tools need 2.34), `almalinux:8` for the RPM (tools need 2.14). Never attach a host-built package to a release.
- Docker's bridge network on clyde has no outbound TCP (pulls work, apt/dnf inside do not); build containers use `--network host`. Do not fix clyde's firewall for this; the rig depends on it.
- EL8 rpmbuild fails on an empty debugsource list when tools compile without `-g`; the spec needs `%global debug_package %{nil}`.
- `mkrpm.sh` drifted from `mkdeb.sh` (no `mxfs_admin`, no udev rule, man pages by name). A tool, page or config added to one builder goes into the other.
See [[trap-a-release-package-built-on-clyde-ships-tools-that-refuse-to-start-on-proxmox-8-and-rhel]].

**A platform release claims exact kernels (user decision 2026-09-24, release 0.89.84).** The registry name and `kernels` field, README table and release notes name the exact kernels verified (e.g. RHEL 9.8 / 5.14.0-687.49.1), never "RHEL 9" or "Ubuntu 24.04"; every other kernel is stated untested, even on the same distribution. User's reason: a cloner who builds for another version and fails concludes "it's not ready". Technical reason: `pal/linux/kcompat_probe.sh` probes each kernel's API at build time, so kernels answer differently. RHEL 9 minors all report 5.14 with different backports; Ubuntu 24.04 point releases pull HWE kernels (6.11+); PVE 9 carries 6.17 and 7.0, which probe differently (7.0 has IOMAP_DIO_BOUNCE, 6.17 does not).
- Every claimed kernel gets a runtime round (`tests/packaged_round.sh`; on PVE `KERNEL=<krel>` pins one).
- Widening to a range is an open design in `docs/platforms.md` (build-check every kernel line, runtime-verify once per distinct probe fingerprint: LINUX_VERSION_CODE + MXFS_HAVE_* set); not implemented.
- rhel9-1/rhel9-2 are stuck on RHEL 9.2 (no subscription), reserved for a future 9.2 claim; AlmaLinux 9.8 (alma9-1/2) stands in for current RHEL 9.
See [[user-a-platform-release-claims-exact-kernels-never-a-whole-distribution]].
