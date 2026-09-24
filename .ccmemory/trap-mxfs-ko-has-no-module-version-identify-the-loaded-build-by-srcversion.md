---
name: trap-mxfs-ko-has-no-module-version-identify-the-loaded-build-by-srcversion
description: TRAP (0.89.84): mxfs.ko declares no MODULE_VERSION, so /sys/module/mxfs/version never exists; identify a DKMS build by srcversion vs /var/lib/dkms tr…
metadata:
  type: feedback
tags: [packaging, dkms, harness, module-identity, trap]
---

tests/packaged_round.sh was written asserting `cat /sys/module/mxfs/version` == the package version. Its first run failed at "loaded= not 0.89.84" although DKMS had built and loaded the right module: nothing in the tree declares MODULE_VERSION (grep finds none), so the sysfs file does not exist and `modinfo -F version` is empty. The version lives only in packaging (VERSION file, dkms.conf, the tools' -D flags).

How to identify which build is loaded instead: three srcversions must agree — `/sys/module/mxfs/srcversion` (loaded), `modinfo -F srcversion mxfs` (the installed file modprobe resolves), and `modinfo -F srcversion /var/lib/dkms/mxfs/<V>/$(uname -r)/$(uname -m)/module/mxfs.ko*` (what DKMS built for version V) — plus `dkms status mxfs/<V> -k $(uname -r)` saying `installed`. packaged_round.sh's is_dkms_build does this now.

Corollary: srcversion does not change when only VERSION changes (0.89.83 -> 0.89.84 tree build kept 10A5B93816D92E3B84B6FFE), and a container build check reproduces the DKMS srcversion exactly for the same kernel (AlmaLinux 9.8: 44881E497A6D901321DF7D6 in both), which is a cheap cross-check that a node runs the build that was checked.
