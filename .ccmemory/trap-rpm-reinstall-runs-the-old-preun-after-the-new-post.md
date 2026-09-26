---
name: trap-rpm-reinstall-runs-the-old-preun-after-the-new-post
description: TRAP (0.89.92): dnf reinstall runs the new %post BEFORE the old %preun; an unconditional 'dkms remove' in %preun deleted the module just built.
metadata:
  type: feedback
tags: [packaging, rpm, dkms, trap]
---

RPM transaction order for reinstall/upgrade: new package %pre/%post, THEN old package %preun/%postun. mkrpm.sh's %preun ran 'dkms remove -m mxfs -v %{version} --all' unconditionally, so 'dnf reinstall mxfs' of the same version deleted the module the new %post had just built: 'modprobe: FATAL: Module mxfs not found'. Only surfaced when packaged_round started forcing a reinstall of a same-version candidate.

Rule for any RPM scriptlet that undoes install work: gate it on "$1" = 0 (erase). Clean up OTHER versions in %post instead. dpkg orders the other way (old prerm before new postinst), so the .deb never showed it — do not infer RPM behaviour from the Debian package.
Also: apt/dnf treat an already-installed same version as "nothing to do"; a harness re-testing a rebuilt candidate of the same version must force --reinstall and drop the DKMS registration first, or it tests the earlier build. tests/rpm_lifecycle.sh covers erase/install/upgrade/reinstall/erase.
