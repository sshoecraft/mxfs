---
name: trap-dracut-bakes-modules-load-d-modules-and-their-modprobe-options-into-the-initramfs
description: TRAP (0.90.4, RHEL 9.8): /etc/modules-load.d/mxfs.conf made dracut copy mxfs + a stale modprobe.d into initramfs; a force_transport edit was lost eve…
metadata:
  type: feedback
---

On dracut distributions (RHEL/Alma/Rocky, anything using dracut), every initramfs regeneration — including the one the DKMS install triggers when the package is installed — pulls each /etc/modules-load.d entry into the initramfs WITH the module file and /etc/modprobe.d as it stood at that moment. Early boot then loads mxfs from the initramfs with those baked options, and the real root's /etc/modprobe.d is never consulted for it.

Measured: packaged_round TRANSPORT=caw on alma9-1/2 edited force_transport=1 -> 0 and reloaded (runtime 0), rebooted: both nodes came back force_transport=1 and mounted TCP. lsinitrd showed etc/modprobe.d/mxfs.conf, etc/modules-load.d/mxfs.conf, usr/lib/modules/<krel>/extra/mxfs.ko.xz. lsinitrd file dates (Aug 14) are dracut's reproducible timestamps, NOT the build time — the module inside was the fresh DKMS build.

Fix shipped 0.90.5: the RPM installs /etc/dracut.conf.d/mxfs.conf `omit_drivers+=" mxfs "` and %post rebuilds any initramfs that still contains mxfs.ko. With it the initramfs's systemd-modules-load logs "Failed to find module 'mxfs'" (harmless, unit deactivates successfully) and the real root loads mxfs with the current options.

initramfs-tools (Ubuntu, Debian, Proxmox) does not read modules-load.d, so those platforms were never affected. Any other option a user changes in /etc/modprobe.d (target_cache_protected, ...) had the same exposure on RHEL.
