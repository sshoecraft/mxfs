---
name: trap-insmod-skips-modprobe-d-options-so-a-test-module-mount-is-refused-and-the-probe-runs-on-the-bare-dir
description: TRAP (0.89.91): insmod of a test mxfs.ko skips the package's modprobe.d options (target_cache_protected=1): mount refused, probe ran on the bare dir.
metadata:
  type: feedback
tags: [rig, module, trap]
---

Swapping a hand-built mxfs.ko onto a package node with `insmod` does not apply /etc/modprobe.d/mxfs.conf (the package sets `force_transport=1` and `target_cache_protected=1`). Without target_cache_protected the RW mount is refused (P-DOMAIN-REFUSED, mount rc=32), and a test that then touches /mnt/mxfs runs on the underlying root-fs directory and reports a meaningless result.

Do: `insmod mxfs.ko $(sed -n 's/^options mxfs //p' /etc/modprobe.d/mxfs.conf | tr '\n' ' ')`, and gate every probe on `grep -q ' /mnt/mxfs mxfs ' /proc/mounts || exit 1`. Restore with rmmod + modprobe.

Related: a lone mount on a LUN with an unclean slot runs whole-cluster bootstrap and waits the 62 s death timeout before replay — a mount budget under ~150 s is killed by `timeout` and the mount is aborted after it completes.
