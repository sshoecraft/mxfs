---
name: user-lab-dir-is-a-build-recipe-site-specifics-live-in-the-lab-file
description: USER 2026-09-24: lab/ tells Claude how to BUILD each test platform (osimager spec + post-build); no IPs/hostnames in tree — they go in ~/.config/mxfs…
metadata:
  type: user
---

The user's framing of `lab/`: "the VM list is a list of infrastructure that MXFS can use to test on" — a Claude session told "verify against OS X" must be able to read `lab/vms.md` + `lab/README.md` and build that platform's pair from scratch. It is a catalog of recipes, NOT an inventory of what currently runs on clyde.

- **No IP addresses, host names, storage portals or home-directory paths in the tree.** "Each user is going to have a different setup." Site specifics live in `~/.config/mxfslab/lab`, read via `tools/mxfs_lab.sh` (`storage`, `pair <platform>=A,B`, `addr`, `qemu monitor_dir`).
- **Never point docs at `/src/...` of another project.** MXFS is public; osimager is on PyPI (`pip install osimager`, docs at sshoecraft.github.io/osimager). User: "providing a path to a src directory the user doesnt have access to".
- **What osimager does is osimager's business** — e.g. the QEMU CPU model (`cpu_model` host when KVM) is not an MXFS doc concern. If a spec is missing (alma 9.8 as of osimager 1.9.1), that is an osimager gap to report, not something to paper over in MXFS.
- Rows are keyed by `data/platforms.json` platform keys; the claimed kernel is not duplicated in `vms.md`.

Trap found alongside: osimager's qemu post-build registers the VM with libvirt using `LIBVIRT_DEFAULT_URI` or the uid default, so an unprivileged build lands in `qemu:///session`; clyde had 35 stale session defs (incl. duplicates of test1..32 pointing at the same disks) until removed 2026-09-24. Build with `-D libvirt_uri=qemu:///system`.
