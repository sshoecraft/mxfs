---
name: trap-osimager-proxmox-builds-never-connect-over-ssh-so-every-build-times-out-on-any-storage
description: TRAP: a packer build logging "SSH communicator to connect: <no value>" never connects and times out (osimager proxmox ssh_host); judge storage by ins…
metadata:
  type: feedback
---

**Seen 2026-10-06 on the physical pair (pve1/pve2, PVE 9).** Every `mkosimage proxmox/<loc>/<spec>` build logged `Using SSH communicator to connect: <no value>` and ended `rc=1` with "Timeout waiting for SSH" after packer's 45 min `ssh_timeout`, on local storage as well as on /mnt/shared. The guests were installed and sshd answered; packer never dialled them.

**Cause (osimager, confirmed and fixed by the owner the same evening):** `osimager/data/specs/ssh/spec.json` rendered `ssh_host` as the packer template `{{ .Host }}` for platform `proxmox`; packer interpolates a missing key as the literal `<no value>`, and the Proxmox builder asks the guest agent for the address only when `ssh_host` is empty. The fix is `''` for platform `proxmox`. Owner: "the mkosimage problem of not getting an ip is fixed and builds complete 100% now".

**How to apply.**
- A build tool's own failure can look exactly like slow storage (a timeout at its own bound). Before reading a build's rc as a verdict on the storage under it, check its log for the step it died in; `<no value>` in a packer line is an unrendered template, not a host.
- Judge the storage by the install itself: the guest agent answering with the build's own hostname (`qm agent <id> get-host-name`; the installed system sets it, the installer does not). `scripts/pve_pair_builds.sh` records "installed after N s" for every build, and `STOP_INSTALLED=1` stops each build there when only install time is being measured.
- Packer's 45 min `ssh_timeout` is a real bar for the owner's workflow: an install slower than that is destroyed by packer, whatever the storage.
