---
name: feedback_never_destroy_all_vms
description: NEVER destroy all VMs on PVE nodes — only destroy VMs on the specific storage being rebuilt
type: feedback
---

NEVER run a blanket `qm destroy` loop across all VMs on a PVE node. The user runs VMs on multiple storage backends (local, local-lvm, mxfs). Destroying all VMs wipes unrelated work.

**Why:** User had 4 active OS image builds running on local storage. A blanket destroy loop killed them all when only the MXFS storage VMs needed cleanup.

**How to apply:** Before destroying any VM, check which storage its disks are on (`qm config <vmid> | grep -E 'scsi|virtio|ide|sata'`). Only destroy VMs whose disks are on the storage being rebuilt. When in doubt, ASK the user which VMs to destroy.
