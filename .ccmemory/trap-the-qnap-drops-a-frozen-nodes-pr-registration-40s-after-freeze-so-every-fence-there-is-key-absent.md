---
name: trap-the-qnap-drops-a-frozen-nodes-pr-registration-40s-after-freeze-so-every-fence-there-is-key-absent
description: TRAP (0.89.79): the QNAP silently purges a frozen initiator's PR key ~40 s after freeze (PRgen unchanged); death lands ~60 s, so every fence there is…
metadata:
  type: feedback
tags: [fencing, qnap, pve, lu-reset, pr]
---

Measured with tests/tcp_peer_freeze_death.sh (virsh suspend of one node of a 2/tcp cluster, READ KEYS sampled every 2 s by the survivor): both keys present at -2.4 s; the frozen node's key GONE at +41.8 s; PR generation 0x1b84 unchanged throughout. The survivor declares death at ~+60 s (40 s TCP grace after the disconnect is seen), so PREEMPT AND ABORT never has a key to name on this target.

**Consequence:** on the QNAP, the only certifying fence for a hung node is the witnessed LU reset (kind 24), which dlm/scsipr.c admits only on audited kernels. Proxmox kernels were not admitted until 0.89.80, so on 0.89.79 a hung PVE node froze its cluster indefinitely (P238-FENCE-LURESET verdict=kernel-unaudited, P238-FENCE-BLOCKED). The Ubuntu rig (6.8.0-101, exact pin row) recovered the same freeze at +78 s. The PVE release rounds never killed a node, so none of them could see it.

**How to apply:**
- Any release claim about node-death recovery needs the freeze test ON THAT PLATFORM (PREP=pve for Proxmox); a rig pass says nothing about a kernel the pin treats differently.
- A fence change that assumes the victim's key is still registered is untestable on the QNAP; test key-present fencing on a conforming target (LIO on serv or test32's bench LUN).
- 0.89.80 admits kernels by pal/linux/libiscsi_fingerprint.sh (TMF declaration shape, build release == running release, denylist). A new distro kernel whose fingerprint differs is refused and freezes on the QNAP the same way — check scripts/pve_libiscsi_crosscheck.sh on a new PVE kernel before claiming it.
- The pve9 nodes' DKMS builds each kernel; `PVE_KBUILD_OK ... libiscsi_fp=` in scripts/pve_kbuild_check.sh shows the fingerprint a build carries.
