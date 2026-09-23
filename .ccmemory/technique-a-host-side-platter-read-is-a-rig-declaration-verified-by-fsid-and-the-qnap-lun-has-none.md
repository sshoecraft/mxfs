---
name: technique-a-host-side-platter-read-is-a-rig-declaration-verified-by-fsid-and-the-qnap-lun-has-none
description: TECHNIQUE (0.89.8, D-A-HARNESS-CAN-MEASURE-THE-WRONG-DEVICE): /home/steve/disk.img is NOT the 2/tcp LUN; host reads go through tools/mxfs_host_image.…
metadata:
  type: feedback
tags: [harness, device-identity, host-image, qnap, 2tcp]
---

# A host-side platter read is a rig declaration verified by fsid; the qnap LUN has none

**The trap (s70/s71):** 34 harnesses read the LUN's platter from `/home/steve/disk.img` (default of `MXFS_SCST_IMG`, `MXFS_BACKING_IMG`, `LUN_IMG`, `FLN_BACKING`, `DBLALLOC_BACKING`). That file is the fileio image of the earlier SCST rig (envelope fsid 5d08fe5a-dcca-4a29-8913-bb7f6c566bb2, /etc/scst.conf now names disk-1.img/disk-2.img). On the qnap rig the LUN lives on the QNAP and NOTHING on clyde backs it, so every such read — `chk_mxfs -v`, `mxfs_agi_dump.py`, `mxfs_logslice.py`, `--free-query` — was a well-formed measurement of another filesystem printed as a verdict about MXFS (d_intents_2tcp_open_efi asserted "every obligation extent reads FREE on the platter" from it).

**The fix (0.89.8):**
- `data/rigs.json[<tag>].host_image` declares the host file/device backing the LUN; the qnap declares `null`.
- `tests/lib/rig.sh mxfs_host_image [node]` / `tools/mxfs_host_image.sh [node]` (for harnesses without the library; prints the path alone on stdout, ABORT text + rc 2 otherwise): the image's envelope fsid, read direct from the file (same 4 KiB sector-0 read as tests/setup/dev_identity.sh), must equal the LUN's — the node's resolved device, else `.cluster_marker.json` fsid. `MXFS_HOST_IMAGE_PATH` overrides the path for one run but never the identity check.
- Call sites: `IMG=$(tools/mxfs_host_image.sh) || { echo "$IMG"; exit 2; }`.
- On a rig without a host image, read the platter FROM A NODE: `mxfs_chk_on_node <node> <file> <what> [args]` (rig.sh, unmounted node, ABORTs on the rc-4 "held open exclusively" refusal because that is the wrong node, not a verdict) or `tools/chk_mxfs --query-only --free-query` on a mounted node (0.89.7), or a fresh-booted unmounted node (fence_crash_cuts reads the quiescent platter from B's boot).

**Not converted, deliberately:** scripts/scst_setup.sh and scripts/lio_tcm_setup.sh (they CREATE a fileio target from the image — the declaration's source) and scripts/clyde_preflight.sh (host headroom, not an MXFS measurement).
