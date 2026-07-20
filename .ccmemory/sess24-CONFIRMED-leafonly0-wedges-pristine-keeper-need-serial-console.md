---
name: sess24-CONFIRMED-leafonly0-wedges-pristine-keeper-need-serial-console
description: sess24 CONFIRMED on PRISTINE keeper EF6000F0 (no code changes): dir_postread_leaf_only=0 ELIMINATES both dir corruption faces (uf=0,hole=0) but HARD-…
metadata:
  type: project
---

## sess24 — leaf_only=0 wedge CONFIRMED on the pristine keeper (confound resolved)

### Decisive clean test (build EF6000F0, ZERO code changes, fresh 8-node boot)
`MXFS_EXTRA_MODARGS="dir_postread_reread=1 dir_postread_leaf_only=0"`, `./run.sh 8 tcp dir_reuse_coherency`:
- **uf=0, hole=0** on ALL nodes — leaf_only=0 (re-read stale dir DATA blocks before RMW) ELIMINATES both corruption faces (use_free stale-RMW-base corruption AND stale-leaf DABUF-HOLE). The coherency fix is REAL and storage is coherent (cache=none/shareable/write-through).
- **Nodes 2-8 HARD-WEDGE** (network-dark, no ping, no SSH) -> all peers' dir-lock acquires deadlock -> rc=-110 (exactly 60 retries × ACQUIRE_WAIT = 184s) -> SHUTDOWN. Reproduced TWICE on the pristine keeper. So the wedge is intrinsic to **leaf_only=0's bulk dir-DATA-block FUA re-read under 8-node contention**, NOT my (now-reverted) DLM changes. (My reverted asymmetric-MHT/fair-grant ALSO wedged, separately, even at default params/4 nodes — two distinct wedge sources; both avoid for now.)

### Why leaf_only=0 wedges (hypothesis, UNVERIFIED — stack not captured)
The postread hook (xfs_da_btree.c ~3796-3906) FUA-re-reads EVERY stale dir DATA buffer encountered during an EX-held op (incl. lookup/freescan scans, not just the one RMW target). Re-reading a buffer (xfs_buf_relse + xfs_trans_read_buf_map) mid-dir-operation while holding the dir ILOCK and possibly other dir-block buffer locks, under heavy cross-node BAST/drain traffic, deadlocks (circular buffer-lock / drain-vs-reread wait). Default keeper (leaf_only=1) does NOT wedge — it corrupts instead. So the fix is to re-read FAR fewer blocks: ONLY the specific data block about to be RMW'd (demand-driven, Patch 5), not every stale data buffer.

### Wedge stack capture is BLOCKED — setup needed for next session
The nodes go fully network-dark on wedge, so SSH/dmesg polling cannot capture the hang stack (tried hung_task_timeout=8s + rapid poll: nodes died before capture). The guest kernel console is NOT on the serial pty (no `console=ttyS0` in cmdline), so `cat /dev/pts/N` captured 0 bytes. TO CAPTURE THE WEDGE STACK:
1. In each guest: add `console=ttyS0,115200` to GRUB_CMDLINE_LINUX (/etc/default/grub) + `update-grub`, reboot.
2. In libvirt domain XML (`virsh edit testN`): give `<serial type='file'><source path='/var/log/.../testN-serial.log'/>...` (or add `<log file=.../>` to the pty serial) so kernel console + NMI-watchdog/hung-task stacks land in a file that survives the wedge.
3. Re-run leaf_only=0; the hardlockup/hung-task stack in the serial log reveals the exact deadlock to fix (or confirms Patch 5 avoids it).

### Path forward (unchanged): Patch 5 demand-driven reread
Keep leaf_only=1 default (cheap, no wedge, but corrupts) and add a TARGETED coherent re-read of ONLY the RMW data block in xfs_dir2_node_addname_int after xfs_dir3_data_read (line ~1959) before xfs_dir2_data_use_free, plus removename + the authoritative readdir/lookup sites (GPT: readers must not return stale results). If O(1)-per-modify re-read does NOT wedge, that's the fix; then tackle the separate PR-reader fairness (carefully, 4/tcp-validated each step). Full design [[sess24-gpt5.5-dlm-fairness-and-demand-reread-design]]; state [[sess24-FINAL-state-leafonly0-wedges-need-demand-reread-patch5]].

### Keeper unchanged: EF6000F0 (tree restored; all sess24 code experiments reverted; only tests/setup/prep_node.sh flushbufs hygiene kept).
</body>
