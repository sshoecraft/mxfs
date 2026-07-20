---
name: sess24-leafonly0-wedge-correlates-p103-reload-storm-serial-setup-done
description: sess24: serial console capture NOW SET UP on test2-4 (console=ttyS0 in guest grub + libvirt <log file> to /var/log/libvirt/qemu/testN-serial.log). le…
metadata:
  type: project
---

## sess24 — wedge diagnosis: P103 reload storm; serial capture now available

### INFRA NOW IN PLACE (reusable): serial console capture on test2, test3, test4
- Guest grub: `console=ttyS0,115200 nmi_watchdog=1` added to GRUB_CMDLINE_LINUX in /etc/default/grub (update-grub run). Persists across reboots.
- libvirt: each domain's `<serial>` has `<log file='/var/log/libvirt/qemu/testN-serial.log' append='off'/>` (in the INACTIVE/persistent config; takes effect on destroy+start). Survives the wedge (file on the HOST).
- Read with `sudo tail /var/log/libvirt/qemu/test2-serial.log`. To extend to test5-8, repeat the grub edit + add the `<log>` element via dumpxml/python/define (script in scratchpad test{2,3,4}.xml).

### What the captured wedge shows (4/tcp leaf_only=0, pristine keeper EF6000F0)
All of test2,3,4 froze at ts ~72-73s in the MIDDLE of a dense FLOOD of:
`mxfs: P103-RELOAD-REUSE-ADOPT ino=<AG-spaced numbers 2M,4M,6M...14M> mem_size=8192/12288 disk_size=0 incore_gen=X disk_gen=Y disk_mode=00 — adopting peer's reused incarnation (gen differs)`
Hundreds of these in ~5s across AG-spaced inode numbers (a mass inode-cluster reload sweep). Then the serial output just STOPS — NO hung-task/INFO:task-blocked/hardlockup/Call-Trace printed. So the wedge is a LIVELOCK or a hard freeze during/after this storm, not a clean D-state lock cycle the hung-task detector would catch.

### P103 path = xfs/xfs_mxfs_dlm.c:9113-9136 (in the inode reload-from-disk path)
Fires when reloading an in-core REG inode whose disk dinode has di_size==0 AND di_gen != incore i_generation (genuine inode-number REUSE): it ADOPTS the peer's reused/freed incarnation (xfs_inode_from_disk). disk_mode=00 = the disk slot is FREE. This is the dir_reuse rm-rf churn (each round frees ~800 inodes that peers realloc). At DEFAULT (leaf_only=1) the 4/tcp test PASSES (no freeze), so `leaf_only=0` specifically AMPLIFIES this reload sweep into a freeze.

### CAVEAT / next questions
- The freeze may be partly a console=ttyS0 ARTIFACT: hundreds of P103 printk lines to a 115200-baud serial is synchronous + slow (~ms each) → seconds of CPU blocked → could itself trip the watchdog. BUT the wedge ALSO happens WITHOUT console=ttyS0 (earlier runs, no serial), so the underlying storm/freeze is real; serial may worsen it. To separate: re-run with the P103 pr_warn rate-limited or removed, OR boot WITHOUT console=ttyS0 but with netconsole (won't survive net death) — or just accept the storm is the signal.
- WHY does leaf_only=0 trigger a mass inode reload sweep? Re-reading dir DATA blocks shouldn't reload inodes directly. Hypothesis: the extra FUA re-reads change timing → more cross-node BASTs → a mass reload cascade; OR the data re-read path invalidates/reloads inodes referenced by the re-read dirents. INVESTIGATE the call chain from the postread data-block re-read (xfs_da_btree.c ~3882 xfs_trans_read_buf_map) to mxfs_dlm reload_inode.

### Bottom line for the relay
- Keeper UNCHANGED: EF6000F0 (all sess24 code reverted; tree byte-identical to sess23 keeper). Only tests/setup/prep_node.sh flushbufs + the test2-4 serial-capture infra added.
- The coherency fix (leaf_only=0) is CORRECT (kills uf=0/hole=0) but triggers a wedge via a P103 inode-reload storm — must be tamed. Path: Patch 5 demand-driven RMW-only reread (avoid the bulk reload trigger) — see [[sess24-gpt5.5-dlm-fairness-and-demand-reread-design]], [[sess24-leafonly0-wedges-at-4-nodes-too-fundamental-reread-deadlock]].
- DLM PR-reader fairness still needed but the asymmetric-MHT/fair-grant approaches WEDGE (reverted) — re-approach per GPT Patches 1-4 with 4/tcp validation each step.
</body>
