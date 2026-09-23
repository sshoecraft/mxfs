---
name: trap-node-journals-are-volatile-a-failed-rejoin-mounts-evidence-survives-only-in-the-libvirt-serial-log
description: TRAP (sess516): test VMs keep a volatile journal + small dmesg ring; a lap that virsh-destroys the node erases the previous boot's kernel log. Read /…
metadata:
  type: feedback
---

# TRAP: node kernel logs do not survive the next lap

- The test VMs' journald is volatile (`/run/log/journal`, Storage=auto with no persistent dir) and `dmesg` wraps within ~15 minutes of chain activity. A `virsh destroy` (every death lap) discards the previous boot's journal entirely.
- sess516: `domain_admission_matrix.sh` rejoin failed `REJOIN_RC=32` at 09:45:50Z; by the time anyone looked (10:14Z) test1's ring had wrapped past the window and test2 had been destroyed by the next lap. `journalctl -k --since/--until` on both nodes returned `-- No entries --`.
- What survived: `/var/log/libvirt/qemu/test2-serial.log` on clyde (root-only, `sudo -n cp`), monotonic timestamps only, printk console-level lines only (alerts/errors: 'lock request failed after 60 retries', 'DLM inode lock unrecoverable', 'Corruption of in-memory data', P-SB-SUMMARY-LOCK-FAIL, P-PRKEY-RETIRED). Anchor monotonic→wallclock with a harness-stamped copy of the same line (the R-row captures carry `journalctl` wallclock).
- RULE: every harness step that can fail must save BOTH nodes' kernel window into its evidence dir at the time (the matrix rejoin now does: `rejoin_journal_<node>.txt` for NODE and PEER), with a filter that drops only the ledger-page noise (P-TAUTH-PREPARED/ACTIVATE/PAGE-MINE/HANDOFF/TAKEOVER-RETIRE/bdev_io), never a positive filter that names the lines you expect.
- Second trap the same hour: `tests/domain_admission_matrix.sh` defaults `MXFS_DEV=/dev/mapper/mpatha`; run outside the chain on the QNAP rig you MUST export `MXFS_DEV=<QNAP by-path>` (and MXFS_NODE_LIST) or every row fails rc=32 in 0 s against the wrong LUN and measures nothing.
