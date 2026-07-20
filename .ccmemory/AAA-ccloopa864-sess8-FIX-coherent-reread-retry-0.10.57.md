---
name: AAA-ccloopa864-sess8-FIX-coherent-reread-retry-0.10.57
description: sess8 FIX (0.10.57, build 78970C3C): reader-side bounded coherent re-read retry in _xfs_buf_read for multi-node dir metadata that fails read-verify C…
metadata:
  type: project
---

## sess8 (ccloop a864) — FIX for dir_reuse@32/caw: transient torn-read coherency retry (0.10.57, build 78970C3C0B2E7589FE730AF)

### FINAL PROVEN ROOT (corrected from the first sess8 memo — the "concurrent write" reading was a CLOCK ERROR; per-node dmesg timestamps are unsynchronized, `realns` wall-clock is the truth):
The writes to the failing shared bmbt leaf are SEQUENTIAL, not concurrent. Last writer before the victim read = the CURRENT EX holder growing the dir:
- wall 1783775978.3702: **rank25** (holds EX, tenure 996) writes dir ino131 bmbt leaf daddr=46051048 numrecs=19.
- wall 1783775978.3718: rank25 **P35-DIRHONOR "(bast_process drain+unlock)"** — begins BAST-triggered handoff drain (1.6ms after the write).
- wall 1783775978.4006: **rank1** acquires EX + cold-reads the SAME leaf (P59-BMBT-ROOT-KEEP DONE=0 → medium read) → **EFSBADCRC (err-74)** → xfs_btree_read_buf_block → xfs_create → xfs_trans_cancel line1068 → **Shutting down** → 32-node barrier stall → 0/32.
So: the prior EX holder rewrote the shared leaf in RAPID succession (rank25 wrote it ~15× in 250ms, nr 18→19) then handed off FAST (BAST); the new holder cold-read the leaf ~30ms later and got a TRANSIENTLY TORN image (bad CRC = block content ≠ its own stored CRC; the coherent SCST/multipath cache had not settled to rank25's final write). A later raw dump of the same block was a fully VALID bmbt leaf (magic BMA3, self-daddr ok, owner=131) → the torn state SETTLED → coherency-timing artifact, NOT durable corruption. (`old_tenure=0` in P67 = fresh reads → this is NOT the RMW-restamp laundering; disregard the earlier laundering hypothesis for THIS block.)

### THE FIX (pal/linux/xfs_buf.c, `_xfs_buf_read`): after `xfs_buf_iowait`, if the read failed EFSBADCRC/EFSCORRUPTED on a MULTI-NODE DIR METADATA buffer (`mxfs_buf_is_multinode_dir_meta`: single-map, ops ∈ {xfs_bmbt_buf_ops, dir3 data/block/leaf1/leafn/free, da3_node}) and fs not shut down, RE-READ the coherent medium a bounded number of times with a short backoff, re-running verify_read each time. `mxfs_buf_coherent_reread_verify` bounces through a kmalloc buffer (plain-bio when mxfs_fua_disable else SCSI-FUA) → memcpy into b_addr → b_ops->verify_read. The reader holds the dir EX here (just adopted), so no other node mutates the block during retries → once rank25's final write lands, the leaf is stable+valid. A genuinely-corrupt block still fails after retries (P-DIRCRC-RETRY-FAIL) → shuts down as before (cannot mask real corruption). Process-context only (xfs_buf_iowait blocked); the softirq __xfs_buf_ioend P15I path could NOT do this (in_interrupt). Module params (0644): `dir_read_crc_retries`=8 (0 disables), `dir_read_crc_retry_us`=4000 (→ max ~32ms added latency on the CRC-fail path only; inert on the happy path so cannot regress the 16 passing 32/caw cells).

### PROBES: P-DIRCRC-RETRY (each retry), P-DIRCRC-RETRY-OK (transient torn settled → fix worked), P-DIRCRC-RETRY-FAIL (durable → need a writer-side fix instead).

### TEST (in progress): `env MXFS_DEV=/dev/mapper/mpatha MXFS_TEST_ENV='DRC_STREAM=1' timeout 1800 ./run.sh 32 caw dir_reuse_coherency`. Expect P-DIRCRC-RETRY-OK at ~round5 and the run to proceed to 32/32 PASS. If P-DIRCRC-RETRY-FAIL/shutdown → torn state is durable, pivot to writer-side (ensure rank25's rapid leaf rewrites are coherently settled before the handoff unlock — e.g. wait for in-flight leaf bio completion in the bast_process drain, or force FUA/barrier on the leaf writes; and/or throttle same-LBA leaf rewrites). Criteria: dir_reuse_coherency 32/caw is the SOLE remaining gap (status board this session: 16/17 PASS, it PENDING). All other 1/2/4/8/16/32 caw cells PASS; tcp_dlm_scaling caw cells n/a (transport:tcp).
