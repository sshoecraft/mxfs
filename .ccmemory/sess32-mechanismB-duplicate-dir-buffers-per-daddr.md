---
name: sess32-mechanismB-duplicate-dir-buffers-per-daddr
description: sess32: P-POSTRMW-BP shows 8 DIFFERENT bp pointers for the SAME dir daddr in ~100ms = mechanism B (duplicate/churned xfs_buf). Stale instance destage…
metadata:
  type: project
---

## sess32 — mechanism B evidence: duplicate/churned dir-block buffers

### Probe (build 06F56794, dir_postrmw_probe=1 + dirwr=1): P-POSTRMW-BP logs bp pointer + lseq/wseq per in-core dir data block right after each create's RMW.

### FINDING (test7, daddr 12559416, 8 consecutive creates in ~100ms):
8 lines, ALL `disk_extra=0 done=1 lseq=0 wseq=0`, but **8 DIFFERENT bp pointers** (ffff895e40681340, ...40681c00, ...440f1a40, ...440f0a80, ...441aae00, ...440f0000, ...441abdc0, ...441aa8c0). The dir DATA block buffer for ONE physical daddr is a DIFFERENT xfs_buf on nearly every access = duplicate/churned buffers (mechanism B per GPT consult #2 Q3). A stale prior instance still referenced by the AIL gets destaged by xfsaild → reverts a peer's add (P-WMERGE MERGE-NEEDED). Consistent with POST-RMW always-superset (the buffer WE rmw is fresh; a DIFFERENT stale instance is what destages).

### CAVEATS
- The heavy probe (per-create xfs_buf_incore + raw disk read over all blocks) AMPLIFIED the loss to 786/800 (vs keeper 799) — timing perturbation. The multiple-bp is real (xfs_buf_incore only finds existing buffers, never creates) but confirm without probe load next session.
- lseq=0/wseq=0 on all: either dir creates don't bump b_mxfs_logged_seq, or these are freshly-read peer-modified blocks. Verify whether dir2_data_log bumps logged_seq.
- xfs_buf_stale(sbp) at xfs_da_btree.c:3693 is ONLY the torn-buffer read-retry path (msleep loop) — NOT the normal-create churn source. Churn source UNKNOWN (candidates: xfs_buf LRU free+recreate under memory pressure; some mxfs invalidate that removes from rhashtable; freed+realloc of the dir block).

### IMPLICATION FOR THE FIX
GPT's RELEASE-side AIL-retire still addresses this: if every dir BLI is pushed OUT of the AIL at EX release, no stale buffer instance (ghost or otherwise) can be re-flushed after a peer supersedes the block. NEXT SESSION: (1) confirm multiple-bp WITHOUT the heavy probe (lighter probe: log bp only for one watched daddr); (2) find the churn source (instrument xfs_buf alloc/free/stale for dir daddrs); (3) implement release-side AIL-retire (xfs_mxfs_dlm.c release fence ~L7857, after data_durable loop: ensure dir BLIs leave the AIL) — deadlock-careful, default-off param. 

### Build 06F56794 = keeper + probes (all default-off). Cluster: reboot to clear. CRITERIA NOT MET. [[sess32-DECISIVE-A-vs-B-late-destage-toctou]] [[sess32-HEAD-handoff]]
</body>
