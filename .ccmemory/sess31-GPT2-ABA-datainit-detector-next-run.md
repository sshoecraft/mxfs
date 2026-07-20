---
name: sess31-GPT2-ABA-datainit-detector-next-run
description: sess31 relay: build 63035077 = 5E706CBF(FACE B fix) + P31E-DATAINIT-ABA detector. NEXT: run dir_reuse, grep P31E — confirms GPT-5.5's get_buf/init AB…
metadata:
  type: project
---

## sess31 relay handoff — GPT-5.5 2nd consult + decisive ABA detector ready

### Build at relay = `63035077` (= FACE B fix build 5E706CBF + ONE log-only detector)
Delta from 5E706CBF: P31E-DATAINIT-ABA detector in `xfs/libxfs/xfs_dir2_data.c` `xfs_dir3_data_init()` (right after `xfs_da_get_buf`, ~line 740). LOG-ONLY, capped 800, multinode-dir-gated. Also added `#include "xfs_mxfs_dlm.h"` + `"../dlm/v5_mount.h"` there.

### What it catches (GPT-5.5 RULE-5 2nd-consult decisive detector)
`xfs_dir3_data_init` uses `xfs_da_get_buf` (get_buf, NOT a disk read) → zeroes+re-inits a fresh empty dir DATA block. The detector coherently plain-reads the physical daddr ABOUT to be zeroed; if it ALREADY holds a valid dir3 header (XDD3/XDB3) with live dirents → fires `P31E-DATAINIT-ABA ino lblk daddr disk_magic disk_owner live_dirents`. That = the get_buf/init ABA clobber: a STALE in-core data fork makes this node treat a logical dir block as NEW/hole when the PEER already materialized it at the reused daddr → init ZEROES the peer's durable committed dirents (the readdir-short / node1_f1..f12 first-wave durable loss).

### NEXT SESSION — run this FIRST (decisive RULE-4 step):
1. `cd /src/mxfs && timeout 560 ./run.sh 2 tcp dir_reuse_coherency` (no instr; cluster is mounted+healthy on 5E706CBF, just `insmod` picks up 63035077 via NFS — run.sh reloads). If test2 module wedges on prep, `bash tests/reboot_cluster.sh 2` (VMs only, NEVER clyde — RULE 2).
2. Both nodes: `dmesg | grep -E "P31E-DATAINIT-ABA|mxfs-drc-RDMISS|mxfs-drc-FAIL"`.

### INTERPRETATION (the fork in the road):
- **P31E FIRES** (live_dirents>0 at init of lblk=0): GPT's ABA root CONFIRMED — the bug is a STALE INODE DATA-FORK (this node thinks block 0 is new/hole/shortform while peer durably has it) → init clobbers. FIX → refresh the dir inode's data fork (extent map / format) at EX acquire / first-modify BEFORE any data_init can run, so the node never treats a peer-materialized block as new. (Reload the dir inode fork coherently on peer-modified acquire; current modify-refresh evicts BLOCKS but may not rebuild the FORK.)
- **P31E does NOT fire** but readdir still short: it's GPT's mechanism (a) — `xfs_trans_read_buf` returns a cached STALE XBF_DONE block 0 (no disk I/O) at `xfs_dir2_block_addname`/`xfs_dir2_block_to_leaf`. FIX → on EX-acquire/first-modify, FORCE block 0 to be re-read from the coherent LUN (not cache); for an OLD-EPOCH PINNED block-0 buffer, do NOT skip-and-proceed (GPT: that is THE correctness hole) — wait until safe to invalidate+cold-read, or fail-stop. Add the read-vs-cache-hit trace GPT section C (caller=block_addname/block_to_leaf, XBF_DONE, pin, mxfs epoch, I/O-issued?).

### GPT-5.5 2nd consult verdict (full text in transcript): 
The "bounded-100ms-wait-then-SKIP pinned dir buffer" in mxfs_dir_evict_data_blocks / xfs_da_btree read-refresh is a CORRECTNESS HOLE — a pinned old-epoch dir block must NOT be used as a modification base (skipping → XFS uses stale XBF_DONE → logs+pins it → xfsaild checkpoints stale = durable revert). Once a stale buffer is logged into the CIL there is NO safe reconcile (forcing makes it MORE durable) → prevention before first log-dirty is the only fix. Real invariant: "first use of dir block 0 as a modification base in an EX epoch must use a current-epoch validated (cold-read or newly-allocated) image, never an old cached/pinned buffer." Most-likely root ranked #1 = the skip hole; the get_buf/init ABA (P31E) = a serious inode-fork/bmap coherency bug if it fires.

### Session state recap
- FACE B (inode-revert/IGET-FAIL) FIXED + regression-free (cache_coherency/zero_silent_loss/crash_consistency all PASS 2/2). See [[sess31-FACEB-FIXED-p116-grant-held-discriminator]].
- Sole remaining 2/tcp blocker = dir-DATA-block first-wave dirent loss (readdir ~185/200). All release/acquire architectural fixes already present; dirskip=1 HANGS; dir_force_evict already default=1. See [[sess31-dirblock-face-all-fixes-present-residual]].
- KEEP detectors: P31-FACEA (xfs_dir2_readdir.c), P31B-RELOAD-BUF (xfs_mxfs_dlm.c), P31E-DATAINIT-ABA (xfs_dir2_data.c). Criterion NOT met — marker NOT written.
</body>
</invoke>
