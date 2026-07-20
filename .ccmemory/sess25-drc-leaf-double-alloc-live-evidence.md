---
name: sess25-drc-leaf-double-alloc-live-evidence
description: sess25(ccloop): dir_reuse_coherency 2/tcp ROOT PROVEN = inode RESURRECTION (xfsaild flushes peer-freed inodes, 201x, P119+P17B=0). Fix P25-RESURRECT-…
metadata:
  type: project
---

## sess25 (ccloop run 8ddb16a2) — ROOT PROVEN + FIX for the 2/tcp criterion blocker (dir_reuse_coherency).

### Criterion = full `./run.sh 2 tcp` suite. Sole blocker = dir_reuse_coherency (other 16 applicable tests PASS; marker EMPTY → loop continues). Repro: `tests/drc_probe.sh` (test1 owns mkdir/rm-rf of SAME name .drcp, both nodes create 50 data+50 md5; fails round 1-5). Suite test fails round 16.

### PROVEN ROOT (RULE 4, build 0302171A's parent 254E0DBE, drc_probe round 2)
INODE RESURRECTION. test2 dmesg: **P-IRESURRECT=201, P119-NONEX-FLUSH-SKIP=0, P17B-EPOCH-GHOST-SKIP=0** → 201 stale-inode flushes by `comm=xfsaild/sda` PROCEEDED (none skipped). Each: `incore_mode=0100644(live file) disk_mode=00(FREED) incore_nlink=1 disk_nlink=0 disk_gen=incore_gen+1 i_dlm_mode=5(EX)`. These are .md5/data FILES created by test2 then rm-rf-freed by test1. test2 holds them stale-live in-core; xfsaild resurrects them.
CAUSAL CHAIN → leaf corruption: md5 file F has data block B → rm-rf frees F (disk mode=0, B→bnobt free) → test2 keeps F stale-live (claims B) → dir recreated, grows to leaf, bnobt allocs B for the dir LEAF → xfsaild RESURRECTS F (flushes stale F reclaiming B) → B double-claimed by F + dir-leaf → md5 data lands on B → P54-DIRBLK-PROBE: dir 1960 leaf bno=0x800000 daddr=2093760 holds md5 hex "a27b" → EFSBADCRC xfs_dir3_leaf_read_verify → readdir/lookup fail. (Earlier "double-alloc" framing was a downstream symptom; resurrection is upstream root. NOT a fresh allocator double-pick — sess55/111 correctly ruled that out.)

### WHY guards miss it
P119 skips iflush if i_dlm_mode!=EX; P17B skips if dirty_seq!=ex_grant_seq. These inodes have STALE i_dlm_mode=EX (peer freed the UNPUBLISHED new inode without BASTing test2) and dirty_seq==ex_grant_seq → both guards pass → resurrection proceeds. P-IRESURRECT is detector-only (no skip).

### FIX (build 0302171A, xfs/xfs_inode.c xfs_iflush, after P17B block, ALWAYS-ON)
`P25-RESURRECT-SKIP`: skip flush (xfs_iflags_set ISTALE_CAW, error=0, goto flush_out) when COHERENT dip is FREE + strictly-later incarnation: `di_mode==0 && di_nlink==0 && VFS_I(ip)->i_mode!=0 && (s32)(disk_gen - incore_gen) > 0`. = sess118 di_gen>incore discriminator re-scoped to disk-FREE only (a free strictly increments OUR gen → comparable here, unlike sess119's general cross-node random-gen concern). New-inode first flush holds newest incarnation (disk_gen<=incore_gen) → flushes normally. Local self-free has in-core mode==0 → excluded.
RESIDUAL RISK: chunk-REINIT resurrections (disk_gen randomized, could be < incore_gen) only ~50% caught by the gen>0 test. If test still fails after this, add a stronger discriminator for those (the minority; majority are disk=incore+1 single-free).

### TESTING NOW (task brqg7neuk): reboot+deploy 0302171A, run dir_reuse_coherency. PASS criteria: 0 FAIL + P25-RESURRECT-SKIP fires + P-IRESURRECT/leaf-CRC drop to ~0. Then run FULL `./run.sh 2 tcp` x>=3 for 100%.

### Instruments added (KEEP): P-DBLALLOC (xfs_alloc.c, gated dirwr/instr, data-alloc-over-live-metadata). drc_probe.sh (tests/). P25-RESURRECT-SKIP is the FIX (always-on).</body>
