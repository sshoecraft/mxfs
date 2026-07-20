---
name: AAA-ccloopa864-sess7-ROOT-bmbt-XDD3-crc-shutdown-diagnosed
description: sess7: dir_reuse@32/caw = R-a WRITER-SIDE (P133 silent=coherent adopt; P60 INCONSISTENT frequent on peers). CONVERGES w/ sess32/40 "Bug B AG free-spa…
metadata:
  type: project
---

## sess7 (ccloop a864) — dir_reuse@32/caw ROOT = R-a WRITER-SIDE (converges with prior "Bug B")

### CRITERIA: sole gap = dir_reuse_coherency 32/caw (audit this session: 101 applicable caw cells PASS, this 1 FAIL 0/32). Every other 1/2/4/8/16/32 caw cell PASS.

### THE BUG: rank1 (test1, dir-owner: rm-rf+mkdir each round) FS shuts down at the round it re-acquires the shared dir ino131 after a stall while 31 peers grew it (deterministic ~r3-r7). Corruption FAMILY: bmbt (xfs_bmbt_read_verify gets XDD3 dir-data ≠ BMA3 on a leaf daddr e.g. 41864600/56517168=0x35e6230 → CRC err74 → xfs_trans_cancel → shutdown) OR torn-shortform (xfs_dir2_sf_verify namelen=0). Then readdir=0, cluster barrier-stalls, 0/32.

### DIAGNOSIS = R-a WRITER-SIDE (rank1 adopts a COHERENT-but-inconsistent image; NOT a stale reader adopt):
1. **P133-DINO-READSTALE (my enhanced dfork-memcmp probe, 0.10.55) did NOT fire** at the failing adopt → adopted dinode `dip` == coherent plain-bio re-read → rank1 adopted the COHERENT dinode. NOT R-b.
2. **P60-RELAUDIT INCONSISTENT-AT-RELEASE fires FREQUENTLY on HEALTHY peers** (test10: 21×; di_nextents=26 vs leafsum=63, di_nextents=13 vs leafsum=32). Writers release the dir with dinode(di_nextents) and its bmbt LEAF records mutually inconsistent.
3. The adopt-side bmbt-evict (mxfs_dir_evict_bmbt_blocks+by_root, xfs_mxfs_dlm.c:18126-18131, sess62 fix, runs EVERY dir reload) DID run (P67/P59 cap-silenced >1000) yet corruption persists → re-reading the coherent leaf still yields a bad block → COHERENT MEDIUM itself inconsistent.
4. First run: leaf daddr 41864600 on the medium held XDD3 dir-DATA w/ correct self-daddr (P77-SKIP-DIFFERS "in-core bmbt differs from LUN") = leaf daddr durably repurposed as a dir-DATA block while the coherent dinode's broot still names it a bmbt leaf.
**=> The coherent medium has a block DOUBLE-USED (bmbt-leaf for ino131 AND dir-data). This IS the prior-known "Bug B = AG free-space double-alloc → file data over inode cluster → EFSCORRUPTED" (see ccmemory sess32-GPT2-verdict-handoff-checkpoint-iflush-fence, and sess40 note "does NOT address Bug B"). NOT closed by any prior session.**

### P15I-MEDIUM probe MISSED this cycle: my 0.10.56 probe (pal/linux/xfs_buf.c ~L1564) coherent-reads the failing daddr at CRC-fail to log verdict MEDIUM-NOT-BMBT(R-a) vs MEDIUM-VALID-BMBT(R-b). It DID NOT fire because the guard `!in_interrupt()` was FALSE — **the bmbt read-completion CRC-fail path runs in softirq/interrupt context**, so the blocking plain-bio read was (correctly) skipped. P15I-CRCFAIL DID fire (daddr=56517168, secrc=[3da5fd55 d73a3565 00000000×5] = sectors 0-1 content, 2-6 zero). NEXT: to get the direct medium verdict, do the read in PROCESS context — defer to a workqueue from the CRC-fail, OR read the failing daddr from the xfs_trans_cancel path (process ctx), OR just dd the raw block from clyde `/dev/mapper/mpatha` at (daddr + bt_sector_offset) sectors right at failure (but block churns). OR skip it — R-a is already well-evidenced (1-4 above).

### NEXT SESSION PLAN:
1. **Study prior "Bug B" work**: `ccmemory get sess32-GPT2-verdict-handoff-checkpoint-iflush-fence` + search "AG free-space double-alloc" / "Bug B" / "double-alloc". This is an AG-allocation coherency bug (a block allocated twice across nodes) analogous to the inode-cluster staler — likely the AG-DLM handoff serves a stale AG free-space view so two nodes allocate the same block for different roles.
2. **Fix direction (writer/allocation-side, since reader-side is exhausted this run + prior)**: ensure AG free-space allocations are coherent across the DLM handoff (no double-alloc of a freed dir block); OR GFS2 go_sync-style full consistent publish (dinode+bmbt+data+AG-btrees) before wire unlock (~/src/linux/fs/gfs2/glops.c inode_go_sync). If own ideas exhausted after evidence, RULE-5 Fable consult WARRANTED (proven arch-level diagnosis, this is the multi-session-unclosed "Bug B").
3. Builds in tree (all KEEP, diagnostic-only additions): 0.10.53 (C98E4152), .54 P-BROOT-REPURPOSE (385D2C0B), .55 enhanced P133 dfork-memcmp (338079B3), .56 P15I-MEDIUM (6C932BD7, current). VERSION=0.10.56.

### MECHANICS/GOTCHAS: pkill'd runs leave 32 node ssh-wrappers + grep `-vE ^Warning` pipeline procs holding /tmp/mxfs_run.lock → next run.sh ABORTS. CLEANUP: `pkill -9 -f 'run.sh 32 caw'; pkill -9 -f 'timeout 4600 env'; fuser -k -9 /tmp/mxfs_run.lock; pkill -9 -f 'mxfs_sshpass.sh test'; pkill -9 -f 'timeout 4480'; pkill -9 -f 'grep -vE .\^Warning'; rm -f /tmp/mxfs_run.lock` (repeat fuser+rm until GONE). Also pkill remote node dir_reuse_coherency.sh. NEVER rebuild while run active (pgrep -xc make / grep build log 'Leaving directory'). fua_disable=1 (coherent=plain-bio; SCSI-FUA=lagging platter). SSH=`bash tools/mxfs_sshpass.sh testN /tmp/.mxfs_pass '<cmd>'`. DEV=/dev/mapper/mpatha (mpath). Deploy = /src NFS-exported → build updates .ko, run.sh prep rmmod+insmod+srcversion-assert. Cluster CLEAN at handoff (run=0, lock gone). scratchpad fix-plan.md has GFS2/OCFS2 notes.
</body>
