---
name: sess61-HANDOFF-state-and-next-steps
description: sess61 HANDOFF: build 75E5FD35, 4/tcp dir_reuse_coherency baseline ~2/24 (peers miss node1_f*, creator never fails). Root PROVEN=stale dirty block0 b…
metadata:
  type: project
---

## sess61 HANDOFF — dir_reuse_coherency 4/tcp (criterion: 1/2/4/8 tcp 100%)

### STATE
- Build **75E5FD35** on disk + deployed. Criterion NOT met.
- 1/tcp=16/16, 2/tcp=17/17 (sess58). 4/tcp: only dir_reuse_coherency fails.
  8/tcp never run.
- **Representative baseline (probes OFF): ~2/24 rounds fail** (rounds 19-20),
  peers (rank2/3/4) miss a node1_f* entry; **creator test1 NEVER fails**. Matches
  sess60 residual. My sess61 changes did NOT regress baseline.

### ROOT — PROVEN this session (RULE 4, direct evidence)
Write-side **stale dirty block0 buffer RMW clobber**. At create time (EX,
comm=dd) the EX holder's in-core block0 BUFFER content is BEHIND disk:
`core_node1=0 disk_node1=76/84/88`, **dirty=1 inail=0 pin=0 bufgen=0** while inode
i_dlm_dir_gen=20. The MXFS tenure-gen mechanism FLAGS it stale (bufgen 0 <
dir_gen) but `mxfs_dir_evict_data_blocks` KEEPS it because it's DIRTY (undurable
guard protects own work). The buffer holds the node's OWN entries; disk holds
peers' (disjoint). The node RMWs+writes its stale block0 → clobbers peers'
dirents durably. At verify (PR) the block reads coherent (sess60 gen-bump) — the
damage is already durable.
- REFUTED: logical-block-0 SPLIT (P60-LBMAP: all nodes' extent maps agree on
  daddr). REFUTED: read-side stale-serve (verify core==disk). REFUTED: double
  sf->block CONVERSION (P42-SFCONV i_gens all DISTINCT across nodes — one
  converter per incarnation). REFUTED: inode-FORK staleness (P61-ADOPT-CHK:
  in-core fmt/nx/size never behind disk under EX; P58-SELFSKIP-STALE-DIR=0 so the
  reload self-skip is NOT the path). The staleness is purely in the cached DATA
  BUFFER content, not the inode.
- Mechanism: single converter materializes block0 (its entries); peers grow disk
  block0 via block_addname; the converter's cached block0 buffer stays stale
  (dirty bufgen=0) and its later RMW clobbers.

### THE OPEN FORK — A vs B (must resolve FIRST, GPT-5.5 emphasized)
For an EX holder's in-core block0 to be BEHIND disk, either:
- **A (stale cached/own buffer)**: node released EX, peer grew disk, node
  reacquired but its block0 buffer (dirty/in-AIL, never cleaned) wasn't refreshed.
  Fixable in the dir/DLM-acquire layer.
- **B (TCP DLM double-grant)**: two nodes held the dir-inode EX concurrently; peer
  grew disk while this node held EX with its dirty buffer. NO dir-layer fix works;
  fix the TCP DLM grant. (sess49 flagged "TCP double-grant" as a known residual.)
The buffer being **dirty=1 (uncommitted)** at reacquire while disk advanced leans
toward B, but not conclusive.
**The CAW slot-table detector `mxfs_v5_dlm_inode_ex_count` returns ex_pop=0 on
TCP (CAW-only) — USELESS for double-grant on TCP.** Next session MUST add a
TCP-DLM-grant-path EX-overlap detector (per GPT): at the TCP DLM master/grant,
assert <=1 EX owner per inode resource and emit grant/release with a monotonic
cookie; OR stamp a per-EX-grant epoch on the inode and assert at first
buffer-dirty that the block0 buffer was validated under the current epoch.

### FIX DESIGN (GPT-5.5, full text in memory) — once A/B known
- If **A**: tenure-cookie invariant. Never let a dir buffer be dirtied unless it
  was read/init under the CURRENT EX tenure. Enforce at EX (re)acquire (BEFORE
  the modify trans dirties block0): invalidate+reread stale CLEAN buffers; a
  stale DIRTY buffer is an invariant violation. Do NOT union-merge dir2 blocks
  (breaks leaf hash/bestfree). Do NOT rebuild the inode fork mid-transaction
  (iflush-corruption shutdown class). The gen bumps on slow-path EX reacquire
  (xfs_mxfs_dlm.c:10161); the gap is the DIRTY block0 buffer kept by
  mxfs_dir_evict_data_blocks (~2300) — extend its sess41 refresh to the
  dirty-stale-tenure case SAFELY (only if not joined-dirty to the live trans),
  or force block0 re-read at reacquire before any add.
- If **B**: fix TCP DLM grant/conversion to enforce EX exclusivity.

### CODE STATE (this session's edits)
- `xfs/libxfs/xfs_inode_buf.c`: P-DIRFLUSH capped at 40 (harmless noise cut).
- `tests/suite/dir_reuse_coherency.sh`: on failure dumps `dmesg` ->
  `/root/drc_fail_r${round}_rank${R}.dmesg` (KEEP — invaluable; ring wraps fast).
- `xfs/xfs_mxfs_dlm.c`: added `mxfs_dir_modify_adopt_disk_format()` (format/count
  reload) — **REFUTED, its call in xfs_create is `if(0)` disabled**. Can delete.
- `xfs/libxfs/xfs_da_btree.c`: P60-LBMAP + P61-BLK0 (in-core vs FUA-disk node1
  count + bufgen/incarn/dirty/inail/pin + ex_pop) — **gated behind mxfs.instr**
  (per-read FUA perturbs timing: amplifies ~2/24 -> 15/24). Run with mxfs.instr=1
  to diagnose, OFF for representative runs.
- `xfs/xfs_inode.c`: the disabled adopt call.

### REPRO / OPS
`./run.sh 4 tcp dir_reuse_coherency`; completion marker "=== done:" in the run
log (NOT pgrep). Reset between runs: `virsh -c qemu:///system destroy+start
test1-4` (device-busy on prep otherwise). Per-failure snapshots on each node at
/root/drc_fail_*.dmesg. pr_warn(4) does NOT hit console at default loglevel 4.
PERF/RULE-0: ~13s/round x24 ~ 312s vs 300s TEST_TIMEOUT — even a coherent run
risks timing out near round 24; needs a per-round cost cut too.
See [[sess61-DECISIVE-dirty-bufgen0-divergent-block0-kept-by-dirty-guard]],
[[sess61-REFINED-content-level-stale-block0-buffer-RMW-clobber]],
[[sess61-PROVEN-ROOT-stale-shortform-reconversion-clobbers-disk-block-dir]].</body>
