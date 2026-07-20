---
name: sess33-dirreuse-faces-and-instrumentation-lessons
description: sess33: dir_reuse 2/tcp — refuted inode-extent-revert as primary; real verify-fail = leaf/last-batch staleness + inode-cluster(0xc40)/dirblock(0x78)…
metadata:
  type: project
---

## sess33 (ccloop 8ddb16a2) — dir_reuse_coherency 2/tcp deep characterization

### Build state
Started 125DD68A. Added detectors + a (no-op) fix; current head ~DBD3A375. All changes are
in xfs_dir2_leaf.c (P33-DSCAN-ONDISK probe, ratelimited), xfs_inode_buf.c (P33-FROMDISK/TODISK-
DIRSHRINK detectors, size+nx), xfs_mxfs_dlm.c (P33-DIRGROW-REVERT-SKIP reload guard).

### CRITICAL INSTRUMENTATION LESSON (cost ~4 build/run cycles)
**dmesg ring buffer WRAPS during a 24-round run.** A CAPPED probe (`atomic_inc<=N`) fires only on
the FIRST N events = early in the run = WRAPPED OUT of dmesg by collection time → reads as "0 fires"
even though it ran. Ratelimited probes (pr_warn_ratelimited) and probes that fire throughout SURVIVE.
**Always use pr_warn_ratelimited (DEFINE_RATELIMIT_STATE) for probes in long runs, NOT a one-shot
atomic cap.** P31E/FROMDISK (fire throughout) survived; P33-ENTER/DSCAN-ONDISK (capped, early) read 0.

### Infra: tests/reset2.sh (NEW, RULE 3)
After EVERY dir_reuse run, the leftover mxfs mount on ≥1 node WEDGES on unmount — xfs-reclaim
kworker + umount stuck in **D-state** (uninterruptible, cannot kill), refcnt=1, won't rmmod. Only a
VM reboot recovers. Also: prep's mkfs reformats the LUN; if a node is still mounted it self-fences
(P131-SELF-FENCE fs_uuid mismatch) → wedge. So `tests/reset2.sh` virsh-destroy+start both VMs and
waits for ssh+/src-nfs. RUN IT BEFORE EVERY run (host clyde reboot is BANNED, VM reboot is fine).

### DIAGNOSIS (RULE 4, instrumented) — the verify-phase failure
Test: 24 rounds; each: rank1 mkdir D; BOTH nodes concurrently write 50 files+50 .md5 (200 entries)
into shared dir ino=131; sync; drop_caches; readdir+stat-each; rank1 rm -rf D (reuses inode/daddrs).
Dir grows SF→block→leaf (block0+block1 data + leaf block; nx=3 size=8192).

REAL verify failure (criteria.json reason, the ONLY reliable signal — the per-name P26-DSCAN-MISS
dmesg count includes WRITE/md5-phase noise, ignore it; read .runs["2/tcp"].reason instead):
- test2: `round=17 readdir=200/200 lookup_fail=8 missing=[node1_f43.md5..node1_f50.md5]` — readdir
  lists ALL 200 (data blocks complete) but stat() fails on the peer's LAST-added 8 .md5 entries.
  NO P26-DSCAN-MISS for those names + P22-DATASCAN-HIT=0 ⇒ lookup did NOT reach the datascan
  fallback ⇒ it errored earlier (FS degraded / leaf read err), not a plain hash-miss.
- test1 (same run): `xfs_inode_buf_verify` EFSCORRUPTED at **inode cluster block 0xc40** (repeated)
  → FS shutdown → "Structure needs cleaning" (EUCLEAN). Inode-CLUSTER corruption (sess44/90 clobber).
- Other runs: `xfs_dir3_block_verify` EFSCORRUPTED at **dir block 0x78** (FACE B): in-core extent map
  decides FMT_BLOCK (eof==1) but block0 on disk is XDD3(leaf data) → wrong verifier (xfs_dir2.c
  xfs_dir2_format, the P56/P58 site). **HIGH RUN-TO-RUN VARIANCE**: faces + which node fails flip.

### What was REFUTED / dead-ends this session
- P32B-DOUBLEMAP=0 ⇒ intra-dir double-alloc REFUTED (handoff root (b) dead).
- The "inode extent-map revert" (ndb=1, size 8192→4096) I chased was a TRANSIENT/early-phase or
  reuse(gen-differ) artifact. At the VERIFY miss, in-core==on-disk (nx=3 size=8192 same gen) — inode
  is NOT torn. P33-FROMDISK fires were all gen-DIFFER reuse (new_fmt=1 size=6 fresh empty dir) =
  benign recycle adoption (xfs_iget_recycle is gen-gated, only adopts on reuse).
- **P33-DIRGROW-REVERT-SKIP reload guard fires 0× = NO-OP** (the same-incarnation reload revert it
  guards does not occur; reverts are reuse via recycle, not reload). The fix is harmless but useless
  as-is. mxfs_ail_drain_inode_to DOES wait until inode durable (no release durability gap there).

### NEXT (RULE 4)
Real residual = (1) peer's LAST-batch leaf-hash entries unresolvable cross-node (stale leaf /
last-writer leaf coherency) + (2) inode-CLUSTER corruption (0xc40, xfs_inode_buf_verify) and dir-block
(0x78) corruption. Get the corrupt-buffer "First 128 bytes" dump to classify (zeros=torn write /
stale=clobber). Inode-cluster clobber = sess44/90 territory (stale 16KB cluster buf flushed over
committed inodes). Consider GPT-5.5 consult (RULE 5) with THIS precise framing (prior sess32 consults
were on wrong AG-free-space framing). [[sess32-GPT2-verdict-handoff-checkpoint-iflush-fence]]
</body>
