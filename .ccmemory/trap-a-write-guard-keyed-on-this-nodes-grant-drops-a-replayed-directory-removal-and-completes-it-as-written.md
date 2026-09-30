---
name: trap-a-write-guard-keyed-on-this-nodes-grant-drops-a-replayed-directory-removal-and-completes-it-as-written
description: TRAP (0.90.27, 8/tcp): replay applied a dir block (32 names), P12-DIR-EXGUARD-SKIP dropped its write (platter 42); inobt frees landed: dangling names.
metadata:
  type: feedback
tags: [recovery, foreign-replay, directory, write-filter, chk_mxfs, dangling]
---

# A write filter that asks "what grant does this node hold" has no answer for a log recovery

**Measured (0.90.26 module, 8/tcp, two nodes power-cut, lap f26a):** no slice
refused, no survivor error, `chk_mxfs` exit 4 with ten dangling names in the
directory the victim was emptying.  The replayer admitted all 28 images of the
victim's window and applied the directory block's image (32 names).  At the
write chokepoint (`xfs_buf_submit_bio`) the exclusive-grant guard saw no grant
on the owner (`in_core=0 mode=-1`), read the platter (42 names), printed
`P12-DIR-EXGUARD-SKIP buf_cnt=32 disk_cnt=42` and completed the buffer with no
I/O.  `bflags=0x40022` carried the log-recovery flag (0x40000).  The
allocation-group images of the same checkpoints landed, so the inode btree
held the frees and the directory still held the names.

**Why it hid:** a replayed CREATE has more names than the platter and passes
the guard; only a death inside a removal has fewer.  Two CAW laps and one TCP
lap were clean by the phase the victims happened to die in.

**What to do:**
- When a replay says "applied" and the platter disagrees, grep the REPLAYER's
  log for the block's daddr: the lines between the token line and the home
  flush name the image's fate (here ten lines told the whole story).
- Any filter that completes a write without I/O needs the recovery question
  asked first.  The inode-cluster mask got it in 0.87.8 (`b_mxfs_recov_slots`),
  the dir write fence in `xfs_buf_submit_ex` had it (`_XBF_LOGRECOVERY`), the
  older chokepoint filters and the two `mxfs_buf_xfsaild_skip_*_write`
  predicates did not until 0.90.27.
- A death lap proves a replayed removal only when the final platter shows a
  partly emptied directory (fewer names than it was built with) and
  `dangling=0`; read the checker's per-directory lines, not only its exit code.
- An earlier hypothesis for the same symptom (the log tail moving past
  un-landed changes) was disproved by the window itself holding the image:
  read what the replayer did with the block before theorising about the
  writer.
