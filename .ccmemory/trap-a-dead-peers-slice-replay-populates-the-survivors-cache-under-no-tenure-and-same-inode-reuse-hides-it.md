---
name: trap-a-dead-peers-slice-replay-populates-the-survivors-cache-under-no-tenure-and-same-inode-reuse-hides-it
description: TRAP (D-BUFFERS-THAT-LOG-RECOVERY, 0.87.8): foreign slice replay leaves 158 bmbt images cached XBF_DONE outside any tenure; a same-inode rebuild hide…
metadata:
  type: feedback
tags: [recovery, buffer-cache, bmbt, coherency, 2/tcp]
---

# Recovery is a cache producer outside the grant discipline

**Measured (2/tcp, sess45, `tests/recov_bmbt_reuse.sh`):** the survivor's
replay of a dead peer's slice reads every logged block through the
survivor's own cache (`xlog_recover_buf_commit_pass2` → `xfs_buf_read(mp->
m_ddev_targp)`), writes the image home, and leaves the copy cached, clean,
`XBF_DONE`.  A victim killed mid-write on a 20000-extent file left 158
bmbt images + 2 AG-btree images in the survivor's cache
(`recov_bmbt_cached=158`).  No tenure read them, so the 0.87.6 tenure-end
eviction never runs for them.

**Reproduction trap:** with `rm F; rebuild F2` the finobt hands F2 the SAME
inode number, and the survivor's acquire-time eviction (keyed on
`bb_owner == acquired ino`) evicts all 158 (`P67-BMBT-EVICT-ENTER
nthisino=158`) — the lap reads clean and proves nothing.  Take the freed
inode number with an empty file first so F2 is a different inode; then the
old images carry the wrong owner, the reload cannot see them, and the btree
owner check refuses them (D-0975 symptom).  A lap that reproduces a cache
defect must make the new consumer's identity differ from the old owner's.

**Detector trap:** a raw "tagged cache hit" counter is nonzero DURING
recovery — the replay re-reads images it populated (623 hits, all from the
recovery worker before the census line).  Split hits by task: the recovery
task's own hits are expected; only hits outside recovery are the defect.

**Astra hazards on the fix (sess45 ruling):**
- tag by PRODUCER, not by queued write: a replay read that skips the
  rewrite (image already newer, LSN skip) still leaves a recovery image;
  tag at the recovery task's read (`m_mxfs_freplay_task == current` in
  `xfs_buf_read_map`), disable recovery readahead on a foreign replay so
  every recovery read is synchronous and attributable;
- never clear provenance from an I/O completion (readahead, another
  recovery read); clear only at retirement or a task-context fresh read;
- fence AFTER home flush and BEFORE IMAGES_REPLAYED/purge; busy or
  local-work images → retryable error, nothing published (same as a flush
  failure); one log force only, never "push the AIL until it goes away";
- fixed-address classes (inode clusters, AGF/AGI/AGFL, SB, dquot) need
  explicit, argued exemptions; unknown ops fail closed (evict);
- verify against an external content oracle (the writers' block lists), not
  the two nodes' agreement — both can agree on damaged contents;
- add a partial-retirement retry arm: fail after N evictions once, the
  second attempt must retire the rest (`dbg_recov_evict_fail_after`).

**Rig trap:** the victim's rejoin (`prep_node.sh`) installs the tree's
mxfs.ko and checks its md5 — never `make` while a death/rejoin lap is on
the rig, and never edit the running harness script.
