---
name: sess385-hole2-proven-agi-publishes-linked-unlinked-head
description: sess385 PROVEN at the publication point: AG release published an unlinked-list head whose home dinode reads nlink=1 while in-core reads 0. 1 of 5 hea…
metadata:
  type: project
tags: [agi, unlinked, defect-361, proven, dlm-release, invariant-1]
---

## The measurement

Build 55DB999D5A6D8A41497366A (0.19.12), 32/caw, one 5-test lap
(`dlm_fairness dlm_membership scaling_curve dlm_scaling rsync_paired`),
board **all 5 PASS**. Probe `P86-AGI-UNLINKED-PUBLISH`, param
`mxfs.agi_publish_audit`, fires immediately before `mxfs_v5_dlm_ag_unlock` —
the exact instant the AG becomes another node's to read.

For every non-null `agi_unlinked[]` bucket head it FUA-reads that inode's home
dinode off the shared LUN (bypassing every cache) and compares against the
in-core inode found by `radix_tree_lookup(&pag->pag_ici_root, agino)`.

    test26  mxfs: P86-AGI-UNLINKED-PUBLISH ag=6 bucket=31 agino=0x86
            ino=25165958 disk_nlink=1 disk_next=0xffffffff core_nlink=0
            disk_gen=2095405065 disk_mode=0x81a4

    aggregate over 5 published heads: joint_ok=4 SPLIT=1 BADHEAD=0

**1 of 5 published unlinked-list heads was a split**: AG 6 was handed to a peer
with its AGI bucket 31 pointing at inode 25165958 whose home dinode on the
shared LUN still read `nlink=1`, mode 0644, `di_next_unlinked=NULLAGINO`.

The next node to acquire AG 6 and walk that bucket does
`xfs_iunlink_reload_next` -> `xfs_iget(UNTRUSTED)` -> `i_nlink != 0` ->
`-EFSCORRUPTED` **inside an already-dirty rename transaction** -> forced
shutdown -> the #474A `mxfs_dlm_noino_bast_work_fn` cascade.

This is the direct proof of HOLE 2 (see
`ccloop-c7ee71c6-sess385-GPT-ruling-inode-publication-hole`): the AG release
path has NO inode-log-item -> home-block conversion stage. `di_nlink=0` lives in
the inode log item and in this node's journal, which no peer replays;
`xfs_log_force(SYNC)` does not move it into the cluster buffer. The cluster
buffer is therefore CLEAN and its in-core image agrees with the medium — both
say LINKED — so the HOLE-1 buffer-staleness probe (P85) is structurally blind
to this and reported `split=0` across 33 release events.

## Why this closes the #361 diagnosis

`D-RSYNC-RENAME-DIRTY-CANCEL-MASS-SHUTDOWN-361` is a symptom of
`D-AGI-UNLINKED-CROSSNODE-RECOVERY-SHUTDOWN`. sess384 narrowed the failure to
one line; sess385 measured the *cause of that line's condition* on the releasing
node's side. The acquirer is not corrupt and the AGI is not corrupt — the
transition was published in halves.

## Both holes, measured on green boards

- HOLE 1 (P85): 34 dirty inode-cluster buffers skipped at AG release in one lap;
  of 23 checkable, **10 differed from in-core at release**, 13 dinodes.
- HOLE 2 (P86): **1 of 5** published unlinked-list heads was a split.

## Probes (keep — they are the verification instruments)

- `mxfs.inode_drain_probe=1` -> `P85-INODE-DRAIN-CENSUS` / `P85-INODE-DRAIN-SPLIT`
  in `mxfs_dlm_ag_drain_inode_buffers`.
- `mxfs.agi_publish_audit=1` -> `P86-AGI-UNLINKED-PUBLISH` /
  `P86-AGI-PUBLISH-CENSUS` just before `mxfs_v5_dlm_ag_unlock`.

`SPLIT=0` across a sustained run with these ON is the verification condition for
the fix. Note the base rate is low (1 head in 5, and most releases publish zero
heads), so a passing lap proves little — the fix needs a run that publishes many
heads.
