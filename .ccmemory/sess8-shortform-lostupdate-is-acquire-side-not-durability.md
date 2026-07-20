---
name: sess8-shortform-lostupdate-is-acquire-side-not-durability
description: sess8 PROVEN: shortform-dir lost-update is ACQUIRE-side/concurrency, NOT write durability — P-SFREL shows every release durable on LUN; refutes relea…
metadata:
  type: project
---

## REFINES [[sess8-rename-guard-fix-and-shortform-lostupdate-root]] with decisive evidence.

Added P-SFREL probe (dirwr-gated) in bast_process release path (xfs_mxfs_dlm.c, right after
`mxfs_ail_drain_inode_sync(ip); blkdev_issue_flush(...)` ~line 3051): for a SHORTFORM dir, after the
full release drain, PLAIN-bio read (mxfs_fua_disable=1 → SCST/LIO write-cache coherence point, same
path a peer's acquire-reload uses) the inode cluster and log on-disk shortform count+names. Build
DA703FD6DF02BDDC48491FD. (Probe is gated; harmless in production. NOTE: a `P-SFREL-VERIFY` line also
appears — pre-existing, not mine.)

## DECISIVE RESULT (dlm_fairness dirwr=1, reproduced ~1/16, dir ino=2097280):
EVERY P-SFREL shows the releasing node's just-committed entries DURABLE on the LUN before release
(e.g. test1 P-SFREL count=3 [n1_r1 n2_r36 n1_r4] DURABLE; test2 P-SFREL count=3 [n1_r1 n1_r4 n2_r40]
DURABLE). So **write-side durability-before-release is CORRECT** — invariant #1 holds for the shortform
dinode. This REFUTES the sess8 "release-side durability gap" hypothesis.

The failure is P-SFDIR-REVERT incore_cnt=3 **disk_cnt=2 fua_cnt=2** (fua==disk, the probe's own class B
= "stale LUN genuinely lacks the entry"): a node's in-core shortform fork had an entry that the LUN
durably lacks → reload adopts the shorter disk image → durable lost-update. Leftover {n1_r1, n1_r4}
(node1's files it created+renamed+rm'd but whose removal was durably reverted), agreed on BOTH nodes.

## THEREFORE the root is ACQUIRE-SIDE / CONCURRENCY, not durability:
A node RMWs the shortform dir from a STALE in-core base that LACKS a peer's ALREADY-DURABLE entry,
then commits+releases durably → clobbers the peer's entry. Since each release is durable and reads use
the write-cache coherence point, a node that ACQUIRES EX *after* a peer's release MUST see the peer's
entry — so the stale base means EITHER (1) a residual DOUBLE-GRANT (both nodes hold dir EX
concurrently, neither reloads the other's change), OR (2) a cached-EX re-affirm/fast-path acquire that
SKIPS the i_dlm_stale reload (node modifies from its stale cached in-core fork without re-reading the
peer's durable LUN image). The gen-token re-affirm (process_remote_request, dlm.c ~2192) re-sends a
GRANT to an existing holder — must verify the CLIENT side (process_remote_grant) and the dir-inode
EX-acquire fast-path FORCE i_dlm_stale=true / a dinode reload on EVERY cross-node dir-EX (re)grant, so
a holder never RMWs a stale fork.

## NEXT (RULE 4): instrument/inspect the CLIENT grant + dir-inode acquire fast-path:
- Does a re-affirm/re-grant set i_dlm_stale so the next modify reloads? (xfs_mxfs_dlm.c acquire path
  ~4698/4833/5455; dlm.c process_remote_grant client side.)
- Is there still a double-grant window for the DIR inode specifically? lockwr=1 perturbs (heisenbug,
  6/6 PASS) so use a lock-free per-CPU ring or post-hoc reasoning, not printk in the grant hot path.
Pure instrumentation (P-SFREL plain-bio read at release) does NOT reliably suppress (reproduced WITH
it), so light probes are usable. Fallbacks: E143DF7B (rename-guard, no probe), E8BF16B2 (pre-guard).
</body>
