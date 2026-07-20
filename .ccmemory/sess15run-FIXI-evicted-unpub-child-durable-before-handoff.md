---
name: sess15run-FIXI-evicted-unpub-child-durable-before-handoff
description: sess15 FIX-I (61FE57FD): crash_consistency ROOT = evicted unpublished child's dinode not durable when dirent went peer-visible; P78-skip arm now flus…
metadata:
  type: project
---

# FIX-I — durable-before-visible for evicted unpublished children

## ROOT (2/tcp r6, ino 0x883400, RULE-4 instrumented proof)
crash_consistency face decoded end-to-end:
1. Creator (test1) makes the LAST file's md5 sidecar (size=33) → child inode
   unpublished (local EX, no master record), icreate+dinode in log only.
2. The test's drop_caches EVICTS the child on the CREATOR → FS-layer EX gone,
   unpub entry popped later by the dir-handoff publish drain →
   **P78-PUB-SKIP** (sess9 FIX-28) skips the master claim (correct for
   locking) — but NOTHING made the child's dinode-cluster durable, and the
   dir handoff made the dirent peer-visible.
3. Reader (test2) resolves the dirent, PR-acquires the child BY NUMBER →
   grants CLEANLY (empty resource: no BAST to creator, no mirror —
   ~60 sibling inos all show P74-GRANT have_mirror=1, the victim has NO
   P74-GRANT line and creator saw NO BAST) → FUA-reads the PRE-ICREATE
   platter = prior-mkfs dinodes → xfs_dinode_verify UUID reject (objdump:
   +0x2d6 = xfs_inode_buf.c:891 uuid_equal) → EFSCORRUPTED.
4. Reader's iget retry ladder (FIX-B) keeps invalidating + re-reading the
   same platter (P12-IGETMISS-RELOAD ×8; step-2 'acted' short-circuits the
   FIX-D visibility nudge — which couldn't reach an unpublished creator
   anyway) → EIO → test FAIL; the platter later self-repairs when the
   creator's async delwri write lands (post-mortem disk was VALID with
   current uuid — do NOT trust late raw-disk reads to refute this face).

## FIX (xfs_mxfs_dlm.c P78-PUB-SKIP arm, mxfs_dlm_publish_drain_loop)
On skip: xfs_imap → xfs_buf_incore(TRYLOCK) the child's cluster buf; if
dirty (DELWRI_Q | pinned | LI_DIRTY | LI_IN_AIL | li_list non-empty):
xfs_log_force(SYNC) + xfs_ail_push_all + bounded poll (≤250ms) until the buf
is clean/off-AIL. P15J-PUBSKIP-FLUSH names each firing (waited_ms, settled).
Peer stays blocked on the dir BAST until return = durable-before-visible.
Validated: 2/tcp r7 17/17, P15J fired 126× waited_ms=0 settled=1 (log force
alone settles — cheap).

## Same-family suspects still open
- r3's 8/tcp inobt CRC flavor (daddr 0x7fc2b8 after P126 staling) — may be
  the same eviction-family for AG-meta; P15I sector-CRC probe armed.
- Reader-side ladder hardening (nudge starvation by step-2) NOT changed —
  root fixed at creator; revisit only if a reader-side face recurs.

## Build 61FE57FD = FIX-H3 + P15I + FIX-I. Ladder restarted on it:
2/tcp r7 17/17 ✓. Pending at write time: 8/tcp r20 running, then 4/1 columns.
